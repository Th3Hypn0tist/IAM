<?php

declare(strict_types=1);

require_once __DIR__ . '/abuse.php';

const IAM_REGISTRATION_RESERVED_USERNAMES = [
    'origin','admin','administrator','root','system','iam','aigm',
    'support','security','api','null','anonymous','local',
];

const IAM_REGISTRATION_FORM_TTL_SECONDS = 43200;
const IAM_REGISTRATION_MIN_FORM_AGE_SECONDS = 2;

function iam_registration_invite_hash(string $inviteCode): string {
    return hash('sha256', $inviteCode);
}

function iam_registration_form_hash(string $formToken): string {
    return hash('sha256', $formToken);
}

function iam_registration_context(string $inviteCode): array {
    return [
        'ip_hash' => iam_abuse_ip_hash(),
        'invite_hash' => iam_registration_invite_hash($inviteCode),
    ];
}

function iam_registration_log(PDO $pdo, array $context, string $outcome): void {
    iam_abuse_log(
        $pdo,
        (string)$context['ip_hash'],
        (string)$context['invite_hash'],
        'register',
        $outcome
    );
}

function iam_registration_reject(
    PDO $pdo,
    array $context,
    string $outcome,
    int $status,
    string $message,
    ?int $retryAfter = null
): never {
    iam_registration_log($pdo, $context, $outcome);
    if ($retryAfter !== null) header('Retry-After: ' . $retryAfter);
    iam_fail($status, $message);
}

function iam_registration_reject_invalid_invite(PDO $pdo, array $context): never {
    iam_registration_log($pdo, $context, 'invalid_invite');

    $ipHash = (string)$context['ip_hash'];
    $invalidCount = iam_abuse_count(
        $pdo,
        'register',
        'ip_hash',
        $ipHash,
        86400
    );

    if ($invalidCount >= 3) {
        $blockSeconds = (int)(iam_config()['invalid_invite_block_seconds'] ?? 3600);
        if ($blockSeconds < 60) {
            throw new RuntimeException('invalid_invite_block_seconds must be at least 60');
        }
        iam_abuse_block(
            $pdo,
            $ipHash,
            'register_invalid_invite',
            'register',
            $blockSeconds
        );
    }

    iam_fail(400, 'Invite code not valid.');
}

function iam_registration_rate_limit(PDO $pdo, array $context): void {
    $ipHash = (string)$context['ip_hash'];
    $inviteHash = (string)$context['invite_hash'];

    iam_abuse_require_not_blocked($pdo, $ipHash);

    $blockFor = 0;
    $reason = '';

    if (iam_abuse_count($pdo, 'register', 'ip_hash', $ipHash, 600) >= 5) {
        $blockFor = max($blockFor, 600);
        $reason = 'register_ip_10m';
    }
    if (iam_abuse_count($pdo, 'register', 'ip_hash', $ipHash, 86400) >= 20) {
        $blockFor = max($blockFor, 86400);
        $reason = 'register_ip_24h';
    }
    if (iam_abuse_count($pdo, 'register', 'identifier_hash', $inviteHash, 1800) >= 5) {
        $blockFor = max($blockFor, 1800);
        $reason = 'register_invite_30m';
    }

    if ($blockFor > 0) {
        iam_abuse_block($pdo, $ipHash, $reason, 'register', $blockFor);
        iam_fail(403, 'Access blocked.');
    }
}

function iam_registration_invite(PDO $pdo, array $context, bool $forUpdate = false): array {
    $suffix = $forUpdate ? ' FOR UPDATE' : '';
    $stmt = $pdo->prepare(
        "SELECT
            invite_id,
            owner_user_id,
            domain_id,
            target_email
         FROM IAM_invites
         WHERE token_hash = ?
           AND status = 'active'
           AND claimed_by_user_id IS NULL
           AND expires_at > CURRENT_TIMESTAMP(6)
         LIMIT 1" . $suffix
    );
    $stmt->execute([(string)$context['invite_hash']]);
    $invite = $stmt->fetch();

    if (!is_array($invite)) {
        iam_registration_reject_invalid_invite($pdo, $context);
    }

    $email = strtolower(trim((string)$invite['target_email']));
    if (
        $email === ''
        || strlen($email) > 320
        || filter_var($email, FILTER_VALIDATE_EMAIL) === false
    ) {
        throw new RuntimeException('invite target email is invalid');
    }

    return [
        'invite_id' => (string)$invite['invite_id'],
        'owner_user_id' => (string)$invite['owner_user_id'],
        'domain_id' => (string)$invite['domain_id'],
        'target_email' => $email,
    ];
}

function iam_registration_require_usable_invite(PDO $pdo, array $context): array {
    return iam_registration_invite($pdo, $context, false);
}

function iam_registration_create_form_state(PDO $pdo, array $invite): string {
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $hash = iam_registration_form_hash($token);
    $formId = 'frm_' . bin2hex(random_bytes(16));
    $expiresAt = gmdate(
        'Y-m-d H:i:s',
        time() + IAM_REGISTRATION_FORM_TTL_SECONDS
    );

    $stmt = $pdo->prepare(
        "INSERT INTO IAM_registration_forms
            (form_id, invite_id, token_hash, expires_at)
         VALUES (?, ?, ?, ?)"
    );
    $stmt->execute([
        $formId,
        (string)$invite['invite_id'],
        $hash,
        $expiresAt,
    ]);

    return $token;
}

function iam_registration_require_form_state(
    PDO $pdo,
    array $invite,
    string $formToken,
    bool $forUpdate = false
): array {
    if ($formToken === '') {
        iam_fail(400, 'Registration failed.');
    }

    $suffix = $forUpdate ? ' FOR UPDATE' : '';
    $stmt = $pdo->prepare(
        "SELECT
            form_id,
            created_at,
            expires_at,
            consumed_at
         FROM IAM_registration_forms
         WHERE token_hash = ?
           AND invite_id = ?
           AND consumed_at IS NULL
           AND expires_at > CURRENT_TIMESTAMP(6)
         LIMIT 1" . $suffix
    );
    $stmt->execute([
        iam_registration_form_hash($formToken),
        (string)$invite['invite_id'],
    ]);
    $form = $stmt->fetch();

    if (!is_array($form)) {
        iam_fail(400, 'Registration form expired. Open the invitation link again.');
    }

    $createdAt = strtotime((string)$form['created_at'] . ' UTC');
    if (
        $createdAt === false
        || time() - $createdAt < IAM_REGISTRATION_MIN_FORM_AGE_SECONDS
    ) {
        iam_fail(400, 'Registration failed.');
    }

    return $form;
}

function iam_registration_consume_form_state(PDO $pdo, string $formId): void {
    $stmt = $pdo->prepare(
        "UPDATE IAM_registration_forms
         SET consumed_at = CURRENT_TIMESTAMP(6)
         WHERE form_id = ?
           AND consumed_at IS NULL"
    );
    $stmt->execute([$formId]);

    if ($stmt->rowCount() !== 1) {
        throw new RuntimeException('registration form state consume failed');
    }
}

function iam_registration_browser_guard(PDO $pdo, array $context, array $body): void {
    if (trim((string)($body['website'] ?? '')) !== '') {
        iam_registration_reject(
            $pdo,
            $context,
            'honeypot',
            400,
            'Registration failed.'
        );
    }
}

function iam_registration_validate(
    PDO $pdo,
    array $context,
    string $username,
    string $password
): array {
    $usernameLength = strlen($username);
    if (
        $usernameLength < 3
        || $usernameLength > 32
        || preg_match('/^[A-Za-z0-9_.-]+$/D', $username) !== 1
        || in_array(strtolower($username), IAM_REGISTRATION_RESERVED_USERNAMES, true)
    ) {
        iam_registration_reject(
            $pdo,
            $context,
            'invalid_input',
            400,
            'Username is not valid.'
        );
    }

    $passwordLength = strlen($password);
    if ($passwordLength < 15 || $passwordLength > 1024) {
        iam_registration_reject(
            $pdo,
            $context,
            'invalid_input',
            400,
            'Password must be between 15 and 1024 characters.'
        );
    }

    if (strcasecmp($password, $username) === 0) {
        iam_registration_reject(
            $pdo,
            $context,
            'invalid_input',
            400,
            'Password must differ from username.'
        );
    }

    return [
        'username' => $username,
        'password' => $password,
    ];
}

function iam_registration_conflict_exists(
    PDO $pdo,
    string $username,
    string $email
): bool {
    $usernameStmt = $pdo->prepare(
        'SELECT 1 FROM IAM_users WHERE username = ? LIMIT 1'
    );
    $usernameStmt->execute([$username]);
    if ($usernameStmt->fetchColumn() !== false) return true;

    $emailStmt = $pdo->prepare(
        'SELECT 1 FROM IAM_user_accounts WHERE email = ? LIMIT 1'
    );
    $emailStmt->execute([$email]);
    return $emailStmt->fetchColumn() !== false;
}
