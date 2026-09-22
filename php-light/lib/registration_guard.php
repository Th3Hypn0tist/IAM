<?php

declare(strict_types=1);

require_once __DIR__ . '/abuse.php';

const IAM_REGISTRATION_RESERVED_USERNAMES = [
    'origin','admin','administrator','root','system','iam','aigm',
    'support','security','api','null','anonymous','local',
];

function iam_registration_invite_hash(string $inviteCode): string {
    return hash('sha256', $inviteCode);
}

function iam_registration_context(string $inviteCode): array {
    return [
        'ip_hash' => iam_abuse_ip_hash(),
        'invite_hash' => iam_registration_invite_hash($inviteCode),
    ];
}

function iam_registration_prune(PDO $pdo): void {
    iam_abuse_prune($pdo);
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

function iam_registration_require_usable_invite(PDO $pdo, array $context): void {
    $stmt = $pdo->prepare(
        "SELECT 1
         FROM IAM_invites
         WHERE token_hash = ?
           AND status = 'active'
           AND claimed_by_user_id IS NULL
           AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP(6))
         LIMIT 1"
    );
    $stmt->execute([(string)$context['invite_hash']]);
    if ($stmt->fetchColumn() === false) {
        iam_registration_reject($pdo, $context, 'invalid_invite', 400, 'Invite code not valid.');
    }
}

function iam_registration_browser_guard(PDO $pdo, array $context, array $body): void {
    $isBrowserSubmission = array_key_exists('website', $body) || array_key_exists('form_started_at_ms', $body);
    if (!$isBrowserSubmission) return;

    if (trim((string)($body['website'] ?? '')) !== '') {
        iam_registration_reject($pdo, $context, 'honeypot', 400, 'Registration failed.');
    }

    $started = $body['form_started_at_ms'] ?? null;
    if (!(is_int($started) || (is_string($started) && ctype_digit($started)))) {
        iam_registration_reject($pdo, $context, 'invalid_input', 400, 'Registration failed.');
    }

    $startedMs = (int)$started;
    $nowMs = (int)floor(microtime(true) * 1000);
    if ($startedMs <= 0 || $nowMs - $startedMs < 2000) {
        iam_registration_reject($pdo, $context, 'invalid_input', 400, 'Registration failed.');
    }
}

function iam_registration_validate(
    PDO $pdo,
    array $context,
    string $inviteCode,
    string $username,
    string $password,
    ?string $email
): array {
    if ($inviteCode === '') {
        iam_registration_reject($pdo, $context, 'invalid_invite', 400, 'Invite code not valid.');
    }

    $usernameLength = strlen($username);
    if (
        $usernameLength < 3
        || $usernameLength > 32
        || preg_match('/^[A-Za-z0-9_.-]+$/D', $username) !== 1
        || in_array(strtolower($username), IAM_REGISTRATION_RESERVED_USERNAMES, true)
    ) {
        iam_registration_reject($pdo, $context, 'invalid_input', 400, 'Username is not valid.');
    }

    $normalizedEmail = null;
    if ($email !== null && $email !== '') {
        $normalizedEmail = strtolower(trim($email));
        if (strlen($normalizedEmail) > 320 || filter_var($normalizedEmail, FILTER_VALIDATE_EMAIL) === false) {
            iam_registration_reject($pdo, $context, 'invalid_input', 400, 'Email is not valid.');
        }
    }

    $passwordLength = strlen($password);
    if ($passwordLength < 8 || $passwordLength > 1024) {
        iam_registration_reject($pdo, $context, 'invalid_input', 400, 'Password must be between 8 and 1024 characters.');
    }

    if (
        strcasecmp($password, $username) === 0
        || ($normalizedEmail !== null && strcasecmp($password, $normalizedEmail) === 0)
    ) {
        iam_registration_reject($pdo, $context, 'invalid_input', 400, 'Password must differ from username and email.');
    }

    return ['username' => $username, 'password' => $password, 'email' => $normalizedEmail];
}

function iam_registration_conflict_exists(PDO $pdo, string $username, ?string $email): bool {
    $usernameStmt = $pdo->prepare('SELECT 1 FROM IAM_users WHERE username = ? LIMIT 1');
    $usernameStmt->execute([$username]);
    if ($usernameStmt->fetchColumn() !== false) return true;

    if ($email === null) return false;

    $emailStmt = $pdo->prepare('SELECT 1 FROM IAM_user_accounts WHERE email = ? LIMIT 1');
    $emailStmt->execute([$email]);
    return $emailStmt->fetchColumn() !== false;
}
