<?php

declare(strict_types=1);

const IAM_REGISTRATION_RESERVED_USERNAMES = [
    'origin',
    'admin',
    'administrator',
    'root',
    'system',
    'iam',
    'aigm',
    'support',
    'security',
    'api',
    'null',
    'anonymous',
    'local',
];

function iam_registration_secret(): string {
    $value = (string)(iam_config()['registration_hmac_secret'] ?? '');
    if (strlen($value) < 32 || str_starts_with($value, 'CHANGE_ME')) {
        throw new RuntimeException('registration_hmac_secret must be configured');
    }
    return $value;
}

function iam_registration_client_ip(): string {
    $value = $_SERVER['REMOTE_ADDR'] ?? '';
    return is_string($value) && $value !== '' ? $value : 'unknown';
}

function iam_registration_ip_hash(): string {
    return hash_hmac('sha256', iam_registration_client_ip(), iam_registration_secret());
}

function iam_registration_invite_hash(string $inviteCode): string {
    return hash('sha256', $inviteCode);
}

function iam_registration_context(string $inviteCode): array {
    return [
        'ip_hash' => iam_registration_ip_hash(),
        'invite_hash' => iam_registration_invite_hash($inviteCode),
    ];
}

function iam_registration_prune(PDO $pdo): void {
    $pdo->exec(
        "DELETE FROM iam_registration_attempts
         WHERE created_at < TIMESTAMPADD(DAY, -7, CURRENT_TIMESTAMP(6))"
    );
}

function iam_registration_log(PDO $pdo, array $context, string $outcome): void {
    static $allowedOutcomes = [
        'accepted',
        'invalid_invite',
        'rate_limited',
        'honeypot',
        'invalid_input',
        'conflict',
    ];

    if (!in_array($outcome, $allowedOutcomes, true)) {
        throw new InvalidArgumentException('invalid registration outcome');
    }

    $stmt = $pdo->prepare(
        "INSERT INTO iam_registration_attempts
            (attempt_id, ip_hash, invite_hash, created_at, outcome)
         VALUES (?, ?, ?, CURRENT_TIMESTAMP(6), ?)"
    );
    $stmt->execute([
        'reg_' . bin2hex(random_bytes(16)),
        (string)$context['ip_hash'],
        (string)$context['invite_hash'],
        $outcome,
    ]);
}

function iam_registration_count(
    PDO $pdo,
    string $column,
    string $hash,
    int $windowSeconds
): int {
    if (!in_array($column, ['ip_hash', 'invite_hash'], true)) {
        throw new InvalidArgumentException('invalid registration rate-limit column');
    }

    $sql = sprintf(
        "SELECT COUNT(*)
         FROM iam_registration_attempts
         WHERE %s = ?
           AND outcome <> 'rate_limited'
           AND created_at >= TIMESTAMPADD(SECOND, -?, CURRENT_TIMESTAMP(6))",
        $column
    );
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$hash, $windowSeconds]);
    return (int)$stmt->fetchColumn();
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
    if ($retryAfter !== null) {
        header('Retry-After: ' . $retryAfter);
    }
    iam_fail($status, $message);
}

function iam_registration_rate_limit(PDO $pdo, array $context): void {
    $retryAfter = 0;

    if (iam_registration_count($pdo, 'ip_hash', (string)$context['ip_hash'], 600) >= 5) {
        $retryAfter = max($retryAfter, 600);
    }

    if (iam_registration_count($pdo, 'ip_hash', (string)$context['ip_hash'], 86400) >= 20) {
        $retryAfter = max($retryAfter, 86400);
    }

    if (iam_registration_count($pdo, 'invite_hash', (string)$context['invite_hash'], 1800) >= 5) {
        $retryAfter = max($retryAfter, 1800);
    }

    if ($retryAfter > 0) {
        iam_registration_reject(
            $pdo,
            $context,
            'rate_limited',
            429,
            'Too many registration attempts.',
            $retryAfter
        );
    }
}

function iam_registration_require_usable_invite(
    PDO $pdo,
    array $context
): void {
    $stmt = $pdo->prepare(
        "SELECT 1
         FROM invites
         WHERE token_hash = ?
           AND status = 'active'
           AND claimed_by_user_id IS NULL
           AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP(6))
         LIMIT 1"
    );
    $stmt->execute([(string)$context['invite_hash']]);
    if ($stmt->fetchColumn() === false) {
        iam_registration_reject(
            $pdo,
            $context,
            'invalid_invite',
            400,
            'Invite code not valid.'
        );
    }
}

function iam_registration_browser_guard(PDO $pdo, array $context, array $body): void {
    $isBrowserSubmission =
        array_key_exists('website', $body)
        || array_key_exists('form_started_at_ms', $body);

    if (!$isBrowserSubmission) return;

    $website = trim((string)($body['website'] ?? ''));
    if ($website !== '') {
        iam_registration_reject(
            $pdo,
            $context,
            'honeypot',
            400,
            'Registration failed.'
        );
    }

    $started = $body['form_started_at_ms'] ?? null;
    if (!(is_int($started) || (is_string($started) && ctype_digit($started)))) {
        iam_registration_reject(
            $pdo,
            $context,
            'invalid_input',
            400,
            'Registration failed.'
        );
    }

    $startedMs = (int)$started;
    $nowMs = (int)floor(microtime(true) * 1000);
    if ($startedMs <= 0 || $nowMs - $startedMs < 2000) {
        iam_registration_reject(
            $pdo,
            $context,
            'invalid_input',
            400,
            'Registration failed.'
        );
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
        iam_registration_reject(
            $pdo,
            $context,
            'invalid_invite',
            400,
            'Invite code not valid.'
        );
    }

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

    $normalizedEmail = null;
    if ($email !== null && $email !== '') {
        $normalizedEmail = strtolower(trim($email));
        if (
            strlen($normalizedEmail) > 320
            || filter_var($normalizedEmail, FILTER_VALIDATE_EMAIL) === false
        ) {
            iam_registration_reject(
                $pdo,
                $context,
                'invalid_input',
                400,
                'Email is not valid.'
            );
        }
    }

    $passwordLength = strlen($password);
    if ($passwordLength < 8 || $passwordLength > 1024) {
        iam_registration_reject(
            $pdo,
            $context,
            'invalid_input',
            400,
            'Password must be between 8 and 1024 characters.'
        );
    }

    if (
        strcasecmp($password, $username) === 0
        || ($normalizedEmail !== null && strcasecmp($password, $normalizedEmail) === 0)
    ) {
        iam_registration_reject(
            $pdo,
            $context,
            'invalid_input',
            400,
            'Password must differ from username and email.'
        );
    }

    return [
        'username' => $username,
        'password' => $password,
        'email' => $normalizedEmail,
    ];
}

function iam_registration_conflict_exists(
    PDO $pdo,
    string $username,
    ?string $email
): bool {
    $usernameStmt = $pdo->prepare(
        'SELECT 1 FROM users WHERE username = ? LIMIT 1'
    );
    $usernameStmt->execute([$username]);
    if ($usernameStmt->fetchColumn() !== false) return true;

    if ($email === null) return false;

    $emailStmt = $pdo->prepare(
        'SELECT 1 FROM user_accounts WHERE email = ? LIMIT 1'
    );
    $emailStmt->execute([$email]);
    return $emailStmt->fetchColumn() !== false;
}
