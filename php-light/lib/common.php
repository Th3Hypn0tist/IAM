<?php

declare(strict_types=1);

const IAM_CONTRACT = 'iam.light';
const IAM_VERSION = '1.0';

function iam_config(): array {
    static $config = null;
    if ($config !== null) return $config;

    $path = dirname(__DIR__) . '/config.php';
    if (!is_file($path)) throw new RuntimeException('IAM config.php is missing');

    $value = require $path;
    if (!is_array($value)) throw new RuntimeException('IAM config.php must return an array');

    $dbConfigPath = trim((string)($value['db_config'] ?? ''));
    if ($dbConfigPath !== '') {
        if (!is_file($dbConfigPath)) {
            throw new RuntimeException('IAM db_config file is missing');
        }
        $dbConfig = require $dbConfigPath;
        if (!is_array($dbConfig)) {
            throw new RuntimeException('IAM db_config must return an array');
        }
        foreach (['dsn', 'user', 'password'] as $key) {
            if (!array_key_exists($key, $dbConfig)) {
                throw new RuntimeException("IAM db_config missing {$key}");
            }
            $value[$key] = $dbConfig[$key];
        }
    }

    foreach (['dsn', 'user', 'password'] as $key) {
        if (!array_key_exists($key, $value)) {
            throw new RuntimeException("IAM config missing {$key}");
        }
    }

    $config = $value;
    return $config;
}

function iam_pdo(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;
    $config = iam_config();
    $pdo = new PDO((string)$config['dsn'], (string)$config['user'], (string)$config['password'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

function iam_headers(): void {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
}

function iam_fail(int $status, string $message): never {
    http_response_code($status);
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function iam_json_body(): array {
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') iam_fail(400, 'empty request body');
    try {
        $value = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        iam_fail(400, 'invalid JSON');
    }
    if (!is_array($value) || array_is_list($value)) iam_fail(400, 'request body must be an object');
    return $value;
}

function iam_require_method(string $method): void {
    if ($_SERVER['REQUEST_METHOD'] !== $method) {
        header('Allow: ' . $method);
        iam_fail(405, 'method not allowed');
    }
}

function iam_identity_payload(array $row): array {
    return [
        'user' => [
            'id' => (string)$row['user_id'],
            'username' => (string)$row['username'],
            'status' => (string)$row['status'],
            'verified' => (bool)$row['verified'],
        ],
        'claims' => [
            'tier' => (int)$row['tier'],
        ],
    ];
}

function iam_base_payload(array $row): array {
    return [
        'ok' => true,
        'contract' => IAM_CONTRACT,
        'version' => IAM_VERSION,
        'auth_level' => 'light',
        ...iam_identity_payload($row),
    ];
}

function iam_password_hash(string $password): string {
    $length = strlen($password);
    if ($length < 8) throw new InvalidArgumentException('password must be at least 8 characters');
    if ($length > 1024) throw new InvalidArgumentException('password is too long');
    $algorithm = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    $hash = password_hash($password, $algorithm);
    if (!is_string($hash) || $hash === '') throw new RuntimeException('password hashing failed');
    return $hash;
}

function iam_cookie_name(): string {
    return (string)(iam_config()['cookie_name'] ?? 'iam_light');
}

function iam_set_cookie(string $token, int $expires): void {
    $config = iam_config();
    setcookie(iam_cookie_name(), $token, [
        'expires' => $expires,
        'path' => (string)($config['cookie_path'] ?? '/'),
        'secure' => (bool)($config['cookie_secure'] ?? true),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function iam_clear_cookie(): void {
    $config = iam_config();
    setcookie(iam_cookie_name(), '', [
        'expires' => 1,
        'path' => (string)($config['cookie_path'] ?? '/'),
        'secure' => (bool)($config['cookie_secure'] ?? true),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
}

function iam_issue_session(PDO $pdo, string $userId): array {
    $ttl = (int)(iam_config()['session_ttl_seconds'] ?? 2592000);
    if ($ttl < 60) throw new RuntimeException('session_ttl_seconds must be at least 60');
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $tokenHash = hash('sha256', $token);
    $sessionId = 'ses_' . bin2hex(random_bytes(16));
    $expires = time() + $ttl;
    $expiresSql = gmdate('Y-m-d H:i:s', $expires);

    $stmt = $pdo->prepare(
        'INSERT INTO IAM_sessions (session_id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)'
    );
    $stmt->execute([$sessionId, $userId, $tokenHash, $expiresSql]);
    iam_set_cookie($token, $expires);

    return [
        'token' => $token,
        'expires_at' => gmdate('Y-m-d\TH:i:s\Z', $expires),
    ];
}

function iam_bearer_token(): ?string {
    $header = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if (preg_match('/^Bearer\s+(.+)$/i', trim($header), $match) === 1) {
        $token = trim($match[1]);
        return $token === '' ? null : $token;
    }
    $cookie = $_COOKIE[iam_cookie_name()] ?? null;
    return is_string($cookie) && $cookie !== '' ? $cookie : null;
}

function iam_session_row(PDO $pdo, string $token): ?array {
    $hash = hash('sha256', $token);
    $stmt = $pdo->prepare(
        "SELECT
            s.session_id, s.user_id, s.expires_at,
            u.username, u.tier, u.status, u.verified,
            a.account_status
         FROM IAM_sessions s
         JOIN IAM_users u ON u.user_id = s.user_id
         JOIN IAM_user_accounts a ON a.user_id = u.user_id
         WHERE s.token_hash = ?
           AND s.revoked_at IS NULL
           AND s.expires_at > CURRENT_TIMESTAMP(6)
         LIMIT 1"
    );
    $stmt->execute([$hash]);
    $row = $stmt->fetch();
    if (!is_array($row)) return null;
    if ($row['status'] !== 'active' || $row['account_status'] !== 'active') return null;

    $touch = $pdo->prepare('UPDATE IAM_sessions SET last_seen_at = CURRENT_TIMESTAMP(6) WHERE session_id = ?');
    $touch->execute([(string)$row['session_id']]);
    return $row;
}

function iam_require_session(PDO $pdo): array {
    $token = iam_bearer_token();
    if ($token === null) iam_fail(401, 'authentication required');
    $row = iam_session_row($pdo, $token);
    if ($row === null) iam_fail(401, 'invalid or expired session');
    return $row;
}
