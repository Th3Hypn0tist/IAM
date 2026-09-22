<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';
require_once dirname(__DIR__) . '/lib/abuse.php';

iam_headers();
iam_require_method('POST');

try {
    $body = iam_json_body();
    $username = trim((string)($body['username'] ?? ''));
    $password = (string)($body['password'] ?? '');

    if ($username === '' || $password === '') iam_fail(400, 'username and password are required');
    if (strlen($username) > 32 || strlen($password) > 1024) iam_fail(400, 'invalid credentials');

    $pdo = iam_pdo();
    iam_abuse_prune($pdo);

    $ipHash = iam_abuse_ip_hash();
    $identifierHash = iam_abuse_identifier_hash($username);
    iam_abuse_require_not_blocked($pdo, $ipHash);

    if (
        iam_abuse_count($pdo, 'login', 'ip_hash', $ipHash, 600) >= 5
        || iam_abuse_count($pdo, 'login', 'ip_hash', $ipHash, 86400) >= 20
        || iam_abuse_count($pdo, 'login', 'identifier_hash', $identifierHash, 1800) >= 5
    ) {
        iam_abuse_block($pdo, $ipHash, 'login_abuse', 'login', 3600);
        iam_fail(403, 'Access blocked.');
    }

    $stmt = $pdo->prepare(
        "SELECT
            u.user_id, u.username, u.tier, u.status, u.verified,
            a.password_hash, a.account_status
         FROM IAM_users u
         JOIN IAM_user_accounts a ON a.user_id = u.user_id
         WHERE u.username = ?
         LIMIT 1"
    );
    $stmt->execute([$username]);
    $row = $stmt->fetch();

    static $dummyHash = null;
    if ($dummyHash === null) {
        $dummyHash = password_hash(
            'IAM-DUMMY-PASSWORD-VERIFICATION',
            defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT
        );
    }

    $hash = is_array($row) ? (string)$row['password_hash'] : (string)$dummyHash;
    $passwordValid = password_verify($password, $hash);

    if (
        !is_array($row)
        || $row['status'] !== 'active'
        || $row['account_status'] !== 'active'
        || !$passwordValid
    ) {
        iam_abuse_log($pdo, $ipHash, $identifierHash, 'login', 'invalid_credentials');
        iam_fail(401, 'invalid username or password');
    }

    iam_abuse_log($pdo, $ipHash, $identifierHash, 'login', 'accepted');
    $session = iam_issue_session($pdo, (string)$row['user_id']);
    echo json_encode([...iam_base_payload($row), ...$session], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    iam_fail(500, 'server error');
}
