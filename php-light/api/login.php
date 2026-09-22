<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';

iam_headers();
iam_require_method('POST');

try {
    $body = iam_json_body();
    $username = trim((string)($body['username'] ?? ''));
    $password = (string)($body['password'] ?? '');
    if ($username === '' || $password === '') iam_fail(400, 'username and password are required');

    $pdo = iam_pdo();
    $stmt = $pdo->prepare(
        "SELECT
            u.user_id, u.username, u.tier, u.status, u.verified,
            a.password_hash, a.account_status
         FROM users u
         JOIN user_accounts a ON a.user_id = u.user_id
         WHERE u.username = ?
         LIMIT 1"
    );
    $stmt->execute([$username]);
    $row = $stmt->fetch();

    if (
        !is_array($row)
        || $row['status'] !== 'active'
        || $row['account_status'] !== 'active'
        || !password_verify($password, (string)$row['password_hash'])
    ) {
        iam_fail(401, 'invalid username or password');
    }

    $session = iam_issue_session($pdo, (string)$row['user_id']);
    echo json_encode([...iam_base_payload($row), ...$session], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    iam_fail(500, 'server error');
}
