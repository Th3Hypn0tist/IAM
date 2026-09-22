<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';

iam_headers();
iam_require_method('POST');

$pdo = null;

try {
    $body = iam_json_body();
    $inviteCode = trim((string)($body['invite_code'] ?? ''));
    $username = trim((string)($body['username'] ?? ''));
    $password = (string)($body['password'] ?? '');
    $emailRaw = trim((string)($body['email'] ?? ''));
    $email = $emailRaw === '' ? null : $emailRaw;

    if ($inviteCode === '' || $username === '' || $password === '') {
        iam_fail(400, 'invite_code, username and password are required');
    }
    if (strlen($username) > 128) iam_fail(400, 'username is too long');
    if ($email !== null && !filter_var($email, FILTER_VALIDATE_EMAIL)) iam_fail(400, 'invalid email');

    $passwordHash = iam_password_hash($password);
    $tokenHash = hash('sha256', $inviteCode);
    $userId = 'usr_' . bin2hex(random_bytes(16));
    $pdo = iam_pdo();
    $pdo->beginTransaction();

    $inviteStmt = $pdo->prepare(
        "SELECT invite_id
         FROM invites
         WHERE token_hash = ?
           AND status = 'active'
           AND claimed_by_user_id IS NULL
           AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP(6))
         FOR UPDATE"
    );
    $inviteStmt->execute([$tokenHash]);
    $invite = $inviteStmt->fetch();
    if (!is_array($invite)) {
        $pdo->rollBack();
        iam_fail(400, 'invite is invalid, expired or already claimed');
    }

    $user = $pdo->prepare(
        "INSERT INTO users (user_id, username, tier, status, verified)
         VALUES (?, ?, 3, 'active', FALSE)"
    );
    $user->execute([$userId, $username]);

    $account = $pdo->prepare(
        "INSERT INTO user_accounts (user_id, password_hash, email, account_status)
         VALUES (?, ?, ?, 'active')"
    );
    $account->execute([$userId, $passwordHash, $email]);

    $claim = $pdo->prepare(
        "UPDATE invites
         SET status = 'claimed',
             claimed_by_user_id = ?,
             claimed_at = CURRENT_TIMESTAMP(6)
         WHERE invite_id = ?
           AND status = 'active'
           AND claimed_by_user_id IS NULL"
    );
    $claim->execute([$userId, (string)$invite['invite_id']]);
    if ($claim->rowCount() !== 1) throw new RuntimeException('invite claim failed');

    $pdo->commit();

    $row = [
        'user_id' => $userId,
        'username' => $username,
        'tier' => 3,
        'status' => 'active',
        'verified' => false,
    ];
    $session = iam_issue_session($pdo, $userId);
    http_response_code(201);
    echo json_encode([...iam_base_payload($row), ...$session], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (InvalidArgumentException $e) {
    if ($pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();
    iam_fail(400, $e->getMessage());
} catch (PDOException $e) {
    if ($pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();
    if ((string)$e->getCode() === '23000') iam_fail(409, 'username or email already exists');
    iam_fail(500, 'server error');
} catch (Throwable $e) {
    if ($pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();
    iam_fail(500, 'server error');
}
