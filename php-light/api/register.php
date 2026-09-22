<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';
require_once dirname(__DIR__) . '/lib/registration_guard.php';

iam_headers();
iam_require_method('POST');

$pdo = null;
$context = null;

try {
    $body = iam_json_body();
    $inviteCode = trim((string)($body['invite_code'] ?? ''));
    $username = trim((string)($body['username'] ?? ''));
    $password = (string)($body['password'] ?? '');
    $emailRaw = trim((string)($body['email'] ?? ''));
    $email = $emailRaw === '' ? null : $emailRaw;

    $pdo = iam_pdo();
    $context = iam_registration_context($inviteCode);

    iam_registration_prune($pdo);
    iam_registration_rate_limit($pdo, $context);
    iam_registration_require_usable_invite($pdo, $context);
    iam_registration_browser_guard($pdo, $context, $body);

    $validated = iam_registration_validate(
        $pdo,
        $context,
        $inviteCode,
        $username,
        $password,
        $email
    );
    $username = (string)$validated['username'];
    $password = (string)$validated['password'];
    $email = $validated['email'];

    if (iam_registration_conflict_exists($pdo, $username, $email)) {
        iam_registration_reject(
            $pdo,
            $context,
            'conflict',
            409,
            'Username or email already exists.'
        );
    }

    $pdo->beginTransaction();

    $inviteStmt = $pdo->prepare(
        "SELECT invite_id
         FROM IAM_invites
         WHERE token_hash = ?
           AND status = 'active'
           AND claimed_by_user_id IS NULL
           AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP(6))
         FOR UPDATE"
    );
    $inviteStmt->execute([(string)$context['invite_hash']]);
    $invite = $inviteStmt->fetch();

    if (!is_array($invite)) {
        $pdo->rollBack();
        iam_registration_reject(
            $pdo,
            $context,
            'invalid_invite',
            400,
            'Invite code not valid.'
        );
    }

    // Expensive password hashing happens only after the invite is proven usable.
    $passwordHash = iam_password_hash($password);
    $userId = 'usr_' . bin2hex(random_bytes(16));

    $user = $pdo->prepare(
        "INSERT INTO IAM_users (user_id, username, tier, status, verified)
         VALUES (?, ?, 3, 'active', FALSE)"
    );
    $user->execute([$userId, $username]);

    $account = $pdo->prepare(
        "INSERT INTO IAM_user_accounts (user_id, password_hash, email, account_status)
         VALUES (?, ?, ?, 'active')"
    );
    $account->execute([$userId, $passwordHash, $email]);

    $claim = $pdo->prepare(
        "UPDATE IAM_invites
         SET status = 'claimed',
             claimed_by_user_id = ?,
             claimed_at = CURRENT_TIMESTAMP(6)
         WHERE invite_id = ?
           AND status = 'active'
           AND claimed_by_user_id IS NULL"
    );
    $claim->execute([$userId, (string)$invite['invite_id']]);

    if ($claim->rowCount() !== 1) {
        throw new RuntimeException('invite claim failed');
    }

    $pdo->commit();

    $row = [
        'user_id' => $userId,
        'username' => $username,
        'tier' => 3,
        'status' => 'active',
        'verified' => false,
    ];

    $session = iam_issue_session($pdo, $userId);
    iam_registration_log($pdo, $context, 'accepted');

    http_response_code(201);
    echo json_encode(
        [...iam_base_payload($row), ...$session],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
} catch (PDOException $e) {
    if ($pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();

    if ((string)$e->getCode() === '23000') {
        if ($pdo instanceof PDO && is_array($context)) {
            iam_registration_log($pdo, $context, 'conflict');
        }
        iam_fail(409, 'Username or email already exists.');
    }

    iam_fail(500, 'server error');
} catch (Throwable $e) {
    if ($pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();
    iam_fail(500, 'server error');
}
