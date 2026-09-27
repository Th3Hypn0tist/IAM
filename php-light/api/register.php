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
    $formToken = trim((string)($body['form_token'] ?? ''));
    $username = trim((string)($body['username'] ?? ''));
    $password = (string)($body['password'] ?? '');

    $pdo = iam_pdo();
    $context = iam_registration_context($inviteCode);

    iam_registration_rate_limit($pdo, $context);

    if ($inviteCode === '') {
        iam_registration_reject_invalid_invite($pdo, $context);
    }

    $invite = iam_registration_require_usable_invite($pdo, $context);
    $form = iam_registration_require_form_state(
        $pdo,
        $invite,
        $formToken,
        false
    );

    iam_registration_browser_guard($pdo, $context, $body);

    $validated = iam_registration_validate(
        $pdo,
        $context,
        $username,
        $password
    );

    $username = (string)$validated['username'];
    $password = (string)$validated['password'];
    $email = (string)$invite['target_email'];
    $domainId = iam_require_domain($pdo, (string)$invite['domain_id']);

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

    $lockedInvite = iam_registration_invite($pdo, $context, true);
    $lockedForm = iam_registration_require_form_state(
        $pdo,
        $lockedInvite,
        $formToken,
        true
    );

    if ((string)$lockedInvite['invite_id'] !== (string)$invite['invite_id']) {
        throw new RuntimeException('invite changed during registration');
    }

    $passwordHash = iam_password_hash($password);
    $userId = 'usr_' . bin2hex(random_bytes(16));

    $user = $pdo->prepare(
        "INSERT INTO IAM_users
            (user_id, username, status, verified)
         VALUES (?, ?, 'active', TRUE)"
    );
    $user->execute([$userId, $username]);

    $account = $pdo->prepare(
        "INSERT INTO IAM_user_accounts
            (user_id, password_hash, email, account_status)
         VALUES (?, ?, ?, 'active')"
    );
    $account->execute([$userId, $passwordHash, $email]);

    $membership = $pdo->prepare(
        "INSERT INTO IAM_domain_memberships
            (user_id, domain_id, status)
         VALUES (?, ?, 'active')
         ON DUPLICATE KEY UPDATE status = VALUES(status)"
    );

    $membership->execute([$userId, IAM_ROOT_DOMAIN]);
    if ($domainId !== IAM_ROOT_DOMAIN) {
        $membership->execute([$userId, $domainId]);
    }

    $tier = $pdo->prepare(
        "INSERT INTO IAM_management_tiers
            (user_id, domain_id, management_tier, status)
         VALUES (?, ?, 3, 'active')"
    );
    $tier->execute([$userId, $domainId]);

    $claim = $pdo->prepare(
        "UPDATE IAM_invites
         SET status = 'claimed',
             claimed_by_user_id = ?,
             claimed_at = CURRENT_TIMESTAMP(6)
         WHERE invite_id = ?
           AND status = 'active'
           AND claimed_by_user_id IS NULL"
    );
    $claim->execute([
        $userId,
        (string)$lockedInvite['invite_id'],
    ]);

    if ($claim->rowCount() !== 1) {
        throw new RuntimeException('invite claim failed');
    }

    iam_registration_consume_form_state(
        $pdo,
        (string)$lockedForm['form_id']
    );

    $pdo->commit();

    $row = [
        'user_id' => $userId,
        'username' => $username,
        'status' => 'active',
        'verified' => true,
    ];
    $row = iam_with_domain_claim($pdo, $row, $domainId);

    $session = iam_issue_session($pdo, $userId);
    iam_registration_log($pdo, $context, 'accepted');

    http_response_code(201);
    echo json_encode(
        [...iam_base_payload($row), ...$session],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
} catch (PDOException $e) {
    if ($pdo instanceof PDO && $pdo->inTransaction()) {
        $pdo->rollBack();
    }

    if ((string)$e->getCode() === '23000') {
        if ($pdo instanceof PDO && is_array($context)) {
            iam_registration_log($pdo, $context, 'conflict');
        }
        iam_fail(409, 'Username or email already exists.');
    }

    error_log('[IAM register] ' . get_class($e) . ': ' . $e->getMessage());
    iam_fail(500, 'server error');
} catch (Throwable $e) {
    if ($pdo instanceof PDO && $pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('[IAM register] ' . get_class($e) . ': ' . $e->getMessage());
    iam_fail(500, 'server error');
}
