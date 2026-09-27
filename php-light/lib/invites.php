<?php

declare(strict_types=1);

require_once __DIR__ . '/common.php';

const IAM_INVITE_TTL_SECONDS = 604800;

function iam_normalize_email(string $email): string {
    $email = strtolower(trim($email));

    if (
        $email === ''
        || strlen($email) > 320
        || filter_var($email, FILTER_VALIDATE_EMAIL) === false
    ) {
        iam_fail(400, 'Email is not valid.');
    }

    return $email;
}

function iam_create_invite(
    PDO $pdo,
    string $ownerUserId,
    string $domainId,
    string $targetEmail
): array {
    $domainId = iam_require_domain($pdo, $domainId);
    $targetEmail = iam_normalize_email($targetEmail);

    if (!iam_can_invite_to_domain($pdo, $ownerUserId, $domainId)) {
        iam_fail(403, 'Access denied.');
    }

    $pdo->beginTransaction();

    try {
        /*
         * One active invitation per destination email and domain.
         * Creating a replacement revokes the previous active invite.
         */
        $revoke = $pdo->prepare(
            "UPDATE IAM_invites
             SET status = 'revoked'
             WHERE domain_id = ?
               AND target_email = ?
               AND status = 'active'
               AND claimed_by_user_id IS NULL"
        );
        $revoke->execute([$domainId, $targetEmail]);

        $token = rtrim(
            strtr(base64_encode(random_bytes(32)), '+/', '-_'),
            '='
        );
        $tokenHash = hash('sha256', $token);
        $inviteId = 'inv_' . bin2hex(random_bytes(16));
        $expiresAt = gmdate(
            'Y-m-d H:i:s',
            time() + IAM_INVITE_TTL_SECONDS
        );

        $insert = $pdo->prepare(
            "INSERT INTO IAM_invites
                (
                    invite_id,
                    owner_user_id,
                    domain_id,
                    target_email,
                    token_hash,
                    expires_at,
                    status
                )
             VALUES (?, ?, ?, ?, ?, ?, 'active')"
        );

        $insert->execute([
            $inviteId,
            $ownerUserId,
            $domainId,
            $targetEmail,
            $tokenHash,
            $expiresAt,
        ]);

        $pdo->commit();

        return [
            'invite_id' => $inviteId,
            'owner_user_id' => $ownerUserId,
            'domain_id' => $domainId,
            'target_email' => $targetEmail,
            'token' => $token,
            'expires_at' => gmdate(
                'Y-m-d\TH:i:s\Z',
                strtotime($expiresAt . ' UTC')
            ),
        ];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}

function iam_invite_registration_url(string $token): string {
    $base = rtrim(
        (string)(iam_config()['public_base_url'] ?? 'https://aigm.fi/iam'),
        '/'
    );

    return $base . '/register?token=' . rawurlencode($token);
}


function iam_invite_existing_user_by_email(
    PDO $pdo,
    string $targetEmail
): ?array {
    $stmt = $pdo->prepare(
        "SELECT
            u.user_id,
            u.username,
            u.status,
            a.account_status
         FROM IAM_user_accounts a
         INNER JOIN IAM_users u
            ON u.user_id = a.user_id
         WHERE a.email = ?
         LIMIT 1"
    );
    $stmt->execute([iam_normalize_email($targetEmail)]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!is_array($row)) {
        return null;
    }

    if (
        (string)$row['status'] !== 'active'
        || (string)$row['account_status'] !== 'active'
    ) {
        return null;
    }

    return $row;
}

function iam_accept_invite_for_existing_user(
    PDO $pdo,
    string $inviteId,
    string $userId,
    string $domainId
): void {
    $domainId = iam_require_domain($pdo, $domainId);

    $pdo->beginTransaction();

    try {
        $lock = $pdo->prepare(
            "SELECT invite_id
             FROM IAM_invites
             WHERE invite_id = ?
               AND status = 'active'
               AND claimed_by_user_id IS NULL
               AND expires_at > CURRENT_TIMESTAMP(6)
             FOR UPDATE"
        );
        $lock->execute([$inviteId]);

        if ($lock->fetchColumn() === false) {
            throw new RuntimeException('invite is no longer active');
        }

        $membership = $pdo->prepare(
            "INSERT INTO IAM_domain_memberships
                (user_id, domain_id, status)
             VALUES (?, ?, 'active')
             ON DUPLICATE KEY UPDATE
                status = VALUES(status)"
        );
        $membership->execute([$userId, $domainId]);

        $claim = $pdo->prepare(
            "UPDATE IAM_invites
             SET status = 'claimed',
                 claimed_by_user_id = ?,
                 claimed_at = CURRENT_TIMESTAMP(6)
             WHERE invite_id = ?
               AND status = 'active'
               AND claimed_by_user_id IS NULL"
        );
        $claim->execute([$userId, $inviteId]);

        if ($claim->rowCount() !== 1) {
            throw new RuntimeException('invite claim failed');
        }

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}


function iam_mark_invite_delivery_failed(
    PDO $pdo,
    string $inviteId
): void {
    $stmt = $pdo->prepare(
        "UPDATE IAM_invites
         SET status = 'delivery_failed'
         WHERE invite_id = ?
           AND status = 'active'
           AND claimed_by_user_id IS NULL"
    );
    $stmt->execute([$inviteId]);
}
