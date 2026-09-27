<?php

declare(strict_types=1);

require_once __DIR__ . '/common.php';
require_once __DIR__ . '/abuse.php';

function iam_can_manage_ip_blocks(
    PDO $pdo,
    string $userId
): bool {
    if (!iam_has_domain_membership(
        $pdo,
        $userId,
        IAM_ROOT_DOMAIN
    )) {
        return false;
    }

    $effective = iam_effective_management_tier(
        $pdo,
        $userId,
        IAM_ROOT_DOMAIN
    );

    return in_array(
        (int)$effective['tier'],
        [
            IAM_MANAGEMENT_TIER_MANAGE,
            IAM_MANAGEMENT_TIER_AAA,
        ],
        true
    );
}

function iam_require_ip_block_manager(
    PDO $pdo,
    string $userId
): void {
    if (!iam_can_manage_ip_blocks($pdo, $userId)) {
        iam_fail(403, 'Access denied.');
    }
}

function iam_list_ip_blocks(
    PDO $pdo,
    string $actorUserId
): array {
    iam_require_ip_block_manager($pdo, $actorUserId);

    $stmt = $pdo->query(
        "SELECT
            ip_hash,
            reason,
            source,
            created_at,
            expires_at
         FROM IAM_ip_blocks
         WHERE expires_at IS NULL
            OR expires_at > CURRENT_TIMESTAMP(6)
         ORDER BY created_at DESC"
    );

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function iam_manual_ip_block(
    PDO $pdo,
    string $actorUserId,
    string $ip,
    string $reason,
    ?int $ttlSeconds
): array {
    iam_require_ip_block_manager($pdo, $actorUserId);

    $ip = trim($ip);
    $reason = trim($reason);

    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        iam_fail(400, 'IP address is not valid.');
    }

    if ($reason === '' || strlen($reason) > 128) {
        iam_fail(400, 'reason is required');
    }

    $hash = hash_hmac(
        'sha256',
        $ip,
        iam_abuse_secret()
    );

    $expiresAt = null;

    if ($ttlSeconds !== null) {
        if ($ttlSeconds < 60) {
            iam_fail(400, 'ttl_seconds must be at least 60');
        }

        $expiresAt = gmdate(
            'Y-m-d H:i:s',
            time() + $ttlSeconds
        );
    }

    $pdo->beginTransaction();

    try {
        $stmt = $pdo->prepare(
            "INSERT INTO IAM_ip_blocks
                (
                    ip_hash,
                    reason,
                    source,
                    created_at,
                    expires_at
                )
             VALUES (
                ?,
                ?,
                'manual',
                CURRENT_TIMESTAMP(6),
                ?
             )
             ON DUPLICATE KEY UPDATE
                reason = VALUES(reason),
                source = 'manual',
                created_at = CURRENT_TIMESTAMP(6),
                expires_at = VALUES(expires_at)"
        );
        $stmt->execute([
            $hash,
            $reason,
            $expiresAt,
        ]);

        $audit = $pdo->prepare(
            "INSERT INTO IAM_ip_block_audit
                (
                    actor_user_id,
                    ip_hash,
                    action,
                    reason
                )
             VALUES (?, ?, 'block', ?)"
        );
        $audit->execute([
            $actorUserId,
            $hash,
            $reason,
        ]);

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }

    return [
        'ip_hash' => $hash,
        'reason' => $reason,
        'source' => 'manual',
        'expires_at' => $expiresAt,
    ];
}

function iam_manual_ip_unblock(
    PDO $pdo,
    string $actorUserId,
    string $ipHash
): void {
    iam_require_ip_block_manager($pdo, $actorUserId);

    $ipHash = strtolower(trim($ipHash));

    if (preg_match('/^[a-f0-9]{64}$/D', $ipHash) !== 1) {
        iam_fail(400, 'ip_hash is not valid');
    }

    $pdo->beginTransaction();

    try {
        $delete = $pdo->prepare(
            "DELETE FROM IAM_ip_blocks
             WHERE ip_hash = ?"
        );
        $delete->execute([$ipHash]);

        $audit = $pdo->prepare(
            "INSERT INTO IAM_ip_block_audit
                (
                    actor_user_id,
                    ip_hash,
                    action,
                    reason
                )
             VALUES (?, ?, 'unblock', NULL)"
        );
        $audit->execute([
            $actorUserId,
            $ipHash,
        ]);

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}
