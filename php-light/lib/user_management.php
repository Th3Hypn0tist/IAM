<?php

declare(strict_types=1);

require_once __DIR__ . '/common.php';

function iam_domain_members(
    PDO $pdo,
    string $actorUserId,
    string $domainId
): array {
    $domainId = iam_require_domain($pdo, $domainId);

    if (!iam_can_manage_domain_users($pdo, $actorUserId, $domainId)) {
        iam_fail(403, 'Access denied.');
    }

    $stmt = $pdo->prepare(
        "SELECT
            m.user_id,
            u.username,
            u.status,
            a.email,
            m.status AS membership_status,
            t.management_tier AS explicit_tier
         FROM IAM_domain_memberships m
         INNER JOIN IAM_users u
            ON u.user_id = m.user_id
         INNER JOIN IAM_user_accounts a
            ON a.user_id = m.user_id
         LEFT JOIN IAM_management_tiers t
            ON t.user_id = m.user_id
           AND t.domain_id = m.domain_id
           AND t.status = 'active'
         WHERE m.domain_id = ?
         ORDER BY u.username ASC"
    );
    $stmt->execute([$domainId]);

    $members = [];

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $effective = iam_effective_management_tier(
            $pdo,
            (string)$row['user_id'],
            $domainId
        );

        $members[] = [
            'user_id' => (string)$row['user_id'],
            'username' => (string)$row['username'],
            'email' => (string)$row['email'],
            'user_status' => (string)$row['status'],
            'membership_status' => (string)$row['membership_status'],
            'explicit_tier' => $row['explicit_tier'] === null
                ? null
                : (int)$row['explicit_tier'],
            'effective_tier' => (int)$effective['tier'],
            'effective_source_domain' =>
                $effective['source_domain_id'],
        ];
    }

    return $members;
}

function iam_explicit_management_tier(
    PDO $pdo,
    string $userId,
    string $domainId
): ?int {
    $stmt = $pdo->prepare(
        "SELECT management_tier
         FROM IAM_management_tiers
         WHERE user_id = ?
           AND domain_id = ?
           AND status = 'active'
         LIMIT 1"
    );
    $stmt->execute([$userId, $domainId]);
    $value = $stmt->fetchColumn();

    return $value === false ? null : (int)$value;
}

function iam_set_management_tier(
    PDO $pdo,
    string $actorUserId,
    string $targetUserId,
    string $domainId,
    int $newTier
): array {
    $domainId = iam_require_domain($pdo, $domainId);

    if (!iam_management_tier_is_assignable($newTier)) {
        iam_fail(400, 'invalid management tier');
    }

    if (!iam_can_manage_domain_users($pdo, $actorUserId, $domainId)) {
        iam_fail(403, 'Access denied.');
    }

    $membership = $pdo->prepare(
        "SELECT status
         FROM IAM_domain_memberships
         WHERE user_id = ?
           AND domain_id = ?
         LIMIT 1"
    );
    $membership->execute([$targetUserId, $domainId]);

    if ($membership->fetchColumn() !== 'active') {
        iam_fail(404, 'User not found in domain.');
    }

    $beforeEffective = iam_effective_management_tier(
        $pdo,
        $targetUserId,
        $domainId
    );

    if ((int)$beforeEffective['tier'] === IAM_MANAGEMENT_TIER_AAA) {
        iam_fail(403, 'AAA management tier cannot be modified here.');
    }

    $fromExplicit = iam_explicit_management_tier(
        $pdo,
        $targetUserId,
        $domainId
    );

    $pdo->beginTransaction();

    try {
        if ($newTier === IAM_MANAGEMENT_TIER_USER) {
            $delete = $pdo->prepare(
                "DELETE FROM IAM_management_tiers
                 WHERE user_id = ?
                   AND domain_id = ?"
            );
            $delete->execute([$targetUserId, $domainId]);
        } else {
            $upsert = $pdo->prepare(
                "INSERT INTO IAM_management_tiers
                    (user_id, domain_id, management_tier, status)
                 VALUES (?, ?, ?, 'active')
                 ON DUPLICATE KEY UPDATE
                    management_tier = VALUES(management_tier),
                    status = 'active'"
            );
            $upsert->execute([
                $targetUserId,
                $domainId,
                $newTier,
            ]);
        }

        $audit = $pdo->prepare(
            "INSERT INTO IAM_management_audit
                (
                    actor_user_id,
                    target_user_id,
                    domain_id,
                    action,
                    from_tier,
                    to_tier
                )
             VALUES (?, ?, ?, 'set_tier', ?, ?)"
        );
        $audit->execute([
            $actorUserId,
            $targetUserId,
            $domainId,
            $fromExplicit,
            $newTier,
        ]);

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }

    return iam_effective_management_tier(
        $pdo,
        $targetUserId,
        $domainId
    );
}
