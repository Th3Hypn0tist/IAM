<?php

declare(strict_types=1);

/*
 * IAM management tiers govern USER ADMINISTRATION ONLY.
 *
 * They are not application permissions. Application authorization belongs
 * to AccessCore.
 */

const IAM_ROOT_DOMAIN = 'iam';

const IAM_MANAGEMENT_TIER_USER = 3;
const IAM_MANAGEMENT_TIER_INVITE = 2;
const IAM_MANAGEMENT_TIER_MANAGE = 1;
const IAM_MANAGEMENT_TIER_AAA = 1337;

function iam_management_tier_is_valid(int $tier): bool {
    return in_array(
        $tier,
        [
            IAM_MANAGEMENT_TIER_USER,
            IAM_MANAGEMENT_TIER_INVITE,
            IAM_MANAGEMENT_TIER_MANAGE,
            IAM_MANAGEMENT_TIER_AAA,
        ],
        true
    );
}

function iam_management_tier_is_assignable(int $tier): bool {
    return in_array(
        $tier,
        [
            IAM_MANAGEMENT_TIER_USER,
            IAM_MANAGEMENT_TIER_INVITE,
            IAM_MANAGEMENT_TIER_MANAGE,
        ],
        true
    );
}

/*
 * Never compare IAM tier numbers numerically.
 *
 * Privilege order:
 *
 * 1337 > 1 > 2 > 3
 */
function iam_management_tier_rank(int $tier): int {
    return match ($tier) {
        IAM_MANAGEMENT_TIER_USER => 0,
        IAM_MANAGEMENT_TIER_INVITE => 1,
        IAM_MANAGEMENT_TIER_MANAGE => 2,
        IAM_MANAGEMENT_TIER_AAA => 3,
        default => throw new InvalidArgumentException('invalid IAM management tier'),
    };
}

function iam_domain_id_normalize(string $domainId): string {
    return strtolower(trim($domainId));
}

function iam_domain_id_is_valid(string $domainId): bool {
    return preg_match('/^[a-z0-9][a-z0-9._-]{0,63}$/D', $domainId) === 1;
}

function iam_require_domain(PDO $pdo, string $domainId): string {
    $domainId = iam_domain_id_normalize($domainId);

    if ($domainId === '' || !iam_domain_id_is_valid($domainId)) {
        iam_fail(400, 'invalid domain');
    }

    $stmt = $pdo->prepare(
        "SELECT domain_id
         FROM IAM_domains
         WHERE domain_id = ?
           AND status = 'active'
         LIMIT 1"
    );
    $stmt->execute([$domainId]);

    if ($stmt->fetchColumn() === false) {
        iam_fail(400, 'invalid domain');
    }

    return $domainId;
}

/*
 * Resolve user-management authority for one target domain.
 *
 * Authority is inherited DOWN the domain tree only. Resolution therefore
 * starts at the target and walks through its ancestors. Child and sibling
 * assignments can never influence the target's parent.
 *
 * A weaker local assignment cannot reduce stronger inherited authority.
 */
function iam_effective_management_tier(
    PDO $pdo,
    string $userId,
    string $domainId
): array {
    $domainId = iam_require_domain($pdo, $domainId);

    $stmt = $pdo->prepare(
        "WITH RECURSIVE ancestors AS (
            SELECT
                domain_id,
                parent_domain_id,
                0 AS depth
            FROM IAM_domains
            WHERE domain_id = ?
              AND status = 'active'

            UNION ALL

            SELECT
                d.domain_id,
                d.parent_domain_id,
                a.depth + 1
            FROM IAM_domains d
            INNER JOIN ancestors a
                ON d.domain_id = a.parent_domain_id
            WHERE d.status = 'active'
              AND a.depth < 64
        )
        SELECT
            a.domain_id,
            a.depth,
            t.management_tier
        FROM ancestors a
        INNER JOIN IAM_management_tiers t
            ON t.domain_id = a.domain_id
           AND t.user_id = ?
           AND t.status = 'active'
        ORDER BY a.depth ASC"
    );

    $stmt->execute([$domainId, $userId]);

    $bestTier = IAM_MANAGEMENT_TIER_USER;
    $bestSource = null;
    $bestDepth = null;

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $tier = (int)$row['management_tier'];

        if (!iam_management_tier_is_valid($tier)) {
            throw new RuntimeException('invalid IAM management tier in database');
        }

        if (
            $bestSource === null
            || iam_management_tier_rank($tier) > iam_management_tier_rank($bestTier)
        ) {
            $bestTier = $tier;
            $bestSource = (string)$row['domain_id'];
            $bestDepth = (int)$row['depth'];
        }
    }

    return [
        'tier' => $bestTier,
        'source_domain_id' => $bestSource,
        'target_domain_id' => $domainId,
        'inherited' => $bestSource !== null && $bestSource !== $domainId,
        'depth' => $bestDepth,
    ];
}

function iam_can_invite_to_domain(PDO $pdo, string $userId, string $domainId): bool {
    $effective = iam_effective_management_tier($pdo, $userId, $domainId);

    return in_array(
        (int)$effective['tier'],
        [
            IAM_MANAGEMENT_TIER_INVITE,
            IAM_MANAGEMENT_TIER_MANAGE,
            IAM_MANAGEMENT_TIER_AAA,
        ],
        true
    );
}

function iam_can_manage_domain_users(PDO $pdo, string $userId, string $domainId): bool {
    $effective = iam_effective_management_tier($pdo, $userId, $domainId);

    return in_array(
        (int)$effective['tier'],
        [
            IAM_MANAGEMENT_TIER_MANAGE,
            IAM_MANAGEMENT_TIER_AAA,
        ],
        true
    );
}

function iam_has_domain_aaa(PDO $pdo, string $userId, string $domainId): bool {
    $effective = iam_effective_management_tier($pdo, $userId, $domainId);
    return (int)$effective['tier'] === IAM_MANAGEMENT_TIER_AAA;
}
