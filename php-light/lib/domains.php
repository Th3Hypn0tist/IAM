<?php

declare(strict_types=1);

require_once __DIR__ . '/common.php';

function iam_user_domains(PDO $pdo, string $userId): array {
    $stmt = $pdo->prepare(
        "SELECT
            d.domain_id,
            d.display_name,
            d.parent_domain_id,
            m.status AS membership_status
         FROM IAM_domain_memberships m
         INNER JOIN IAM_domains d
            ON d.domain_id = m.domain_id
         WHERE m.user_id = ?
           AND m.status = 'active'
           AND d.status = 'active'
         ORDER BY d.domain_id ASC"
    );
    $stmt->execute([$userId]);

    $domains = [];

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $effective = iam_effective_management_tier(
            $pdo,
            $userId,
            (string)$row['domain_id']
        );

        $domains[] = [
            'id' => (string)$row['domain_id'],
            'display_name' => (string)$row['display_name'],
            'parent_domain_id' => $row['parent_domain_id'] === null
                ? null
                : (string)$row['parent_domain_id'],
            'effective_tier' => (int)$effective['tier'],
            'effective_source_domain' =>
                $effective['source_domain_id'],
        ];
    }

    return $domains;
}
