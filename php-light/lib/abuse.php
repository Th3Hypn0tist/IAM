<?php

declare(strict_types=1);

function iam_abuse_secret(): string {
    $value = (string)(iam_config()['abuse_hmac_secret'] ?? '');
    if (strlen($value) < 32 || str_starts_with($value, 'CHANGE_ME')) {
        throw new RuntimeException('abuse_hmac_secret must be configured');
    }
    return $value;
}

function iam_abuse_client_ip(): string {
    $value = $_SERVER['REMOTE_ADDR'] ?? '';
    return is_string($value) && $value !== '' ? $value : 'unknown';
}

function iam_abuse_ip_hash(): string {
    return hash_hmac('sha256', iam_abuse_client_ip(), iam_abuse_secret());
}

function iam_abuse_identifier_hash(string $value): string {
    return hash_hmac('sha256', strtolower(trim($value)), iam_abuse_secret());
}

function iam_abuse_prune(PDO $pdo): void {
    $pdo->exec(
        "DELETE FROM IAM_abuse_events
         WHERE created_at < TIMESTAMPADD(DAY, -7, CURRENT_TIMESTAMP(6))"
    );
    $pdo->exec(
        "DELETE FROM IAM_ip_blocks
         WHERE expires_at IS NOT NULL
           AND expires_at <= CURRENT_TIMESTAMP(6)"
    );
}

function iam_abuse_is_blocked(PDO $pdo, string $ipHash): bool {
    $stmt = $pdo->prepare(
        "SELECT 1
         FROM IAM_ip_blocks
         WHERE ip_hash = ?
           AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP(6))
         LIMIT 1"
    );
    $stmt->execute([$ipHash]);
    return $stmt->fetchColumn() !== false;
}

function iam_abuse_require_not_blocked(PDO $pdo, string $ipHash): void {
    if (iam_abuse_is_blocked($pdo, $ipHash)) {
        iam_fail(403, 'Access blocked.');
    }
}

function iam_abuse_log(
    PDO $pdo,
    string $ipHash,
    ?string $identifierHash,
    string $action,
    string $outcome
): void {
    $stmt = $pdo->prepare(
        "INSERT INTO IAM_abuse_events
            (event_id, ip_hash, identifier_hash, action, outcome, created_at)
         VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP(6))"
    );
    $stmt->execute([
        'abe_' . bin2hex(random_bytes(16)),
        $ipHash,
        $identifierHash,
        $action,
        $outcome,
    ]);
}

function iam_abuse_count(
    PDO $pdo,
    string $action,
    string $column,
    string $hash,
    int $windowSeconds
): int {
    if (!in_array($column, ['ip_hash', 'identifier_hash'], true)) {
        throw new InvalidArgumentException('invalid abuse counter column');
    }
    $sql = sprintf(
        "SELECT COUNT(*)
         FROM IAM_abuse_events
         WHERE action = ?
           AND %s = ?
           AND outcome NOT IN ('accepted', 'blocked')
           AND created_at >= TIMESTAMPADD(SECOND, -?, CURRENT_TIMESTAMP(6))",
        $column
    );
    $stmt = $pdo->prepare($sql);
    $stmt->execute([$action, $hash, $windowSeconds]);
    return (int)$stmt->fetchColumn();
}

function iam_abuse_block(
    PDO $pdo,
    string $ipHash,
    string $reason,
    string $source,
    int $ttlSeconds
): void {
    if ($ttlSeconds < 1) throw new InvalidArgumentException('block TTL must be positive');
    $expiresAt = gmdate('Y-m-d H:i:s', time() + $ttlSeconds);
    $stmt = $pdo->prepare(
        "INSERT INTO IAM_ip_blocks (ip_hash, reason, source, created_at, expires_at)
         VALUES (?, ?, ?, CURRENT_TIMESTAMP(6), ?)
         ON DUPLICATE KEY UPDATE
             reason = VALUES(reason),
             source = VALUES(source),
             created_at = CURRENT_TIMESTAMP(6),
             expires_at = GREATEST(COALESCE(expires_at, VALUES(expires_at)), VALUES(expires_at))"
    );
    $stmt->execute([$ipHash, $reason, $source, $expiresAt]);
    iam_abuse_log($pdo, $ipHash, null, $source, 'blocked');
}
