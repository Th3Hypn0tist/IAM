<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';
require_once dirname(__DIR__) . '/lib/user_management.php';

iam_headers();
iam_require_method('POST');

try {
    $pdo = iam_pdo();
    $session = iam_require_session($pdo);
    $body = iam_json_body();

    $domainId = trim((string)($body['domain'] ?? ''));
    $targetUserId = trim((string)($body['user_id'] ?? ''));
    $tierRaw = $body['tier'] ?? null;

    if (
        $domainId === ''
        || $targetUserId === ''
        || !is_int($tierRaw)
    ) {
        iam_fail(400, 'domain, user_id and integer tier are required');
    }

    $effective = iam_set_management_tier(
        $pdo,
        (string)$session['user_id'],
        $targetUserId,
        $domainId,
        $tierRaw
    );

    echo json_encode(
        [
            'ok' => true,
            'user_id' => $targetUserId,
            'domain' => $domainId,
            'effective_tier' => (int)$effective['tier'],
            'source_domain' => $effective['source_domain_id'],
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
} catch (Throwable $e) {
    error_log('[IAM tier] ' . get_class($e) . ': ' . $e->getMessage());
    iam_fail(500, 'server error');
}
