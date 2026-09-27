<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';
require_once dirname(__DIR__) . '/lib/user_management.php';

iam_headers();
iam_require_method('GET');

try {
    $pdo = iam_pdo();
    $session = iam_require_session($pdo);

    $domainId = trim((string)($_GET['domain'] ?? ''));
    if ($domainId === '') {
        iam_fail(400, 'domain is required');
    }

    echo json_encode(
        [
            'ok' => true,
            'domain' => $domainId,
            'members' => iam_domain_members(
                $pdo,
                (string)$session['user_id'],
                $domainId
            ),
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
} catch (Throwable $e) {
    error_log('[IAM users] ' . get_class($e) . ': ' . $e->getMessage());
    iam_fail(500, 'server error');
}
