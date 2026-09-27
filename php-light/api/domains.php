<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';
require_once dirname(__DIR__) . '/lib/domains.php';
require_once dirname(__DIR__) . '/lib/ip_blocks.php';

iam_headers();
iam_require_method('GET');

try {
    $pdo = iam_pdo();
    $session = iam_require_session($pdo);

    echo json_encode(
        [
            'ok' => true,
            'domains' => iam_user_domains(
                $pdo,
                (string)$session['user_id']
            ),
            'iam_security' => [
                'ip_blocks_manage' => iam_can_manage_ip_blocks(
                    $pdo,
                    (string)$session['user_id']
                ),
            ],
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
} catch (Throwable $e) {
    error_log('[IAM domains] ' . get_class($e) . ': ' . $e->getMessage());
    iam_fail(500, 'server error');
}
