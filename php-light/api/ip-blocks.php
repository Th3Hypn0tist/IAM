<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';
require_once dirname(__DIR__) . '/lib/ip_blocks.php';

iam_headers();

try {
    $pdo = iam_pdo();
    $session = iam_require_session($pdo);
    $actorUserId = (string)$session['user_id'];

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        echo json_encode(
            [
                'ok' => true,
                'blocks' => iam_list_ip_blocks(
                    $pdo,
                    $actorUserId
                ),
            ],
            JSON_UNESCAPED_SLASHES
                | JSON_UNESCAPED_UNICODE
        );
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('Allow: GET, POST');
        iam_fail(405, 'method not allowed');
    }

    $body = iam_json_body();
    $action = trim((string)($body['action'] ?? ''));

    if ($action === 'block') {
        $ttl = $body['ttl_seconds'] ?? null;

        if ($ttl !== null && !is_int($ttl)) {
            iam_fail(400, 'ttl_seconds must be an integer');
        }

        $block = iam_manual_ip_block(
            $pdo,
            $actorUserId,
            (string)($body['ip'] ?? ''),
            (string)($body['reason'] ?? ''),
            $ttl
        );

        echo json_encode(
            [
                'ok' => true,
                'block' => $block,
            ],
            JSON_UNESCAPED_SLASHES
                | JSON_UNESCAPED_UNICODE
        );
        exit;
    }

    if ($action === 'unblock') {
        iam_manual_ip_unblock(
            $pdo,
            $actorUserId,
            (string)($body['ip_hash'] ?? '')
        );

        echo json_encode(
            ['ok' => true],
            JSON_UNESCAPED_SLASHES
        );
        exit;
    }

    iam_fail(400, 'invalid action');
} catch (Throwable $e) {
    error_log(
        '[IAM IP blocks] '
        . get_class($e)
        . ': '
        . $e->getMessage()
    );
    iam_fail(500, 'server error');
}
