<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';
require_once dirname(__DIR__) . '/lib/identity_core.php';

iam_headers();

try {
    $pdo = iam_pdo();
    $row = iam_require_session($pdo);
    $userId = (string)$row['user_id'];

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        echo json_encode(
            [
                'ok' => true,
                'profile' => identitycore_profile($pdo, $userId),
            ],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('Allow: GET, POST');
        iam_fail(405, 'method not allowed');
    }

    $body = iam_json_body();
    $fields = $body['fields'] ?? [];
    $visibility = $body['visibility'] ?? [];

    if (!is_array($fields) || array_is_list($fields)) {
        iam_fail(400, 'fields must be an object');
    }
    if (!is_array($visibility) || array_is_list($visibility)) {
        iam_fail(400, 'visibility must be an object');
    }

    try {
        $profile = identitycore_update(
            $pdo,
            $userId,
            $fields,
            $visibility
        );
    } catch (InvalidArgumentException $e) {
        iam_fail(400, $e->getMessage());
    }

    echo json_encode(
        [
            'ok' => true,
            'profile' => $profile,
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
} catch (Throwable $e) {
    error_log('[IAM profile] ' . get_class($e) . ': ' . $e->getMessage());
    iam_fail(500, 'server error');
}
