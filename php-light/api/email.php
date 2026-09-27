<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';
require_once dirname(__DIR__) . '/lib/email_change.php';

iam_headers();
iam_require_method('POST');

try {
    $pdo = iam_pdo();
    $session = iam_require_session($pdo);
    $body = iam_json_body();

    $email = trim((string)($body['email'] ?? ''));

    if ($email === '') {
        iam_fail(400, 'email is required');
    }

    $request = iam_create_email_change_request(
        $pdo,
        (string)$session['user_id'],
        $email
    );

    try {
        iam_send_email_change_verification($request);
    } catch (Throwable $deliveryError) {
        $invalidate = $pdo->prepare(
            "UPDATE IAM_email_change_requests
             SET invalidated_at = CURRENT_TIMESTAMP(6)
             WHERE request_id = ?
               AND consumed_at IS NULL
               AND invalidated_at IS NULL"
        );
        $invalidate->execute([(string)$request['request_id']]);
        throw $deliveryError;
    }

    echo json_encode(
        [
            'ok' => true,
            'pending_email' => $request['pending_email'],
            'expires_at' => $request['expires_at'],
            'delivery' => 'sent',
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
} catch (Throwable $e) {
    error_log('[IAM email change] ' . get_class($e) . ': ' . $e->getMessage());
    iam_fail(500, 'server error');
}
