<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';
require_once dirname(__DIR__) . '/lib/invites.php';

iam_headers();
iam_require_method('POST');

try {
    $pdo = iam_pdo();
    $session = iam_require_session($pdo);

    $body = iam_json_body();
    $domainId = trim((string)($body['domain'] ?? ''));
    $email = trim((string)($body['email'] ?? ''));

    if ($domainId === '' || $email === '') {
        iam_fail(400, 'domain and email are required');
    }

    $invite = iam_create_invite(
        $pdo,
        (string)$session['user_id'],
        $domainId,
        $email
    );

    $registrationUrl = iam_invite_registration_url(
        (string)$invite['token']
    );

    http_response_code(201);
    echo json_encode(
        [
            'ok' => true,
            'invite' => [
                'id' => $invite['invite_id'],
                'domain' => $invite['domain_id'],
                'email' => $invite['target_email'],
                'expires_at' => $invite['expires_at'],
                'registration_url' => $registrationUrl,
                'delivery' => 'not_configured',
            ],
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
} catch (Throwable $e) {
    error_log('[IAM invite] ' . get_class($e) . ': ' . $e->getMessage());
    iam_fail(500, 'server error');
}
