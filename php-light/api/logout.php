<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';

iam_headers();
iam_require_method('POST');

try {
    $pdo = iam_pdo();
    $token = iam_bearer_token();
    if ($token !== null) {
        $stmt = $pdo->prepare(
            'UPDATE iam_sessions SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP(6)) WHERE token_hash = ?'
        );
        $stmt->execute([hash('sha256', $token)]);
    }
    iam_clear_cookie();
    echo json_encode(['ok' => true, 'contract' => IAM_CONTRACT, 'version' => IAM_VERSION], JSON_UNESCAPED_SLASHES);
} catch (Throwable $e) {
    iam_fail(500, 'server error');
}
