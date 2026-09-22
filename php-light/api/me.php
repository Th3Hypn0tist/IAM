<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/common.php';

iam_headers();
iam_require_method('GET');

try {
    $row = iam_require_session(iam_pdo());
    echo json_encode(iam_base_payload($row), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    iam_fail(500, 'server error');
}
