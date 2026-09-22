<?php

declare(strict_types=1);

return [
    'dsn' => 'mysql:host=127.0.0.1;dbname=aigm;charset=utf8mb4',
    'user' => 'iam',
    'password' => 'CHANGE_ME',
    'session_ttl_seconds' => 2592000,
    'cookie_name' => 'iam_light',
    'cookie_path' => '/iam',
    'cookie_secure' => true,
    'registration_hmac_secret' => 'CHANGE_ME_TO_A_RANDOM_SECRET_OF_AT_LEAST_32_BYTES',
];
