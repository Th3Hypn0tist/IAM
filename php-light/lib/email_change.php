<?php

declare(strict_types=1);

require_once __DIR__ . '/common.php';
require_once __DIR__ . '/mail.php';
require_once __DIR__ . '/invites.php';

const IAM_EMAIL_CHANGE_TTL_SECONDS = 604800;

function iam_create_email_change_request(
    PDO $pdo,
    string $userId,
    string $newEmail
): array {
    $newEmail = iam_normalize_email($newEmail);

    $currentStmt = $pdo->prepare(
        "SELECT email
         FROM IAM_user_accounts
         WHERE user_id = ?
         LIMIT 1"
    );
    $currentStmt->execute([$userId]);
    $currentEmail = $currentStmt->fetchColumn();

    if ($currentEmail === false) {
        throw new RuntimeException('IAM account missing');
    }

    if (strcasecmp((string)$currentEmail, $newEmail) === 0) {
        iam_fail(400, 'New email must differ from current email.');
    }

    $conflict = $pdo->prepare(
        "SELECT 1
         FROM IAM_user_accounts
         WHERE email = ?
           AND user_id <> ?
         LIMIT 1"
    );
    $conflict->execute([$newEmail, $userId]);

    if ($conflict->fetchColumn() !== false) {
        iam_fail(409, 'Email already exists.');
    }

    $token = rtrim(
        strtr(base64_encode(random_bytes(32)), '+/', '-_'),
        '='
    );
    $tokenHash = hash('sha256', $token);
    $requestId = 'emc_' . bin2hex(random_bytes(16));
    $expiresAt = gmdate(
        'Y-m-d H:i:s',
        time() + IAM_EMAIL_CHANGE_TTL_SECONDS
    );

    $pdo->beginTransaction();

    try {
        $invalidate = $pdo->prepare(
            "UPDATE IAM_email_change_requests
             SET invalidated_at = CURRENT_TIMESTAMP(6)
             WHERE user_id = ?
               AND consumed_at IS NULL
               AND invalidated_at IS NULL"
        );
        $invalidate->execute([$userId]);

        $insert = $pdo->prepare(
            "INSERT INTO IAM_email_change_requests
                (
                    request_id,
                    user_id,
                    pending_email,
                    token_hash,
                    expires_at
                )
             VALUES (?, ?, ?, ?, ?)"
        );
        $insert->execute([
            $requestId,
            $userId,
            $newEmail,
            $tokenHash,
            $expiresAt,
        ]);

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }

    return [
        'request_id' => $requestId,
        'user_id' => $userId,
        'pending_email' => $newEmail,
        'token' => $token,
        'expires_at' => gmdate(
            'Y-m-d\TH:i:s\Z',
            strtotime($expiresAt . ' UTC')
        ),
    ];
}

function iam_email_change_verification_url(string $token): string {
    $base = rtrim(
        (string)(iam_config()['public_base_url'] ?? 'https://aigm.fi/iam'),
        '/'
    );

    return $base . '?email_verify=' . rawurlencode($token);
}

function iam_send_email_change_verification(array $request): void {
    $email = (string)($request['pending_email'] ?? '');
    $token = (string)($request['token'] ?? '');

    if ($token === '') {
        throw new RuntimeException('email change token is missing');
    }

    iam_send_mail(
        $email,
        'AIGM IAM email verification',
        "Verify your AIGM IAM email:\n\n" .
        iam_email_change_verification_url($token) . "\n"
    );
}

function iam_verify_email_change(
    PDO $pdo,
    string $token
): bool {
    if ($token === '') {
        return false;
    }

    $hash = hash('sha256', $token);

    $pdo->beginTransaction();

    try {
        $stmt = $pdo->prepare(
            "SELECT
                request_id,
                user_id,
                pending_email
             FROM IAM_email_change_requests
             WHERE token_hash = ?
               AND consumed_at IS NULL
               AND invalidated_at IS NULL
               AND expires_at > CURRENT_TIMESTAMP(6)
             LIMIT 1
             FOR UPDATE"
        );
        $stmt->execute([$hash]);
        $request = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!is_array($request)) {
            $pdo->rollBack();
            return false;
        }

        $conflict = $pdo->prepare(
            "SELECT 1
             FROM IAM_user_accounts
             WHERE email = ?
               AND user_id <> ?
             LIMIT 1
             FOR UPDATE"
        );
        $conflict->execute([
            (string)$request['pending_email'],
            (string)$request['user_id'],
        ]);

        if ($conflict->fetchColumn() !== false) {
            $pdo->rollBack();
            return false;
        }

        $update = $pdo->prepare(
            "UPDATE IAM_user_accounts
             SET email = ?
             WHERE user_id = ?"
        );
        $update->execute([
            (string)$request['pending_email'],
            (string)$request['user_id'],
        ]);

        $consume = $pdo->prepare(
            "UPDATE IAM_email_change_requests
             SET consumed_at = CURRENT_TIMESTAMP(6)
             WHERE request_id = ?
               AND consumed_at IS NULL"
        );
        $consume->execute([(string)$request['request_id']]);

        if ($consume->rowCount() !== 1) {
            throw new RuntimeException('email change consume failed');
        }

        $pdo->commit();
        return true;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}
