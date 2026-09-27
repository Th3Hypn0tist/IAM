<?php

declare(strict_types=1);

function iam_mail_from(): string {
    $from = strtolower(trim(
        (string)(iam_config()['mail_from'] ?? 'noreply@aigm.fi')
    ));

    if (
        $from === ''
        || strlen($from) > 320
        || filter_var($from, FILTER_VALIDATE_EMAIL) === false
    ) {
        throw new RuntimeException('IAM mail_from is invalid');
    }

    return $from;
}

function iam_send_mail(
    string $to,
    string $subject,
    string $body
): void {
    $to = strtolower(trim($to));

    if (
        $to === ''
        || strlen($to) > 320
        || filter_var($to, FILTER_VALIDATE_EMAIL) === false
    ) {
        throw new InvalidArgumentException('mail recipient is invalid');
    }

    if (
        str_contains($subject, "\r")
        || str_contains($subject, "\n")
    ) {
        throw new InvalidArgumentException('mail subject is invalid');
    }

    $from = iam_mail_from();

    $headers = [
        'From: AIGM <' . $from . '>',
        'Reply-To: ' . $from,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
        'X-Auto-Response-Suppress: All',
    ];

    if (
        mail(
            $to,
            $subject,
            $body,
            implode("\r\n", $headers)
        ) !== true
    ) {
        throw new RuntimeException('mail delivery was not accepted');
    }
}

function iam_send_invite_email(array $invite): void {
    $email = (string)($invite['target_email'] ?? '');
    $token = (string)($invite['token'] ?? '');

    if ($token === '') {
        throw new RuntimeException('invite token is missing');
    }

    $url = iam_invite_registration_url($token);

    iam_send_mail(
        $email,
        'AIGM IAM invitation',
        "You have been invited to AIGM IAM!\n\n" .
        $url . "\n"
    );
}
