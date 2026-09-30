<?php

declare(strict_types=1);

const IDENTITYCORE_FIELDS = [
    'display_name',
    'organization',
    'phone',
    'country',
    'timezone',
    'language',
    'website',
];

function identitycore_fields(): array {
    return IDENTITYCORE_FIELDS;
}

function identitycore_profile(PDO $pdo, string $userId): array {
    $stmt = $pdo->prepare(
        "SELECT
            display_name,
            organization,
            phone,
            country,
            timezone,
            language,
            website
         FROM IdentityCore_profiles
         WHERE user_id = ?
         LIMIT 1"
    );
    $stmt->execute([$userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!is_array($row)) {
        $row = array_fill_keys(identitycore_fields(), null);
    }

    $visibilityStmt = $pdo->prepare(
        "SELECT field_name, visibility
         FROM IdentityCore_field_visibility
         WHERE user_id = ?"
    );
    $visibilityStmt->execute([$userId]);

    $visibility = array_fill_keys(identitycore_fields(), 'private');

    while ($item = $visibilityStmt->fetch(PDO::FETCH_ASSOC)) {
        $field = (string)$item['field_name'];
        if (array_key_exists($field, $visibility)) {
            $visibility[$field] = (string)$item['visibility'];
        }
    }

    return [
        'fields' => $row,
        'visibility' => $visibility,
    ];
}

function identitycore_normalize_field(string $field, mixed $value): ?string {
    if (!in_array($field, identitycore_fields(), true)) {
        throw new InvalidArgumentException('invalid IdentityCore field');
    }

    if ($value === null) {
        return null;
    }

    if (!is_string($value)) {
        throw new InvalidArgumentException('IdentityCore field must be a string');
    }

    $value = trim($value);
    if ($value === '') {
        return null;
    }

    $max = match ($field) {
        'phone' => 64,
        'language' => 32,
        'country', 'timezone' => 128,
        'website' => 512,
        default => 255,
    };

    if (strlen($value) > $max) {
        throw new InvalidArgumentException('IdentityCore field is too long');
    }

    if ($field === 'website') {
        if (!preg_match('~^[a-z][a-z0-9+.-]*://~i', $value)) {
            $value = 'https://' . $value;
        }

        $validated = filter_var($value, FILTER_VALIDATE_URL);
        $parts = $validated === false ? false : parse_url($validated);

        if (
            $validated === false
            || !is_array($parts)
            || !isset($parts['scheme'], $parts['host'])
            || !in_array(strtolower((string)$parts['scheme']), ['http', 'https'], true)
            || (string)$parts['host'] === ''
        ) {
            throw new InvalidArgumentException('website is not valid');
        }

        $value = $validated;
    }

    return $value;
}

function identitycore_update(
    PDO $pdo,
    string $userId,
    array $fields,
    array $visibility
): array {
    $normalized = [];

    foreach (identitycore_fields() as $field) {
        $normalized[$field] = identitycore_normalize_field(
            $field,
            $fields[$field] ?? null
        );
    }

    foreach (identitycore_fields() as $field) {
        $value = (string)($visibility[$field] ?? 'private');
        if (!in_array($value, ['private', 'public'], true)) {
            throw new InvalidArgumentException('invalid IdentityCore visibility');
        }
        $visibility[$field] = $value;
    }

    $pdo->beginTransaction();

    try {
        $profile = $pdo->prepare(
            "INSERT INTO IdentityCore_profiles
                (
                    user_id,
                    display_name,
                    organization,
                    phone,
                    country,
                    timezone,
                    language,
                    website
                )
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                display_name = VALUES(display_name),
                organization = VALUES(organization),
                phone = VALUES(phone),
                country = VALUES(country),
                timezone = VALUES(timezone),
                language = VALUES(language),
                website = VALUES(website)"
        );

        $profile->execute([
            $userId,
            $normalized['display_name'],
            $normalized['organization'],
            $normalized['phone'],
            $normalized['country'],
            $normalized['timezone'],
            $normalized['language'],
            $normalized['website'],
        ]);

        $visStmt = $pdo->prepare(
            "INSERT INTO IdentityCore_field_visibility
                (user_id, field_name, visibility)
             VALUES (?, ?, ?)
             ON DUPLICATE KEY UPDATE
                visibility = VALUES(visibility)"
        );

        foreach (identitycore_fields() as $field) {
            $visStmt->execute([
                $userId,
                $field,
                $visibility[$field],
            ]);
        }

        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }

    return identitycore_profile($pdo, $userId);
}

function identitycore_public_profile_by_username(
    PDO $pdo,
    string $username
): ?array {
    $stmt = $pdo->prepare(
        "SELECT u.user_id, u.username, p.*
         FROM IAM_users u
         LEFT JOIN IdentityCore_profiles p
            ON p.user_id = u.user_id
         WHERE u.username = ?
           AND u.status = 'active'
         LIMIT 1"
    );
    $stmt->execute([$username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!is_array($row)) {
        return null;
    }

    $userId = (string)$row['user_id'];

    $visibilityStmt = $pdo->prepare(
        "SELECT field_name
         FROM IdentityCore_field_visibility
         WHERE user_id = ?
           AND visibility = 'public'"
    );
    $visibilityStmt->execute([$userId]);

    $publicFields = [];
    while ($field = $visibilityStmt->fetchColumn()) {
        $field = (string)$field;
        if (!in_array($field, identitycore_fields(), true)) {
            continue;
        }

        $value = $row[$field] ?? null;
        if (is_string($value) && $value !== '') {
            $publicFields[$field] = $value;
        }
    }

    return [
        'user_id' => $userId,
        'username' => (string)$row['username'],
        'fields' => $publicFields,
    ];
}
