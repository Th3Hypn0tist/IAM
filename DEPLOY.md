# php-light deployment

Reference live target:

```text
https://aigm.fi/iam
/var/www/vhosts/aigm.fi/httpdocs/iam/
```

The live `config.php` stays on the server and is not overwritten by deploys.

Its shared database config binding remains:

```php
'db_config' => __DIR__ . '/../../config.php',
```

which resolves to:

```text
/var/www/vhosts/aigm.fi/config.php
```

## Fresh database

Before first deploy of `iam.light 1.1`:

1. Create/reset the IAM database.
2. Execute `php-light/schema.sql`.
3. Generate a password hash compatible with PHP `password_hash()`.
4. Copy `bootstrap-origin.sql.example` outside the web root.
5. Replace the bootstrap email and password-hash placeholders.
6. Execute the bootstrap SQL directly against the IAM database.
7. Delete the filled bootstrap copy.

The bootstrap creates:

```text
user_id: 0
username: origin
IAM membership: active
LMTS membership: active
IAM management tier: 1337
```

Tier `1337` is intentionally inserted through SQL only.

## Files deployed to /iam

Deploy:

```text
.htaccess
index.php
api/
lib/
```

Do not deploy:

```text
config.example.php
config.php
schema.sql
bootstrap-origin.sql.example
README.md
contract/
.git*
```

## Required live config values

The live `config.php` must provide or inherit:

```php
'session_ttl_seconds' => 2592000,
'cookie_name' => 'iam_light',
'cookie_path' => '/',
'cookie_secure' => true,
'abuse_hmac_secret' => '<at least 32 random bytes>',
'invalid_invite_block_seconds' => 3600,
'public_base_url' => 'https://aigm.fi/iam',
'mail_from' => 'noreply@aigm.fi',
```

## Server requirements

- HTTPS
- PHP with PDO + PDO_MYSQL
- PHP `mail()`
- working local MTA
- Apache rewrite support
- `.htaccess` overrides enabled for the IAM directory

## First smoke test

After deploy:

1. Open `https://aigm.fi/iam`.
2. Log in as `origin`.
3. Confirm the IAM and LMTS domains are listed.
4. Confirm IP-block management is visible for Origin.
5. Create an LMTS invite.
6. Confirm email arrives from `noreply@aigm.fi`.
7. Open the invite and register a new user.
8. Confirm the new user can restore IAM session with `domain=lmts`.
9. Confirm the new user cannot access IP-block management.
10. Change the new user's email and verify it through the received link.
