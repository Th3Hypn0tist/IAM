# IAM php-light

Dependency-free PHP implementation of `iam.light 1.0`.

## Deploy

Copy the contents of this directory to the web root serving the IAM path, for example:

```text
https://aigm.fi/iam
```

Then:

1. Copy `config.example.php` to `config.php`.
2. Fill the MariaDB/MySQL credentials.
3. Import `schema.sql` into the IAM database.
4. Use HTTPS.
5. Ensure PHP has PDO and PDO_MYSQL.

No Composer packages are required.

## Endpoints

```text
POST /api/login.php
POST /api/register.php
GET  /api/me.php
POST /api/logout.php
GET  /register/
```

The browser registration page is therefore available at:

```text
https://aigm.fi/iam/register/
```

## Existing Origin

An existing `users.user_id = '0'` identity is retained.

The account password hash must be a PHP `password_hash()` value because php-light deliberately does not carry legacy credential verifiers. If the account was created with another hash format, replace only `user_accounts.password_hash`; the canonical Origin identity itself does not change.

Generate a compatible hash with PHP:

```sh
php -r '$p=getenv("IAM_PASSWORD"); echo password_hash($p, defined("PASSWORD_ARGON2ID") ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT), PHP_EOL;'
```

Set `IAM_PASSWORD` only for that command and clear it afterwards, or use another non-logging local mechanism to generate the hash.

## Database ownership

php-light owns authentication state. Application consumers such as LMTS must not verify passwords against their local application database. They consume IAM sessions through the HTTP contract.
