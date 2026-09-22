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
3. Set `registration_hmac_secret` to a random secret of at least 32 bytes.
4. Import `schema.sql` into the IAM database.
5. Use HTTPS.
6. Ensure PHP has PDO and PDO_MYSQL.

No Composer packages are required.

Generate a registration HMAC secret locally:

```sh
php -r 'echo bin2hex(random_bytes(32)), PHP_EOL;'
```

Do not reuse a password, invite code, bearer token or database credential as the HMAC secret.

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

## Registration abuse guard

Registration remains invite-only. php-light additionally applies:

- 5 registration attempts per IP hash / 10 minutes;
- 20 registration attempts per IP hash / 24 hours;
- 5 registration attempts per invite hash / 30 minutes;
- HTTP 429 with `Retry-After` when a limit is exceeded;
- a browser-only honeypot field;
- a browser-only 2 second minimum form time;
- 3-32 character ASCII usernames containing only letters, digits, `_`, `-` or `.`;
- a reserved username list;
- optional normalized and validated email;
- password length 8-1024, and password must differ from username and email;
- 7 day registration-attempt retention.

The attempt table stores only an HMAC-SHA-256 IP hash, SHA-256 invite hash, timestamp and outcome. Raw invite codes and IP addresses are not written to that table.

`REMOTE_ADDR` is the registration rate-limit source. If the deployment is behind a reverse proxy, configure the web server/proxy so PHP receives the intended client address in `REMOTE_ADDR`; php-light deliberately does not trust arbitrary forwarded-IP headers.

For every unusable invite state, the only public invite-validity response is exactly:

```text
Invite code not valid.
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
