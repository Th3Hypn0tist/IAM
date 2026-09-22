# IAM Light Authentication Contract

Status: baseline  
Contract: `iam.light`  
Version: `1.0`

## Purpose

IAM light provides the minimum portable authentication boundary:

```text
username + password
        ↓
credential verification
        ↓
opaque revocable session
        ↓
canonical user identity
```

Authentication is orthogonal to application storage, execution and publication targets.

## Identity

A successful IAM light authentication returns a canonical identity:

```json
{
  "id": "usr_...",
  "username": "name",
  "status": "active",
  "verified": false
}
```

An implementation may return application claims separately from identity. The PHP reference implementation currently exposes the existing numeric `tier` value as a claim for LMTS compatibility:

```json
{
  "claims": {
    "tier": 3
  }
}
```

Clients must not treat claims as proof of authentication. Identity and claims are separate concepts.

## Session

The client receives an opaque bearer token.

Requirements:

- token is generated from cryptographically secure random bytes;
- the plaintext token is returned only to the client;
- persistent storage contains only a one-way token hash;
- sessions have an expiry;
- sessions can be revoked;
- logout revokes the current session;
- passwords are never stored by clients.

Bearer transport:

```http
Authorization: Bearer <opaque-token>
```

Browser implementations may additionally use an HttpOnly secure cookie carrying the same opaque token.

## Passwords

Passwords are implementation-owned credential material.

For `php-light`:

- passwords are hashed using PHP `password_hash()`;
- Argon2id is preferred when available;
- `password_verify()` performs verification;
- minimum accepted password length is 8 characters;
- maximum accepted password length is 1024 characters.

Legacy credential formats are not silently accepted or converted.

## Login

```http
POST /api/login.php
Content-Type: application/json
```

Request:

```json
{
  "username": "origin",
  "password": "..."
}
```

Success:

```json
{
  "ok": true,
  "contract": "iam.light",
  "version": "1.0",
  "auth_level": "light",
  "token": "<opaque-token>",
  "expires_at": "2026-10-22T18:00:00Z",
  "user": {
    "id": "0",
    "username": "origin",
    "status": "active",
    "verified": true
  },
  "claims": {
    "tier": 1337
  }
}
```

Invalid credentials return HTTP 401 without revealing whether the username exists.

## Register

Registration is invite-only.

```http
POST /api/register.php
Content-Type: application/json
```

Request:

```json
{
  "invite_code": "<raw invite code>",
  "username": "new-user",
  "password": "...",
  "email": "optional@example.com"
}
```

Requirements:

- invite code must exist, be active, unclaimed and unexpired;
- invite lookup uses SHA-256 of the raw invite code;
- every unusable invite state returns exactly `Invite code not valid.`;
- username is 3-32 characters and limited to ASCII letters, digits, `_`, `-` and `.`;
- username uniqueness is case-insensitive;
- reserved usernames cannot be registered;
- email is optional; when present it is normalized, validated, length-limited and unique;
- password must not equal username or email;
- normal registration cannot allocate Origin identity `user_id = "0"`;
- successful registration claims the invite atomically;
- successful registration returns an authenticated light session.

The php-light reference implementation applies registration abuse controls before expensive credential hashing. These controls include IP- and invite-hash rate limits plus browser-only honeypot and minimum-form-time checks. Registration attempt storage must never contain a raw invite code.

## Current identity

```http
GET /api/me.php
Authorization: Bearer <opaque-token>
```

Success returns the same `user`, `claims`, contract and auth-level fields without issuing a new token.

Missing, expired or revoked sessions return HTTP 401.

## Logout

```http
POST /api/logout.php
Authorization: Bearer <opaque-token>
```

Logout is idempotent. The supplied session is revoked if it exists.

## Client modes

IAM does not define application startup modes. A client such as LMTS may expose:

```text
Login
Register
Local
```

`Local` means IAM identity is absent. It does **not** disable the client's local database or alter its output/report targets.

## Security invariants

- no password is returned by any endpoint;
- no endpoint logs plaintext passwords or bearer tokens;
- credential errors do not disclose account existence;
- inactive users or accounts cannot authenticate;
- token hashes are compared by lookup of SHA-256 digests;
- raw invite codes are never written to registration-attempt logs;
- server responses containing authentication state are `Cache-Control: no-store`;
- deployment must use HTTPS outside localhost.
