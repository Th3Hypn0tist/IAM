# IAM Light Authentication Contract

Status: domain-aware  
Contract: `iam.light`  
Version: `1.1`

## Purpose

IAM light provides the portable authentication boundary:

```text
username + password
        ↓
credential verification
        ↓
opaque revocable session
        ↓
canonical IAM identity
        ↓
domain-scoped IAM user-management claim
```

Authentication is orthogonal to application storage, execution, publication
targets and application authorization.

Application permissions belong to AccessCore, not IAM.

## Identity

A successful IAM light authentication returns a canonical identity:

```json
{
  "id": "usr_...",
  "username": "name",
  "status": "active",
  "verified": true
}
```

The PHP reference implementation additionally exposes the effective IAM
user-management tier for the requested domain:

```json
{
  "claims": {
    "tier": 2
  }
}
```

The tier is not an application permission.

Privilege order:

```text
1337 > 1 > 2 > 3
```

Authority inherits from parent domain to descendants only. A stronger inherited
tier cannot be weakened by a lower child-domain assignment.

## Session

The client receives an opaque bearer token.

Requirements:

- token is generated from cryptographically secure random bytes;
- persistent storage contains only a one-way token hash;
- sessions expire and can be revoked;
- logout revokes the current session;
- passwords are never stored by clients.

Bearer transport:

```http
Authorization: Bearer <opaque-token>
```

Browser implementations may additionally use the same token in a Secure,
HttpOnly, SameSite=Strict cookie.

The reference AIGM.fi deployment uses a site-wide cookie path so the same IAM
session can be used by multiple surfaces on the same host.

## Passwords

For `php-light`:

- PHP `password_hash()` is used;
- Argon2id is preferred when available;
- `password_verify()` performs verification;
- minimum accepted password length is 15 characters;
- maximum accepted password length is 1024 characters;
- no composition rules require uppercase, lowercase, numbers or special characters;
- long passphrases are recommended.

## Login

```http
POST /api/login.php
Content-Type: application/json
```

Request:

```json
{
  "username": "origin",
  "password": "...",
  "domain": "lmts"
}
```

Domain context is mandatory.

Success:

```json
{
  "ok": true,
  "contract": "iam.light",
  "version": "1.1",
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

Invalid credentials return HTTP 401 without revealing whether the username
exists.

## Register

Registration is invitation-only.

Canonical browser entry:

```text
/iam/register?token=<opaque-invite-token>
```

The literal path `register` has no special meaning without a token and is
resolved through the same public username path as any other
`/iam/<username>` request.

Invitation requirements:

- inviter identity is stored;
- target domain is stored;
- destination email is stored;
- invite token is cryptographically random;
- only SHA-256 of the token is stored;
- invite is one-time;
- invite expires after 7 days;
- all unusable invite states return exactly `Invite code not valid.`.

For a new IAM identity:

- invitation email is the canonical IAM email;
- email is not editable during registration;
- possession of the invite proves control of the initial email;
- username is 3-32 ASCII letters, digits, `_`, `-` or `.`;
- reserved usernames are rejected at creation time;
- password length is 15-1024 characters;
- successful registration creates domain membership;
- successful registration claims the invite atomically;
- successful registration issues an authenticated IAM session.

For an existing IAM identity:

- the same invitation can add that identity to another IAM domain;
- the user must authenticate as the IAM account bound to the invite email;
- no second IAM identity is created;
- successful acceptance creates/activates the target-domain membership and
  claims the invite atomically.

## Registration form state

Browser registration uses a server-generated form-state token.

Requirements:

- form-state token is stored only as a hash;
- form state expires after 12 hours;
- form must be at least 2 seconds old before submit;
- expiry does not consume the underlying 7-day invite;
- reopening a still-valid invite creates a new form state;
- honeypot protection is applied;
- no CAPTCHA is required;
- no browser fingerprinting is required.

Three invalid invite-token attempts from one IP trigger an IP block.

## Current identity

```http
GET /api/me.php?domain=lmts
Authorization: Bearer <opaque-token>
```

Domain context is mandatory.

Success returns the same `user`, `claims`, contract and auth-level fields
without issuing a new token.

Missing, expired or revoked sessions return HTTP 401.

## Logout

```http
POST /api/logout.php
Authorization: Bearer <opaque-token>
```

Logout is idempotent. The supplied session is revoked if it exists.

## IdentityCore

IdentityCore profile data is separate from IAM account/authentication data.

The reference implementation currently supports:

- display_name
- organization
- phone
- country
- timezone
- language
- website

Each field has independent `private` or `public` visibility.

`/iam` is the authenticated self-service profile editor.

`/iam/<username>` exposes only the user's public IdentityCore projection.

Unknown usernames return exactly:

```text
User not found
```

## Client modes

IAM does not define an application's local/public execution mode.

A client such as LMTS may authenticate through IAM while retaining its own
runtime target choices.

LMTS registration is not part of `iam.light 1.1`; new identities are created
through the IAM web registration flow.

## Security invariants

- username is the login identifier; email is not;
- passwords and raw bearer tokens are never persisted or returned by unrelated endpoints;
- credential errors do not disclose account existence;
- inactive users or accounts cannot authenticate;
- raw invite tokens are stored only as hashes;
- raw invite tokens are never written to abuse logs;
- invite provenance is retained;
- IAM management tiers are not application permissions;
- user-management inheritance is downward only;
- normal application code cannot assign tier 1337;
- responses containing authentication state use `Cache-Control: no-store`;
- deployment uses HTTPS outside localhost.
