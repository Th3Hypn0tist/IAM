# IAM php-light

Dependency-free PHP implementation of `iam.light 1.1`.

## Canonical deployment

```text
https://aigm.fi/iam
```

IAM is now designed around a fresh canonical database. Before the first public
release, `schema.sql` is the source of truth and no migration compatibility
layer is maintained.

## Core boundaries

IAM owns:

- authentication;
- username and canonical email;
- sessions;
- invites and invite provenance;
- domain membership;
- domain hierarchy;
- domain-scoped user-management tiers.

IdentityCore owns profile metadata and field visibility.

AccessCore owns application permissions.

IAM management tiers MUST NOT be used as application authorization.

## Domain management tiers

Privilege order:

```text
1337 > 1 > 2 > 3
```

Semantics:

- `3`: normal user, no delegated user-management authority;
- `2`: may invite users into the domain;
- `1`: may invite and manage users in the domain;
- `1337`: AAA user management for the domain and descendants.

Inheritance travels down the domain tree only.

A stronger inherited tier always overrides a weaker local tier.

Tier `1337` is readable by the runtime but is not assignable through normal
application code. During the current bootstrap phase it can only be inserted
directly in the database.

## Seed domains

`schema.sql` currently creates:

```text
iam
└── lmts
```

IAM is the root/master domain.

## Authentication

Login uses username + password.

Email is not a login identifier.

Password policy:

- minimum 15 characters;
- maximum 1024 characters;
- no uppercase/lowercase/number/special-character composition rules;
- long passphrases are recommended;
- four unrelated words is the recommended starting model.

The IAM session cookie is site-wide on `aigm.fi` by default:

```php
'cookie_path' => '/',
```

It remains Secure + HttpOnly + SameSite=Strict.

## Domain context

Domain context is mandatory for domain-aware IAM identity responses.

Login:

```http
POST /iam/api/login.php
Content-Type: application/json

{
  "username": "TheHypnotist",
  "password": "...",
  "domain": "lmts"
}
```

Session restore:

```text
GET /iam/api/me.php?domain=lmts
```

The response shape remains compatible:

```json
{
  "user": {
    "id": "usr_...",
    "username": "TheHypnotist",
    "status": "active",
    "verified": true
  },
  "claims": {
    "tier": 2
  }
}
```

The returned `claims.tier` is the effective IAM user-management tier for the
requested domain. Clients must not calculate inheritance themselves.

## Registration

Registration is invitation-only.

Canonical browser entry:

```text
/iam/register?token=<opaque-invite-token>
```

The path word `register` has no special meaning without a token. Therefore:

```text
/iam/register
```

is processed through the same public username lookup path as any other
`/iam/<username>` request.

Invitation rules:

- inviter is stored permanently;
- target domain is stored;
- destination email is stored;
- token is random and stored only as SHA-256;
- token is one-time;
- invite TTL is 7 days;
- initial email is verified through possession of the email-bound invitation.

Registration form state:

- generated server-side;
- TTL 12 hours;
- minimum age 2 seconds;
- expiry does not consume the invite;
- user can reopen the invitation while the invite remains valid.

Anti-abuse:

- honeypot;
- HMAC-hashed IP tracking;
- invite-hash tracking;
- rate limiting;
- three invalid invite-token attempts from one IP trigger an IP block;
- no CAPTCHA;
- no browser fingerprinting.

Every unusable invitation state returns:

```text
Invite code not valid.
```

## IAM web surface

`/iam`

- no session: reusable system-wide IAM Login View;
- valid session: IdentityCore self-service profile editor.

`/iam/<username>`

- exact username lookup;
- existing user: public IdentityCore projection;
- missing user: `User not found`.

There is no reserved-word runtime branch. Reserved usernames are rejected only
when a username is created.

## IdentityCore

Current canonical profile fields:

- display_name
- organization
- phone
- country
- timezone
- language
- website

Each field has independent `private` or `public` visibility.

The `/iam` self-service editor changes only IdentityCore profile information.

## Deploy

1. Copy `config.example.php` to `config.php`.
2. Configure database credentials.
3. Configure `abuse_hmac_secret` with at least 32 random bytes.
4. Create a fresh database from `schema.sql`.
5. Seed/bootstrap the required initial IAM user directly in the database.
6. Assign bootstrap management tiers directly in the database where required.
7. Use HTTPS.
8. Ensure PHP has PDO and PDO_MYSQL.
9. Ensure Apache rewrite support is enabled for `php-light/.htaccess`.

No Composer packages are required.

## LMTS

LMTS is a client of IAM, not an IAM implementation.

LMTS must use canonical domain context:

```text
lmts
```

LMTS registration is removed. New identities are created through the IAM web
registration flow.

LMTS does not interpret IAM tiers as LMTS application permissions.

Static report-publish authentication remains a separate later change.
