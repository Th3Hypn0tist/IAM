# IAM

Portable Identity and Access Management contracts and implementations for the AIGM ecosystem.

IAM defines authentication semantics independently from any one runtime. Implementations live under runtime-specific directories and must satisfy the contracts under `contract/`.

## Implementations

- `php-light/` — dependency-free PHP implementation of IAM **light** authentication.

## Light authentication

IAM light proves a username/password identity and issues a revocable opaque session token.

It does **not** decide where application data is stored or published. For example, an LMTS user may authenticate through IAM while still using any LMTS report target combination (Local, Public, or both).

Current reference deployment:

```text
https://aigm.fi/iam
```

LMTS is the first reference client.
