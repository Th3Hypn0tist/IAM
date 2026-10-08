# IAM

Identity and authentication authority for the AIGM ecosystem.

## Canonical responsibility split

```text
IAM        = who
AccessCore = authority / may
DWH        = where / what relates to what
WebEngine  = execute the declared web structure
WebGUI     = generic UI primitives
S3D        = spatial / 3D primitives
```

IAM answers one canonical question:

```text
Who is this subject?
```

IAM owns identity, authentication and session semantics. It does not decide whether an authenticated subject may perform an application action.

## Boundary

```text
IAM
 ↓ identity context
WebEngine / services
 ↓ subject
AccessCore
 ↓ allow | deny
protected operation
```

IAM does not own:

- application authorization policy;
- DWH structural/resource resolution;
- website composition;
- UI primitives;
- spatial/3D primitives;
- domain business behavior.

`managementTier` and other IAM administrative claims remain IAM user-management metadata. They must not be translated by WebEngine or another consumer into application permissions.

## Implementations

- `php-light/` — dependency-free PHP implementation of IAM light authentication.

IAM light proves a username/password identity and issues a revocable opaque session token.

It does not decide where application data is stored or published. DWH owns structural/resource resolution and AccessCore owns authorization.

## Canonical deployment direction

```text
/app/iam/   implementation/domain root
/iam/       public projection
```

The existing deployment may remain in place during migration until the parallel `/app/iam/` candidate is proven.

See `Contracts/` for machine-readable boundaries and `DEPLOY.md` for the current deployment procedure.
