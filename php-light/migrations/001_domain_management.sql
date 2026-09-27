-- IAM MVP -> domain-scoped user-management migration
-- Apply together with the matching iam-domain-management application version.
-- No compatibility fallback to IAM_users.tier remains after this migration.

START TRANSACTION;

CREATE TABLE IF NOT EXISTS IAM_domains (
    domain_id         VARCHAR(64) NOT NULL,
    display_name      VARCHAR(128) NOT NULL,
    parent_domain_id  VARCHAR(64) NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (domain_id),
    KEY idx_IAM_domains_parent (parent_domain_id),
    CONSTRAINT fk_IAM_domains_parent
        FOREIGN KEY (parent_domain_id) REFERENCES IAM_domains(domain_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS IAM_domain_memberships (
    user_id       VARCHAR(128) NOT NULL,
    domain_id     VARCHAR(64) NOT NULL,
    status        VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id, domain_id),
    KEY idx_IAM_domain_memberships_domain (domain_id, status),
    CONSTRAINT fk_IAM_domain_memberships_user
        FOREIGN KEY (user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_IAM_domain_memberships_domain
        FOREIGN KEY (domain_id) REFERENCES IAM_domains(domain_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS IAM_management_tiers (
    user_id          VARCHAR(128) NOT NULL,
    domain_id        VARCHAR(64) NOT NULL,
    management_tier SMALLINT UNSIGNED NOT NULL DEFAULT 3,
    status           VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id, domain_id),
    KEY idx_IAM_management_tiers_domain (domain_id, management_tier, status),
    CONSTRAINT fk_IAM_management_tiers_user
        FOREIGN KEY (user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_IAM_management_tiers_domain
        FOREIGN KEY (domain_id) REFERENCES IAM_domains(domain_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT chk_IAM_management_tier
        CHECK (management_tier IN (1,2,3,1337))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO IAM_domains (domain_id, display_name, parent_domain_id, status)
VALUES
    ('iam', 'IAM', NULL, 'active'),
    ('lmts', 'LMTS', 'iam', 'active')
ON DUPLICATE KEY UPDATE
    display_name = VALUES(display_name),
    parent_domain_id = VALUES(parent_domain_id),
    status = VALUES(status);

-- Every existing IAM identity belongs to the IAM root.
INSERT INTO IAM_domain_memberships (user_id, domain_id, status)
SELECT user_id, 'iam', 'active'
FROM IAM_users
ON DUPLICATE KEY UPDATE status = VALUES(status);

-- Existing MVP global tiers become explicit root-domain management tiers.
-- Because IAM is the root, these values continue to apply to LMTS through
-- downward inheritance.
INSERT INTO IAM_management_tiers (
    user_id,
    domain_id,
    management_tier,
    status
)
SELECT
    user_id,
    'iam',
    tier,
    'active'
FROM IAM_users
WHERE tier IN (1,2,3,1337)
ON DUPLICATE KEY UPDATE
    management_tier = VALUES(management_tier),
    status = VALUES(status);

ALTER TABLE IAM_invites
    ADD COLUMN domain_id VARCHAR(64) NULL AFTER owner_user_id,
    ADD COLUMN target_email VARCHAR(320) NULL AFTER domain_id;

UPDATE IAM_invites
SET domain_id = 'iam'
WHERE domain_id IS NULL;

ALTER TABLE IAM_invites
    ADD KEY idx_IAM_invites_domain (domain_id),
    ADD CONSTRAINT fk_IAM_invites_domain
        FOREIGN KEY (domain_id) REFERENCES IAM_domains(domain_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT;

-- Existing invites predate email-bound registration. They are intentionally
-- left with target_email = NULL and must not be treated as new-contract
-- email-bound invites.


CREATE TABLE IF NOT EXISTS IAM_registration_forms (
    form_id        VARCHAR(128) NOT NULL,
    invite_id      VARCHAR(128) NOT NULL,
    token_hash     CHAR(64) NOT NULL,
    created_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at     DATETIME(6) NOT NULL,
    consumed_at    DATETIME(6) NULL,
    PRIMARY KEY (form_id),
    UNIQUE KEY uq_IAM_registration_forms_token_hash (token_hash),
    KEY idx_IAM_registration_forms_invite (invite_id, expires_at),
    CONSTRAINT fk_IAM_registration_forms_invite
        FOREIGN KEY (invite_id) REFERENCES IAM_invites(invite_id)
        ON UPDATE RESTRICT ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Old global tier workflow tables are obsolete under domain-scoped management.
DROP TABLE IF EXISTS IAM_user_tier_history;
DROP TABLE IF EXISTS IAM_tier_progression_requests;

ALTER TABLE IAM_users
    DROP CONSTRAINT chk_IAM_users_tier;

ALTER TABLE IAM_users
    DROP COLUMN tier;

COMMIT;
