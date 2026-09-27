-- IAM php-light storage
-- Contract: iam.light 1.1
-- Target: MariaDB / MySQL
--
-- IAM owns identity, credentials, invite lifecycle, session state and abuse state.
-- Application domains such as LMTS reference IAM_users; they do not duplicate IAM identity tables.

CREATE TABLE IF NOT EXISTS IAM_users (
    user_id          VARCHAR(128) NOT NULL,
    username         VARCHAR(128) NOT NULL,
    status           VARCHAR(32) NOT NULL DEFAULT 'active',
    verified         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id),
    UNIQUE KEY uq_IAM_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS IdentityCore_profiles (
    user_id       VARCHAR(128) NOT NULL,
    display_name  VARCHAR(255) NULL,
    organization  VARCHAR(255) NULL,
    phone         VARCHAR(64) NULL,
    country       VARCHAR(128) NULL,
    timezone      VARCHAR(128) NULL,
    language      VARCHAR(32) NULL,
    website       VARCHAR(512) NULL,
    created_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id),
    CONSTRAINT fk_IdentityCore_profiles_user
        FOREIGN KEY (user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS IdentityCore_field_visibility (
    user_id       VARCHAR(128) NOT NULL,
    field_name    VARCHAR(64) NOT NULL,
    visibility    VARCHAR(16) NOT NULL DEFAULT 'private',
    updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id, field_name),
    KEY idx_IdentityCore_visibility_public (visibility, field_name),
    CONSTRAINT fk_IdentityCore_visibility_user
        FOREIGN KEY (user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT chk_IdentityCore_visibility
        CHECK (visibility IN ('private','public'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS IAM_user_accounts (
    user_id          VARCHAR(128) NOT NULL,
    password_hash    VARCHAR(255) NOT NULL,
    email            VARCHAR(320) NULL,
    account_status   VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id),
    UNIQUE KEY uq_IAM_user_accounts_email (email),
    CONSTRAINT fk_IAM_user_accounts_user
        FOREIGN KEY (user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS IAM_domains (
    domain_id         VARCHAR(64) NOT NULL,
    display_name      VARCHAR(128) NOT NULL,
    parent_domain_id  VARCHAR(64) NULL,
    status            VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
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
    updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
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
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id, domain_id),
    KEY idx_IAM_management_tiers_domain (domain_id, management_tier, status),
    CONSTRAINT fk_IAM_management_tiers_user
        FOREIGN KEY (user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    CONSTRAINT fk_IAM_management_tiers_domain
        FOREIGN KEY (domain_id) REFERENCES IAM_domains(domain_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT chk_IAM_management_tier CHECK (management_tier IN (1,2,3,1337))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO IAM_domains (domain_id, display_name, parent_domain_id, status)
VALUES
    ('iam', 'IAM', NULL, 'active'),
    ('lmts', 'LMTS', 'iam', 'active')
ON DUPLICATE KEY UPDATE
    display_name = VALUES(display_name),
    parent_domain_id = VALUES(parent_domain_id),
    status = VALUES(status);


CREATE TABLE IF NOT EXISTS IAM_management_audit (
    audit_id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_user_id   VARCHAR(128) NOT NULL,
    target_user_id  VARCHAR(128) NOT NULL,
    domain_id       VARCHAR(64) NOT NULL,
    action          VARCHAR(32) NOT NULL,
    from_tier       SMALLINT UNSIGNED NULL,
    to_tier         SMALLINT UNSIGNED NULL,
    created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (audit_id),
    KEY idx_IAM_management_audit_actor (actor_user_id, created_at),
    KEY idx_IAM_management_audit_target (target_user_id, created_at),
    KEY idx_IAM_management_audit_domain (domain_id, created_at),
    CONSTRAINT fk_IAM_management_audit_actor
        FOREIGN KEY (actor_user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_IAM_management_audit_target
        FOREIGN KEY (target_user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_IAM_management_audit_domain
        FOREIGN KEY (domain_id) REFERENCES IAM_domains(domain_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT chk_IAM_management_audit_from
        CHECK (from_tier IS NULL OR from_tier IN (1,2,3,1337)),
    CONSTRAINT chk_IAM_management_audit_to
        CHECK (to_tier IS NULL OR to_tier IN (1,2,3,1337))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS IAM_invites (
    invite_id            VARCHAR(128) NOT NULL,
    owner_user_id        VARCHAR(128) NOT NULL,
    domain_id            VARCHAR(64) NOT NULL,
    target_email         VARCHAR(320) NOT NULL,
    token_hash           CHAR(64) NOT NULL,
    created_at           DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at           DATETIME(6) NOT NULL,
    status               VARCHAR(32) NOT NULL DEFAULT 'active',
    claimed_by_user_id   VARCHAR(128) NULL,
    claimed_at           DATETIME(6) NULL,
    PRIMARY KEY (invite_id),
    UNIQUE KEY uq_IAM_invites_token_hash (token_hash),
    KEY idx_IAM_invites_owner (owner_user_id),
    KEY idx_IAM_invites_domain (domain_id),
    KEY idx_IAM_invites_claimed_by (claimed_by_user_id),
    CONSTRAINT fk_IAM_invites_owner
        FOREIGN KEY (owner_user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_IAM_invites_domain
        FOREIGN KEY (domain_id) REFERENCES IAM_domains(domain_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_IAM_invites_claimed_by
        FOREIGN KEY (claimed_by_user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


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


CREATE TABLE IF NOT EXISTS IAM_email_change_requests (
    request_id       VARCHAR(128) NOT NULL,
    user_id          VARCHAR(128) NOT NULL,
    pending_email    VARCHAR(320) NOT NULL,
    token_hash       CHAR(64) NOT NULL,
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at       DATETIME(6) NOT NULL,
    consumed_at      DATETIME(6) NULL,
    invalidated_at   DATETIME(6) NULL,
    PRIMARY KEY (request_id),
    UNIQUE KEY uq_IAM_email_change_token_hash (token_hash),
    KEY idx_IAM_email_change_user (user_id, created_at),
    KEY idx_IAM_email_change_pending (pending_email),
    CONSTRAINT fk_IAM_email_change_user
        FOREIGN KEY (user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS IAM_sessions (
    session_id       VARCHAR(128) NOT NULL,
    user_id          VARCHAR(128) NOT NULL,
    token_hash       CHAR(64) NOT NULL,
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at       DATETIME(6) NOT NULL,
    last_seen_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    revoked_at       DATETIME(6) NULL,
    PRIMARY KEY (session_id),
    UNIQUE KEY uq_IAM_sessions_token_hash (token_hash),
    KEY idx_IAM_sessions_user (user_id, created_at),
    KEY idx_IAM_sessions_expiry (expires_at),
    CONSTRAINT fk_IAM_sessions_user
        FOREIGN KEY (user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS IAM_abuse_events (
    event_id          VARCHAR(128) NOT NULL,
    ip_hash           CHAR(64) NOT NULL,
    identifier_hash   CHAR(64) NULL,
    action            VARCHAR(32) NOT NULL,
    outcome           VARCHAR(32) NOT NULL,
    created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (event_id),
    KEY idx_IAM_abuse_ip_action_time (ip_hash, action, created_at),
    KEY idx_IAM_abuse_identifier_action_time (identifier_hash, action, created_at),
    KEY idx_IAM_abuse_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS IAM_ip_blocks (
    ip_hash           CHAR(64) NOT NULL,
    reason            VARCHAR(128) NOT NULL,
    source            VARCHAR(32) NOT NULL,
    created_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at        DATETIME(6) NULL,
    PRIMARY KEY (ip_hash),
    KEY idx_IAM_ip_blocks_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
