-- IAM php-light storage
-- Contract: iam.light 1.0
-- Target: MariaDB / MySQL
--
-- IAM owns identity, credentials, invite lifecycle, session state and abuse state.
-- Application domains such as LMTS reference IAM_users; they do not duplicate IAM identity tables.

CREATE TABLE IF NOT EXISTS IAM_users (
    user_id          VARCHAR(128) NOT NULL,
    username         VARCHAR(128) NOT NULL,
    display_name     VARCHAR(255) NULL,
    organization     VARCHAR(255) NULL,
    tier             SMALLINT UNSIGNED NOT NULL DEFAULT 3,
    status           VARCHAR(32) NOT NULL DEFAULT 'active',
    verified         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id),
    UNIQUE KEY uq_IAM_users_username (username),
    CONSTRAINT chk_IAM_users_tier CHECK (tier IN (1,2,3,1337))
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

CREATE TABLE IF NOT EXISTS IAM_invites (
    invite_id            VARCHAR(128) NOT NULL,
    owner_user_id        VARCHAR(128) NOT NULL,
    token_hash           CHAR(64) NOT NULL,
    created_at           DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at           DATETIME(6) NULL,
    status               VARCHAR(32) NOT NULL DEFAULT 'active',
    claimed_by_user_id   VARCHAR(128) NULL,
    claimed_at           DATETIME(6) NULL,
    PRIMARY KEY (invite_id),
    UNIQUE KEY uq_IAM_invites_token_hash (token_hash),
    KEY idx_IAM_invites_owner (owner_user_id),
    KEY idx_IAM_invites_claimed_by (claimed_by_user_id),
    CONSTRAINT fk_IAM_invites_owner
        FOREIGN KEY (owner_user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_IAM_invites_claimed_by
        FOREIGN KEY (claimed_by_user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS IAM_tier_progression_requests (
    progression_id                   VARCHAR(128) NOT NULL,
    user_id                          VARCHAR(128) NOT NULL,
    current_tier                     SMALLINT UNSIGNED NOT NULL,
    requested_tier                   SMALLINT UNSIGNED NOT NULL,
    eligibility_status               VARCHAR(32) NOT NULL DEFAULT 'pending',
    eligibility_evidence_json        LONGTEXT NULL,
    approval_required_from_user_id   VARCHAR(128) NULL,
    status                           VARCHAR(32) NOT NULL DEFAULT 'pending',
    created_at                       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    resolved_at                      DATETIME(6) NULL,
    PRIMARY KEY (progression_id),
    KEY idx_IAM_tier_progression_user (user_id),
    KEY idx_IAM_tier_progression_approver (approval_required_from_user_id),
    CONSTRAINT fk_IAM_tier_progression_user
        FOREIGN KEY (user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_IAM_tier_progression_approver
        FOREIGN KEY (approval_required_from_user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT chk_IAM_tier_progression_current CHECK (current_tier IN (1,2,3,1337)),
    CONSTRAINT chk_IAM_tier_progression_requested CHECK (requested_tier IN (1,2,3,1337)),
    CONSTRAINT chk_IAM_tier_progression_evidence CHECK (
        eligibility_evidence_json IS NULL OR JSON_VALID(eligibility_evidence_json)
    )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS IAM_user_tier_history (
    history_id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id              VARCHAR(128) NOT NULL,
    from_tier            SMALLINT UNSIGNED NOT NULL,
    to_tier              SMALLINT UNSIGNED NOT NULL,
    eligible_at          DATETIME(6) NULL,
    approved_by_user_id  VARCHAR(128) NULL,
    approved_at          DATETIME(6) NULL,
    rule_version         VARCHAR(128) NULL,
    reason_json          LONGTEXT NULL,
    created_at           DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (history_id),
    KEY idx_IAM_user_tier_history_user (user_id, created_at),
    CONSTRAINT fk_IAM_user_tier_history_user
        FOREIGN KEY (user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_IAM_user_tier_history_approver
        FOREIGN KEY (approved_by_user_id) REFERENCES IAM_users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT chk_IAM_user_tier_history_from CHECK (from_tier IN (1,2,3,1337)),
    CONSTRAINT chk_IAM_user_tier_history_to CHECK (to_tier IN (1,2,3,1337)),
    CONSTRAINT chk_IAM_user_tier_history_reason CHECK (
        reason_json IS NULL OR JSON_VALID(reason_json)
    )
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
