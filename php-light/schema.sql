-- IAM php-light storage
-- Contract: iam.light 1.0
-- Target: MariaDB / MySQL
--
-- users, user_accounts and invites intentionally retain the current AIGM/LMTS
-- identity shapes so an existing installation can be adopted without changing
-- canonical user ids or invite semantics.

CREATE TABLE IF NOT EXISTS users (
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
    UNIQUE KEY uq_users_username (username),
    CONSTRAINT chk_users_tier CHECK (tier IN (1,2,3,1337))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_accounts (
    user_id          VARCHAR(128) NOT NULL,
    password_hash    VARCHAR(255) NOT NULL,
    email            VARCHAR(320) NULL,
    account_status   VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id),
    UNIQUE KEY uq_user_accounts_email (email),
    CONSTRAINT fk_user_accounts_user
        FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS invites (
    invite_id            VARCHAR(128) NOT NULL,
    owner_user_id        VARCHAR(128) NOT NULL,
    token_hash           VARCHAR(255) NOT NULL,
    created_at           DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at           DATETIME(6) NULL,
    status               VARCHAR(32) NOT NULL DEFAULT 'active',
    claimed_by_user_id   VARCHAR(128) NULL,
    claimed_at           DATETIME(6) NULL,
    PRIMARY KEY (invite_id),
    UNIQUE KEY uq_invites_token_hash (token_hash),
    KEY idx_invites_owner (owner_user_id),
    KEY idx_invites_claimed_by (claimed_by_user_id),
    CONSTRAINT fk_invites_owner
        FOREIGN KEY (owner_user_id) REFERENCES users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT,
    CONSTRAINT fk_invites_claimed_by
        FOREIGN KEY (claimed_by_user_id) REFERENCES users(user_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS iam_sessions (
    session_id       VARCHAR(128) NOT NULL,
    user_id          VARCHAR(128) NOT NULL,
    token_hash       CHAR(64) NOT NULL,
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at       DATETIME(6) NOT NULL,
    last_seen_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    revoked_at       DATETIME(6) NULL,
    PRIMARY KEY (session_id),
    UNIQUE KEY uq_iam_sessions_token_hash (token_hash),
    KEY idx_iam_sessions_user (user_id, created_at),
    KEY idx_iam_sessions_expiry (expires_at),
    CONSTRAINT fk_iam_sessions_user
        FOREIGN KEY (user_id) REFERENCES users(user_id)
        ON UPDATE RESTRICT ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
