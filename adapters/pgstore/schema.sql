-- auth-go Postgres schema. Apply via your product's migration tool.
-- Tables are tenant-aware; combine with Row-Level Security per the Klarlabs
-- product standard (tenant_id derived server-side, never from the client).

CREATE TABLE IF NOT EXISTS authgo_sessions (
    token       TEXT        PRIMARY KEY,
    user_id     TEXT        NOT NULL,
    tenant_id   TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS authgo_sessions_user_idx ON authgo_sessions (user_id);

CREATE TABLE IF NOT EXISTS authgo_magic_links (
    hash        TEXT        PRIMARY KEY,
    email       TEXT        NOT NULL,
    tenant_id   TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed    BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS authgo_passkeys (
    id          BYTEA       PRIMARY KEY,
    user_id     TEXT        NOT NULL,
    public_key  BYTEA       NOT NULL,
    sign_count  BIGINT      NOT NULL DEFAULT 0,
    name        TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS authgo_passkeys_user_idx ON authgo_passkeys (user_id);

-- Brute-force lockout counters. `key` is opaque to the library; callers SHOULD
-- store a hash of the email (hex SHA-256) so no plaintext PII is persisted.
CREATE TABLE IF NOT EXISTS authgo_login_attempts (
    key           TEXT        PRIMARY KEY,
    failure_count INTEGER     NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
