-- auth-go SQLite schema — the SQLite dialect mirror of pgstore/schema.sql,
-- applied automatically by Migrate (db.go). SQLite is embedded, so unlike the
-- Postgres adapter there is no external migration tool to run; the adapter
-- bootstraps the schema on construction.
--
-- Dialect notes vs. the Postgres schema:
--   * TIMESTAMPTZ → TEXT. Times are stored as RFC3339Nano UTC strings (see
--     adapters/sqlite encode/decode helpers); SQLite has no native timestamp
--     type and string comparison of RFC3339 sorts chronologically.
--   * BYTEA       → BLOB.
--   * TEXT[]      → TEXT. The scope array is stored as a newline-joined list of
--     canonical "resource:action" entries; the value-object constructor has
--     already rejected any entry containing a newline (or other exotic byte).
--   * now()       → handled in Go (the adapter stamps updated_at), so the
--     schema carries no function-valued default.

CREATE TABLE IF NOT EXISTS authgo_users (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    email       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS authgo_users_tenant_idx ON authgo_users (tenant_id);

CREATE TABLE IF NOT EXISTS authgo_sessions (
    token       TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS authgo_sessions_user_idx ON authgo_sessions (user_id);

CREATE TABLE IF NOT EXISTS authgo_magic_links (
    hash        TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    tenant_id   TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0
);

-- Enrolled TOTP secrets, one per user. The base32 secret is a credential;
-- protect this column the way you protect any shared secret.
CREATE TABLE IF NOT EXISTS authgo_totp_secrets (
    user_id     TEXT PRIMARY KEY,
    secret      TEXT NOT NULL
);

-- Last consumed TOTP time step per user, for single-use enforcement (RFC 6238 §5.2).
CREATE TABLE IF NOT EXISTS authgo_totp_used_steps (
    user_id     TEXT    PRIMARY KEY,
    last_step   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS authgo_passkeys (
    id          BLOB PRIMARY KEY,
    user_id     TEXT NOT NULL,
    public_key  BLOB NOT NULL,
    sign_count  INTEGER NOT NULL DEFAULT 0,
    name        TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS authgo_passkeys_user_idx ON authgo_passkeys (user_id);

-- Brute-force lockout counters. `key` is opaque to the library; callers SHOULD
-- store a hash of the email (hex SHA-256) so no plaintext PII is persisted.
CREATE TABLE IF NOT EXISTS authgo_login_attempts (
    key           TEXT PRIMARY KEY,
    failure_count INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT,
    updated_at    TEXT NOT NULL
);

-- Scoped API keys for agent workers. Only the hex SHA-256 hash of each token is
-- stored — the raw token is returned once at issue time and never persisted.
-- `scope` holds the canonical "resource:action" capability entries (wildcards
-- allowed, e.g. tools:*) newline-joined. `hash` is UNIQUE so validation is a
-- single indexed lookup.
CREATE TABLE IF NOT EXISTS authgo_workload_keys (
    id          TEXT PRIMARY KEY,
    hash        TEXT NOT NULL UNIQUE,
    worker_id   TEXT NOT NULL,
    scope       TEXT NOT NULL DEFAULT '',
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS authgo_workload_keys_worker_idx ON authgo_workload_keys (worker_id);
