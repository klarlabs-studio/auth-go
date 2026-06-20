// Package sqlite provides SQLite implementations of the auth domain repository
// ports, built on the stdlib database/sql and the pure-Go (cgo-free) driver
// modernc.org/sqlite — the same driver the other Klarlabs services use, so a
// product can vendor one SQLite stack across the stack.
//
// SQLite is embedded: there is no external service to provision and no separate
// migration tool to run. Open applies schema.sql on construction, so the
// returned *sql.DB is ready to back the repositories. The same database also
// works under libSQL, which is wire-compatible.
//
// Every repository method is context-aware (the *Context query verbs), matching
// the domain ports; storage I/O honors cancellation, deadlines, and trace
// propagation through ctx.
package sqlite

import (
	"database/sql"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, registered as "sqlite"
)

//go:embed schema.sql
var schema string

// timeLayout is the canonical on-disk timestamp encoding. SQLite has no native
// timestamp type, so every time column is stored as an RFC3339Nano UTC string —
// lexically sortable and round-trips a time.Time without precision loss.
const timeLayout = time.RFC3339Nano

// Open opens (creating if absent) a SQLite database at path, applies the schema,
// and returns a ready *sql.DB. An in-memory database is available with the
// special path ":memory:" (single connection; see below).
//
// Reliability PRAGMAs ride in the DSN so they apply to every pooled connection,
// not just the first: foreign_keys(1) enforces FK constraints (off by default
// in SQLite), journal_mode(WAL) lets readers and a single writer coexist, and
// busy_timeout(5000) waits up to 5s for the writer lock instead of failing fast
// under short bursts of contention.
func Open(path string) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite: database path is required")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf("sqlite: create database directory: %w", err)
		}
	}
	dsn := path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open database: %w", err)
	}
	if err := Migrate(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// Migrate applies schema.sql to db. It is idempotent (every statement is
// CREATE ... IF NOT EXISTS), so it is safe to call on an existing database and
// is exported for callers that manage their own *sql.DB (e.g. a shared pool or
// a libSQL connection) instead of using Open.
func Migrate(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("sqlite: apply schema: %w", err)
	}
	return nil
}

// encodeTime renders a time.Time as the canonical on-disk string (UTC).
func encodeTime(t time.Time) string {
	return t.UTC().Format(timeLayout)
}

// decodeTime parses an on-disk timestamp string back into a UTC time.Time.
func decodeTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("sqlite: parse timestamp %q: %w", s, err)
	}
	return t.UTC(), nil
}

// nowUTC is the wall clock in UTC. The login-attempt adapter stamps updated_at
// with it; the column is bookkeeping/audit metadata, not a domain invariant
// (the LockoutService owns lock timing through its injected Clock), so a direct
// wall-clock read is correct here.
func nowUTC() time.Time { return time.Now().UTC() }
