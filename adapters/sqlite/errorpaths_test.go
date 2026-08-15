package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/adapters/sqlite"
	"github.com/klarlabs-studio/auth-go/domain"
)

// These tests drive the adapter's error-handling branches: I/O failures from
// the underlying database and corrupted timestamp columns. They use the real
// embedded SQLite — by closing the DB before the call (forcing every query to
// fail) and by hand-writing a malformed row, respectively — so no mock is
// needed.

// closedDB returns a SQLite DB whose connection is already closed, so every
// subsequent query returns an error: the cheapest way to drive the
// "ExecContext/QueryContext failed" branches.
func closedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sqlite.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = db.Close()
	return db
}

func TestErrorPaths_ClosedDB(t *testing.T) {
	ctx := context.Background()
	db := closedDB(t)

	users := sqlite.NewUserRepo(db)
	if _, err := users.GetUser(ctx, tid(t), uid(t, "u1")); err == nil {
		t.Fatal("User.GetUser on closed DB must error")
	}
	if err := users.UpsertUser(ctx, domain.User{}); err == nil {
		t.Fatal("User.UpsertUser on closed DB must error")
	}

	session := sqlite.NewSessionRepo(db)
	if err := session.Save(ctx, domain.Session{}); err == nil {
		t.Fatal("Save on closed DB must error")
	}
	if _, err := session.FindByToken(ctx, domain.Token{}); err == nil {
		t.Fatal("FindByToken on closed DB must error")
	}
	if err := session.Delete(ctx, domain.Token{}); err == nil {
		t.Fatal("Delete on closed DB must error")
	}
	if err := session.DeleteByUser(ctx, uid(t, "u1")); err == nil {
		t.Fatal("DeleteByUser on closed DB must error")
	}

	ml := sqlite.NewMagicLinkRepo(db)
	if err := ml.Save(ctx, domain.MagicLink{}); err == nil {
		t.Fatal("MagicLink.Save on closed DB must error")
	}
	if _, err := ml.FindByHash(ctx, "x"); err == nil {
		t.Fatal("MagicLink.FindByHash on closed DB must error")
	}
	if _, err := ml.MarkConsumed(ctx, "x"); err == nil {
		t.Fatal("MarkConsumed on closed DB must error")
	}
	em, _ := domain.NewEmail("a@b.co")
	tn, _ := domain.NewTenantID("t1")
	if err := ml.InvalidateOutstanding(ctx, em, tn); err == nil {
		t.Fatal("InvalidateOutstanding on closed DB must error")
	}

	totp := sqlite.NewPlaintextTOTPRepo(db)
	if _, err := totp.GetSecret(ctx, uid(t, "u1")); err == nil {
		t.Fatal("TOTP.GetSecret on closed DB must error")
	}
	if err := totp.SetSecret(ctx, uid(t, "u1"), domain.TOTPSecret{}); err == nil {
		t.Fatal("TOTP.SetSecret on closed DB must error")
	}
	if err := totp.DeleteSecret(ctx, uid(t, "u1")); err == nil {
		t.Fatal("TOTP.DeleteSecret on closed DB must error")
	}

	pk := sqlite.NewPasskeyRepo(db)
	if err := pk.Add(ctx, domain.PasskeyCredential{ID: []byte{1}, UserID: uid(t, "u1")}); err == nil {
		t.Fatal("Passkey.Add on closed DB must error")
	}
	if _, err := pk.ListByUser(ctx, uid(t, "u1")); err == nil {
		t.Fatal("ListByUser on closed DB must error")
	}
	if err := pk.UpdateSignCount(ctx, []byte{1}, 2); err == nil {
		t.Fatal("UpdateSignCount on closed DB must error")
	}
	if err := pk.Delete(ctx, []byte{1}); err == nil {
		t.Fatal("Passkey.Delete on closed DB must error")
	}

	la := sqlite.NewLoginAttemptRepo(db)
	if _, err := la.Get(ctx, "k"); err == nil {
		t.Fatal("LoginAttempt.Get on closed DB must error")
	}
	if err := la.Save(ctx, domain.LoginAttemptSnapshot{Key: "k"}); err == nil {
		t.Fatal("LoginAttempt.Save on closed DB must error")
	}
	if err := la.Delete(ctx, "k"); err == nil {
		t.Fatal("LoginAttempt.Delete on closed DB must error")
	}

	wk := sqlite.NewWorkloadKeyRepo(db)
	if _, err := wk.GetKey(ctx, domain.KeyID("x")); err == nil {
		t.Fatal("GetKey on closed DB must error")
	}
	if _, err := wk.GetKeyByHash(ctx, "x"); err == nil {
		t.Fatal("GetKeyByHash on closed DB must error")
	}
	if _, err := wk.ListKeysByWorker(ctx, wid(t, "w")); err == nil {
		t.Fatal("ListKeysByWorker on closed DB must error")
	}
	if err := wk.DeleteKey(ctx, domain.KeyID("x")); err == nil {
		t.Fatal("DeleteKey on closed DB must error")
	}
}

// TestErrorPaths_CorruptTimestamps writes rows with an unparseable timestamp
// directly, then proves the read paths surface a decode error rather than
// returning a garbage time.
func TestErrorPaths_CorruptTimestamps(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// User with a corrupt created_at.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO authgo_users (id, tenant_id, email, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`, "u", "t", "a@b.co", "garbage", "garbage"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// Seeded under tenant "t"; the lookup must match it to reach the decode branch.
	tenantT, err := domain.NewTenantID("t")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sqlite.NewUserRepo(db).GetUser(ctx, tenantT, uid(t, "u")); err == nil {
		t.Fatal("GetUser must reject a corrupt created_at")
	}
	// A second user with a valid created_at but a corrupt updated_at exercises
	// the second decode branch.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO authgo_users (id, tenant_id, email, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`, "u2", "t", "a@b.co", time.Now().UTC().Format(time.RFC3339Nano), "garbage"); err != nil {
		t.Fatalf("seed user2: %v", err)
	}
	if _, err := sqlite.NewUserRepo(db).GetUser(ctx, tenantT, uid(t, "u2")); err == nil {
		t.Fatal("GetUser must reject a corrupt updated_at")
	}

	// TOTP secret that is not valid base32 — GetSecret must surface the decode
	// error rather than return a garbage secret.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO authgo_totp_secrets (user_id, secret) VALUES (?, ?)`, "u-totp", "not!base32!"); err != nil {
		t.Fatalf("seed totp: %v", err)
	}
	if _, err := sqlite.NewPlaintextTOTPRepo(db).GetSecret(ctx, uid(t, "u-totp")); err == nil {
		t.Fatal("GetSecret must reject a corrupt secret")
	}

	// Session with a corrupt created_at.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO authgo_sessions (token, user_id, tenant_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`, "tok", "u", "t", "garbage", "garbage"); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	tok, _ := domain.TokenFromString("tok")
	if _, err := sqlite.NewSessionRepo(db).FindByToken(ctx, tok); err == nil {
		t.Fatal("FindByToken must reject a corrupt timestamp")
	}

	// Magic link with a corrupt expires_at.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO authgo_magic_links (hash, email, tenant_id, expires_at, consumed)
		 VALUES (?, ?, ?, ?, 0)`, "h", "a@b.co", "t", "garbage"); err != nil {
		t.Fatalf("seed magic link: %v", err)
	}
	if _, err := sqlite.NewMagicLinkRepo(db).FindByHash(ctx, "h"); err == nil {
		t.Fatal("FindByHash must reject a corrupt timestamp")
	}

	// Login attempt with a corrupt locked_until.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO authgo_login_attempts (key, failure_count, locked_until, updated_at)
		 VALUES (?, ?, ?, ?)`, "k", 1, "garbage", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("seed login attempt: %v", err)
	}
	if _, err := sqlite.NewLoginAttemptRepo(db).Get(ctx, "k"); err == nil {
		t.Fatal("Get must reject a corrupt locked_until")
	}

	// Workload key with a corrupt expires_at.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO authgo_workload_keys (id, hash, worker_id, scope, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`, "id", "hash", "w", "tools:*", "garbage", "garbage"); err != nil {
		t.Fatalf("seed workload key: %v", err)
	}
	wk := sqlite.NewWorkloadKeyRepo(db)
	if _, err := wk.GetKey(ctx, domain.KeyID("id")); err == nil {
		t.Fatal("GetKey must reject a corrupt timestamp")
	}
	if _, err := wk.ListKeysByWorker(ctx, wid(t, "w")); err == nil {
		t.Fatal("ListKeysByWorker must reject a corrupt timestamp")
	}
}
