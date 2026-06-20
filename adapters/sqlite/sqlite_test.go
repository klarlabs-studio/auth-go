package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/adapters/sqlite"
	"github.com/klarlabs-studio/auth-go/domain"
)

// openTestDB opens a fresh, isolated SQLite database in a temp dir, applies the
// schema, and returns it. SQLite is embedded, so this needs no external
// service — every test gets its own file, auto-removed with the temp dir.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func uid(t *testing.T, s string) domain.UserID {
	t.Helper()
	id, err := domain.NewUserID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// tid returns the fixed test tenant. Every session/magic-link here belongs to
// the same tenant, so the helper hardcodes it rather than threading a constant
// argument through every call site.
func tid(t *testing.T) domain.TenantID {
	t.Helper()
	id, err := domain.NewTenantID("t1")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func wid(t *testing.T, s string) domain.WorkerID {
	t.Helper()
	id, err := domain.NewWorkerID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func scope(t *testing.T, actions ...string) domain.Scope {
	t.Helper()
	sc, err := domain.NewScope(actions...)
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func TestUserRepo(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewUserRepo(db)
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := repo.GetUser(ctx, uid(t, "u1")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing user: want ErrNotFound, got %v", err)
	}

	u, err := domain.NewUser(uid(t, "u1"), tid(t), mustEmail(t), now, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertUser(ctx, u); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := repo.GetUser(ctx, uid(t, "u1"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Email().String() != "a@b.co" || got.TenantID().String() != "t1" {
		t.Fatalf("roundtrip mismatch: %+v", got.Snapshot())
	}
	if !got.CreatedAt().Equal(now) || !got.UpdatedAt().Equal(now) {
		t.Fatalf("timestamps not round-tripped: %+v", got.Snapshot())
	}

	// Upsert updates in place.
	later := now.Add(time.Hour)
	other, err := domain.NewEmail("c@d.co")
	if err != nil {
		t.Fatal(err)
	}
	u2, err := domain.NewUser(uid(t, "u1"), tid(t), other, now, later)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertUser(ctx, u2); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = repo.GetUser(ctx, uid(t, "u1"))
	if got.Email().String() != "c@d.co" || !got.UpdatedAt().Equal(later) {
		t.Fatalf("upsert did not update: %+v", got.Snapshot())
	}
}

func TestSessionRepo(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewSessionRepo(db)
	now := time.Now().UTC().Truncate(time.Second)
	svc := domain.NewSessionService(repo, time.Hour, func() time.Time { return now })

	s, err := svc.Issue(ctx, uid(t, "u1"), tid(t))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := svc.Validate(ctx, s.Token())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.UserID().String() != "u1" || got.TenantID().String() != "t1" {
		t.Fatalf("roundtrip mismatch: %+v", got.Snapshot())
	}
	if !got.ExpiresAt().Equal(now.Add(time.Hour)) {
		t.Fatalf("expiry not round-tripped: got %s want %s", got.ExpiresAt(), now.Add(time.Hour))
	}

	// upsert (Save twice) must not error
	if err := repo.Save(ctx, s); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// unknown token → ErrNotFound
	missing, _ := domain.NewToken()
	if _, err := repo.FindByToken(ctx, missing); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown: want ErrNotFound, got %v", err)
	}

	if err := svc.RevokeAll(ctx, uid(t, "u1")); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindByToken(ctx, s.Token()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoke-all: want ErrNotFound, got %v", err)
	}
}

func TestSessionRepo_DeleteScopedToUser(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewSessionRepo(db)
	now := time.Now().UTC().Truncate(time.Second)
	svc := domain.NewSessionService(repo, time.Hour, func() time.Time { return now })

	a, _ := svc.Issue(ctx, uid(t, "u1"), tid(t))
	b, _ := svc.Issue(ctx, uid(t, "u2"), tid(t))
	if err := repo.DeleteByUser(ctx, uid(t, "u1")); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindByToken(ctx, a.Token()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("u1 session survived DeleteByUser")
	}
	if _, err := repo.FindByToken(ctx, b.Token()); err != nil {
		t.Fatalf("DeleteByUser hit another user: %v", err)
	}
	// single Delete
	if err := repo.Delete(ctx, b.Token()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindByToken(ctx, b.Token()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("Delete did not remove the session")
	}
}

func TestMagicLinkRepo(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewMagicLinkRepo(db)
	now := time.Now().UTC().Truncate(time.Second)
	svc := domain.NewMagicLinkService(repo, 15*time.Minute, func() time.Time { return now })

	email, _ := domain.NewEmail("felix@klarlabs.de")
	raw, err := svc.Issue(ctx, email, tid(t))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	link, err := svc.Consume(ctx, raw)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if link.Email().String() != "felix@klarlabs.de" {
		t.Fatalf("email mismatch: %s", link.Email())
	}
	// single-use
	if _, err := svc.Consume(ctx, raw); !errors.Is(err, domain.ErrConsumed) {
		t.Fatalf("reuse: want ErrConsumed, got %v", err)
	}
	// MarkConsumed on unknown → ErrNotFound
	if err := repo.MarkConsumed(ctx, "does-not-exist"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("mark unknown: want ErrNotFound, got %v", err)
	}
}

func TestMagicLinkRepo_Expiry(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewMagicLinkRepo(db)
	now := time.Now().UTC().Truncate(time.Second)
	svc := domain.NewMagicLinkService(repo, 15*time.Minute, func() time.Time { return now })
	raw, _ := svc.Issue(ctx, mustEmail(t), tid(t))
	now = now.Add(16 * time.Minute)
	if _, err := svc.Consume(ctx, raw); !errors.Is(err, domain.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func mustEmail(t *testing.T) domain.Email {
	t.Helper()
	e, err := domain.NewEmail("a@b.co")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestPasskeyRepo(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewPasskeyRepo(db)
	u := uid(t, "u1")

	if err := repo.Add(ctx, domain.PasskeyCredential{
		ID: []byte{1, 2, 3}, UserID: u, PublicKey: []byte{9, 9}, Name: "Touch ID",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// a credential for a different user must not leak into ListByUser(u)
	if err := repo.Add(ctx, domain.PasskeyCredential{
		ID: []byte{4}, UserID: uid(t, "other"), PublicKey: []byte{1},
	}); err != nil {
		t.Fatalf("add other: %v", err)
	}
	got, err := repo.ListByUser(ctx, u)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Name != "Touch ID" {
		t.Fatalf("list mismatch: %+v", got)
	}
	if err := repo.UpdateSignCount(ctx, []byte{1, 2, 3}, 7); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, _ := repo.ListByUser(ctx, u)
	if again[0].SignCount != 7 {
		t.Fatalf("sign count: %d", again[0].SignCount)
	}
	if err := repo.UpdateSignCount(ctx, []byte{0}, 1); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown update: want ErrNotFound, got %v", err)
	}
	if err := repo.Delete(ctx, []byte{1, 2, 3}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	final, _ := repo.ListByUser(ctx, u)
	if len(final) != 0 {
		t.Fatalf("delete left rows: %+v", final)
	}
}

func TestLoginAttemptRepo(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewLoginAttemptRepo(db)
	key := "k"

	if _, err := repo.Get(ctx, key); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown: want ErrNotFound, got %v", err)
	}

	until := time.Now().UTC().Add(15 * time.Minute).Truncate(time.Second)
	if err := repo.Save(ctx, domain.LoginAttemptSnapshot{Key: key, FailureCount: 5, LockedUntil: until}); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailureCount != 5 || !got.LockedUntil.Equal(until) {
		t.Fatalf("roundtrip: %+v", got)
	}
	// upsert path: Save again with a cleared lock (zero time → NULL)
	if err := repo.Save(ctx, domain.LoginAttemptSnapshot{Key: key, FailureCount: 0}); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.Get(ctx, key)
	if got.FailureCount != 0 || !got.LockedUntil.IsZero() {
		t.Fatalf("upsert cleared state not persisted: %+v", got)
	}
	if err := repo.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(ctx, key); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
}

// TestLockoutService_OverSQLite exercises the full lockout flow against the
// SQLite store to prove the upsert/clear transitions persist correctly.
func TestLockoutService_OverSQLite(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	svc := domain.NewLockoutService(sqlite.NewLoginAttemptRepo(db), domain.DefaultLockoutPolicy(), func() time.Time { return clock })
	key := "felix@klarlabs.de"

	for i := 1; i <= 4; i++ {
		locked, err := svc.RecordFailure(ctx, key)
		if err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
		if locked {
			t.Fatalf("locked too early at %d", i)
		}
	}
	locked, err := svc.RecordFailure(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatal("want locked on 5th failure")
	}
	if l, _ := svc.IsLocked(ctx, key); !l {
		t.Fatal("IsLocked should be true after threshold")
	}
	// Clearing resets the counter.
	if err := svc.Clear(ctx, key); err != nil {
		t.Fatal(err)
	}
	if l, _ := svc.IsLocked(ctx, key); l {
		t.Fatal("IsLocked should be false after Clear")
	}
}

func TestWorkloadKeyRepo(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewWorkloadKeyRepo(db)
	now := time.Now().UTC().Truncate(time.Second)
	svc := domain.NewWorkloadKeyService(repo, func() time.Time { return now })
	w := wid(t, "agent-1")

	key, raw, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  w,
		Scope:     scope(t, "tools:*", "memory:read"),
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Validate + authorize round-trip through SQLite.
	claims, err := svc.ValidateKey(ctx, raw)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.WorkerID.String() != "agent-1" {
		t.Fatalf("worker mismatch: %v", claims.WorkerID)
	}
	if err := svc.Authorize(ctx, raw, "tools:write"); err != nil {
		t.Fatalf("authorize wildcard: %v", err)
	}
	if err := svc.Authorize(ctx, raw, "memory:write"); !errors.Is(err, domain.ErrScopeDenied) {
		t.Fatalf("authorize no-match: want ErrScopeDenied, got %v", err)
	}

	// Scope persisted and rehydrated intact, sorted/canonical.
	got, err := repo.GetKey(ctx, key.ID())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Scope().Actions()) != 2 {
		t.Fatalf("scope lost across sqlite: %+v", got.Scope().Actions())
	}
	// GetKeyByHash hot path.
	byHash, err := repo.GetKeyByHash(ctx, domain.HashWorkloadToken(raw))
	if err != nil || byHash.ID() != key.ID() {
		t.Fatalf("get by hash: %v / %+v", err, byHash.Snapshot())
	}

	// Duplicate hash → ErrConflict.
	if err := repo.CreateKey(ctx, key); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate: want ErrConflict, got %v", err)
	}

	// Rotate: old invalid, new valid.
	newKey, newRaw, err := svc.RotateKey(ctx, key.ID())
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := svc.ValidateKey(ctx, raw); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("old token survived rotate: %v", err)
	}
	if _, err := svc.ValidateKey(ctx, newRaw); err != nil {
		t.Fatalf("new token invalid: %v", err)
	}

	// List, then revoke-all.
	list, err := repo.ListKeysByWorker(ctx, w)
	if err != nil || len(list) != 1 {
		t.Fatalf("list after rotate: %v / %d", err, len(list))
	}
	if err := svc.RevokeAllKeys(ctx, w); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetKey(ctx, newKey.ID()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoke-all missed key: %v", err)
	}

	// Delete unknown → ErrNotFound; GetKeyByHash unknown → ErrNotFound.
	if err := repo.DeleteKey(ctx, domain.KeyID("nope")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete unknown: want ErrNotFound, got %v", err)
	}
	if _, err := repo.GetKeyByHash(ctx, "deadbeef"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get unknown hash: want ErrNotFound, got %v", err)
	}
}

func TestWorkloadKeyRepo_Expiry(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewWorkloadKeyRepo(db)
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	svc := domain.NewWorkloadKeyService(repo, func() time.Time { return clock })

	_, raw, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  wid(t, "agent-2"),
		Scope:     scope(t, "tools:read"),
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	clock = now.Add(2 * time.Hour) // past expiry
	if _, err := svc.ValidateKey(ctx, raw); !errors.Is(err, domain.ErrKeyExpired) {
		t.Fatalf("want ErrKeyExpired, got %v", err)
	}
}

// TestMigrateIdempotent proves Open can run twice over the same file (schema is
// CREATE ... IF NOT EXISTS) without error or data loss.
func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "auth.db")
	db, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	repo := sqlite.NewSessionRepo(db)
	now := time.Now().UTC().Truncate(time.Second)
	svc := domain.NewSessionService(repo, time.Hour, func() time.Time { return now })
	s, err := svc.Issue(ctx, uid(t, "u1"), tid(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	// Re-open the same file; the row must survive and the schema re-apply cleanly.
	db2, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	t.Cleanup(func() { _ = db2.Close() })
	repo2 := sqlite.NewSessionRepo(db2)
	if _, err := repo2.FindByToken(ctx, s.Token()); err != nil {
		t.Fatalf("row lost across reopen: %v", err)
	}
}
