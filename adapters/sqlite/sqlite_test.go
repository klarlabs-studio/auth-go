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
	if _, err := repo.FindByToken(ctx, hkey(s.Token())); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoke-all: want ErrNotFound, got %v", err)
	}
}

// hkey returns the at-rest lookup key (SHA-256 hash) for a raw session token —
// sessions are keyed by the hash, so direct repository lookups/deletes must hash.
func hkey(raw domain.Token) domain.Token {
	h, _ := domain.TokenFromString(domain.HashToken(raw))
	return h
}

func TestLoginAttemptRepo_RecordFailureAtomically(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewLoginAttemptRepo(db)
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	const window = 15 * time.Minute

	// Four failures: below the 5-failure threshold, not locked; count tracks.
	for i := 1; i <= 4; i++ {
		snap, justLocked, err := repo.RecordFailureAtomically(ctx, "k", now, 5, window)
		if err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
		if justLocked {
			t.Fatalf("locked early at failure %d", i)
		}
		if snap.FailureCount != i {
			t.Fatalf("count = %d, want %d", snap.FailureCount, i)
		}
	}
	// Fifth failure engages the lock.
	snap, justLocked, err := repo.RecordFailureAtomically(ctx, "k", now, 5, window)
	if err != nil {
		t.Fatal(err)
	}
	if !justLocked {
		t.Error("5th failure should engage the lock")
	}
	if snap.LockedUntil.IsZero() {
		t.Error("locked_until not set on the locking failure")
	}
	// After the window expires, the next failure resets the count to 1.
	later := now.Add(20 * time.Minute)
	snap, _, err = repo.RecordFailureAtomically(ctx, "k", later, 5, window)
	if err != nil {
		t.Fatal(err)
	}
	if snap.FailureCount != 1 {
		t.Errorf("expired lock should reset count to 1, got %d", snap.FailureCount)
	}
	if !snap.LockedUntil.IsZero() {
		t.Error("count-below-threshold after reset should clear the lock")
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
	if _, err := repo.FindByToken(ctx, hkey(a.Token())); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("u1 session survived DeleteByUser")
	}
	if _, err := repo.FindByToken(ctx, hkey(b.Token())); err != nil {
		t.Fatalf("DeleteByUser hit another user: %v", err)
	}
	// single Delete
	if err := repo.Delete(ctx, hkey(b.Token())); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindByToken(ctx, hkey(b.Token())); !errors.Is(err, domain.ErrNotFound) {
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
	// MarkConsumed on unknown → (false, nil): nothing to flip, not an error.
	if ok, err := repo.MarkConsumed(ctx, "does-not-exist"); ok || err != nil {
		t.Fatalf("mark unknown: want (false, nil), got (%v, %v)", ok, err)
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

func TestTOTPRepo(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewTOTPRepo(db)
	u := uid(t, "u1")

	if _, err := repo.GetSecret(ctx, u); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing secret: want ErrNotFound, got %v", err)
	}
	if err := repo.DeleteSecret(ctx, u); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete missing: want ErrNotFound, got %v", err)
	}

	secret, err := domain.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetSecret(ctx, u, secret); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := repo.GetSecret(ctx, u)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.String() != secret.String() {
		t.Fatalf("round-trip mismatch: %q vs %q", got.String(), secret.String())
	}

	// SetSecret replaces in place.
	other, _ := domain.NewTOTPSecret()
	if err := repo.SetSecret(ctx, u, other); err != nil {
		t.Fatalf("replace: %v", err)
	}
	got, _ = repo.GetSecret(ctx, u)
	if got.String() != other.String() {
		t.Fatal("SetSecret did not replace")
	}

	if err := repo.DeleteSecret(ctx, u); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetSecret(ctx, u); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
}

// TestTOTPRepo_ConsumeStep exercises the AtomicTOTPConsumer UPSERT directly: a
// step is accepted once, replays (same or older step) are rejected, and only a
// strictly-advancing step is consumed again.
func TestTOTPRepo_ConsumeStep(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewTOTPRepo(db)
	u := uid(t, "u1")

	cases := []struct {
		step int64
		want bool
		desc string
	}{
		{100, true, "first consume"},
		{100, false, "same step replay"},
		{99, false, "older step replay"},
		{101, true, "advancing step"},
		{101, false, "advanced step replay"},
	}
	for _, c := range cases {
		fresh, err := repo.ConsumeStep(ctx, u, c.step)
		if err != nil {
			t.Fatalf("%s: %v", c.desc, err)
		}
		if fresh != c.want {
			t.Fatalf("%s: fresh=%v, want %v", c.desc, fresh, c.want)
		}
	}
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

// TestWorkloadKeyRepo_RotateAtomically proves the single-transaction swap: after
// a successful rotate exactly one key (the new one) exists, an unknown old ID
// yields ErrNotFound and changes nothing, and a hash collision yields
// ErrConflict and rolls the whole swap back (the old key survives).
func TestWorkloadKeyRepo_RotateAtomically(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := sqlite.NewWorkloadKeyRepo(db)
	now := time.Now().UTC().Truncate(time.Second)
	svc := domain.NewWorkloadKeyService(repo, func() time.Time { return now })
	w := wid(t, "agent-rot")

	old, _, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID: w, Scope: scope(t, "tools:read"), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Unknown old ID → ErrNotFound, nothing changes (old still present).
	newSnap := domain.APIKeySnapshot{
		ID: "wk_new", Hash: "newhash", WorkerID: "agent-rot",
		Scope: []string{"tools:read"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if err := repo.RotateAtomically(ctx, domain.KeyID("wk_absent"), domain.APIKeyFromSnapshot(newSnap)); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("rotate unknown: want ErrNotFound, got %v", err)
	}
	if _, err := repo.GetKey(ctx, old.ID()); err != nil {
		t.Fatalf("old key lost after failed rotate: %v", err)
	}

	// Successful atomic swap: old gone, new present, exactly one key.
	if err := repo.RotateAtomically(ctx, old.ID(), domain.APIKeyFromSnapshot(newSnap)); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := repo.GetKey(ctx, old.ID()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("old key survived atomic rotate: %v", err)
	}
	if _, err := repo.GetKey(ctx, domain.KeyID("wk_new")); err != nil {
		t.Fatalf("new key absent after rotate: %v", err)
	}
	list, _ := repo.ListKeysByWorker(ctx, w)
	if len(list) != 1 {
		t.Fatalf("atomic rotate left %d keys, want 1", len(list))
	}

	// Hash collision rolls the whole swap back: insert a second key, then try to
	// rotate it into a key whose hash duplicates the surviving one.
	second, _, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID: w, Scope: scope(t, "tools:read"), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue second: %v", err)
	}
	collide := domain.APIKeySnapshot{
		ID: "wk_collide", Hash: "newhash", WorkerID: "agent-rot", // duplicate hash of wk_new
		Scope: []string{"tools:read"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if err := repo.RotateAtomically(ctx, second.ID(), domain.APIKeyFromSnapshot(collide)); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("rotate collision: want ErrConflict, got %v", err)
	}
	// The swap rolled back: the second key still exists (delete was undone).
	if _, err := repo.GetKey(ctx, second.ID()); err != nil {
		t.Fatalf("second key lost after rolled-back rotate: %v", err)
	}
}

// TestWorkloadKeyRepo_RotateAtomicallyInTx proves the *sql.Tx-composed path:
// when the repo is built over a caller's transaction the swap runs directly
// (no nested transaction) and is atomic within that outer transaction.
func TestWorkloadKeyRepo_RotateAtomicallyInTx(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	svc := domain.NewWorkloadKeyService(sqlite.NewWorkloadKeyRepo(db), func() time.Time { return now })
	w := wid(t, "agent-tx")
	old, _, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID: w, Scope: scope(t, "tools:read"), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	txRepo := sqlite.NewWorkloadKeyRepo(tx)
	newSnap := domain.APIKeySnapshot{
		ID: "wk_txnew", Hash: "txhash", WorkerID: "agent-tx",
		Scope: []string{"tools:read"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if err := txRepo.RotateAtomically(ctx, old.ID(), domain.APIKeyFromSnapshot(newSnap)); err != nil {
		_ = tx.Rollback()
		t.Fatalf("rotate in tx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	repo := sqlite.NewWorkloadKeyRepo(db)
	if _, err := repo.GetKey(ctx, old.ID()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("old key survived tx rotate: %v", err)
	}
	if _, err := repo.GetKey(ctx, domain.KeyID("wk_txnew")); err != nil {
		t.Fatalf("new key absent after tx rotate: %v", err)
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
	// Sessions are keyed at rest by the token hash; look it up the same way.
	hashed, _ := domain.TokenFromString(domain.HashToken(s.Token()))
	if _, err := repo2.FindByToken(ctx, hashed); err != nil {
		t.Fatalf("row lost across reopen: %v", err)
	}
}
