package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/adapters/memory"
	"github.com/klarlabs-studio/auth-go/domain"
)

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

func uid(t *testing.T, s string) domain.UserID {
	t.Helper()
	id, err := domain.NewUserID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func tid(t *testing.T, s string) domain.TenantID {
	t.Helper()
	id, err := domain.NewTenantID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func email(t *testing.T, s string) domain.Email {
	t.Helper()
	e, err := domain.NewEmail(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func mustUser(t *testing.T, id, tenant, addr string, ts time.Time) domain.User {
	t.Helper()
	u, err := domain.NewUser(uid(t, id), tid(t, tenant), email(t, addr), ts, ts)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestUserRepo(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewUserRepo()
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

	if _, err := repo.GetUser(ctx, tid(t, "t1"), uid(t, "u1")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing user: want ErrNotFound, got %v", err)
	}

	u := mustUser(t, "u1", "t1", "a@b.com", now)
	if err := repo.UpsertUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetUser(ctx, tid(t, "t1"), uid(t, "u1"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Email().String() != "a@b.com" || got.TenantID().String() != "t1" {
		t.Fatalf("get mismatch: %+v", got.Snapshot())
	}

	// The lookup is tenant-scoped: the same ID under a different tenant is not
	// resolved across the boundary.
	if _, err := repo.GetUser(ctx, tid(t, "t2"), uid(t, "u1")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-tenant: want ErrNotFound, got %v", err)
	}

	// Upsert updates in place (same ID).
	updated := mustUser(t, "u1", "t1", "c@d.com", now.Add(time.Hour))
	if err := repo.UpsertUser(ctx, updated); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetUser(ctx, tid(t, "t1"), uid(t, "u1"))
	if got.Email().String() != "c@d.com" {
		t.Fatalf("upsert did not update: %+v", got.Snapshot())
	}
}

// hkey returns the at-rest lookup key (SHA-256 hash) for a raw session token.
// Sessions are keyed by the hash, so direct repository lookups/deletes (which
// bypass the service that normally hashes) must hash too.
func hkey(raw domain.Token) domain.Token {
	h, _ := domain.TokenFromString(domain.HashToken(raw))
	return h
}

func TestSessionRepo(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewSessionRepo()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewSessionService(repo, time.Hour, func() time.Time { return now })

	s, err := svc.Issue(ctx, uid(t, "u1"), tid(t, "t1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.FindByToken(ctx, hkey(s.Token()))
	if err != nil || got.UserID().String() != "u1" {
		t.Fatalf("find: %v / %+v", err, got.Snapshot())
	}
	if err := repo.Delete(ctx, hkey(s.Token())); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindByToken(ctx, hkey(s.Token())); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}

	a, _ := svc.Issue(ctx, uid(t, "u2"), tid(t, "t2"))
	b, _ := svc.Issue(ctx, uid(t, "u2"), tid(t, "t2"))
	if err := repo.DeleteByUser(ctx, uid(t, "u2")); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []domain.Token{a.Token(), b.Token()} {
		if _, err := repo.FindByToken(ctx, tok); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal("DeleteByUser missed a session")
		}
	}
}

func TestMagicLinkRepo(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewMagicLinkRepo()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewMagicLinkService(repo, 15*time.Minute, func() time.Time { return now })
	email, _ := domain.NewEmail("a@b.co")

	raw, err := svc.Issue(ctx, email, tid(t, "t1"))
	if err != nil {
		t.Fatal(err)
	}
	link, err := svc.Consume(ctx, raw)
	if err != nil || link.Email().String() != "a@b.co" {
		t.Fatalf("consume: %v / %+v", err, link.Snapshot())
	}
	if ok, err := repo.MarkConsumed(ctx, "does-not-exist"); ok || err != nil {
		t.Fatalf("mark unknown: want (false, nil), got (%v, %v)", ok, err)
	}
}

func TestPasskeyRepo(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewPasskeyRepo()
	u := uid(t, "u1")
	_ = repo.Add(ctx, domain.PasskeyCredential{ID: []byte{1}, UserID: u, Name: "K"})
	got, _ := repo.ListByUser(ctx, u)
	if len(got) != 1 {
		t.Fatalf("list: %+v", got)
	}
	if err := repo.UpdateSignCount(ctx, []byte{1}, 5); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateSignCount(ctx, []byte{9}, 5); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown: want ErrNotFound, got %v", err)
	}
	_ = repo.Delete(ctx, []byte{1})
	final, _ := repo.ListByUser(ctx, u)
	if len(final) != 0 {
		t.Fatal("delete failed")
	}
}

// TestPasskeyRepo_NoAliasing proves the store copies credential byte slices, so
// neither the caller's Add buffer nor a returned ListByUser slice aliases the
// stored credential — mutating either must not corrupt what the store holds.
func TestPasskeyRepo_NoAliasing(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewPasskeyRepo()
	u := uid(t, "u1")

	id := []byte{1, 2, 3}
	pub := []byte{9, 9, 9}
	if err := repo.Add(ctx, domain.PasskeyCredential{ID: id, UserID: u, PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	// Mutating the buffers passed to Add must not reach the stored copy.
	id[0], pub[0] = 0xFF, 0xFF

	got, _ := repo.ListByUser(ctx, u)
	if len(got) != 1 {
		t.Fatalf("list: %+v", got)
	}
	if got[0].ID[0] != 1 || got[0].PublicKey[0] != 9 {
		t.Fatalf("Add aliased caller buffers: %+v", got[0])
	}
	// Mutating a returned slice must not reach the stored copy either.
	got[0].PublicKey[0] = 0x00
	again, _ := repo.ListByUser(ctx, u)
	if again[0].PublicKey[0] != 9 {
		t.Fatalf("ListByUser aliased stored buffer: %+v", again[0])
	}
}

func TestTOTPRepo(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewTOTPRepo()
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
		t.Fatal(err)
	}
	got, err := repo.GetSecret(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != secret.String() {
		t.Fatalf("secret round-trip mismatch: %q vs %q", got.String(), secret.String())
	}

	// SetSecret replaces in place.
	other, _ := domain.NewTOTPSecret()
	if err := repo.SetSecret(ctx, u, other); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetSecret(ctx, u)
	if got.String() != other.String() {
		t.Fatal("SetSecret did not replace")
	}

	if err := repo.DeleteSecret(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetSecret(ctx, u); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestLoginAttemptRepo(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewLoginAttemptRepo()
	key := "k"

	// Unknown key → ErrNotFound.
	if _, err := repo.Get(ctx, key); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown: want ErrNotFound, got %v", err)
	}

	until := time.Date(2026, 6, 8, 12, 15, 0, 0, time.UTC)
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
	if err := repo.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(ctx, key); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestWorkloadKeyRepo_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewWorkloadKeyRepo()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewWorkloadKeyService(repo, func() time.Time { return now })

	w := wid(t, "agent-1")
	key, raw, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  w,
		Scope:     scope(t, "tools:*"),
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	// GetKey by ID.
	got, err := repo.GetKey(ctx, key.ID())
	if err != nil || got.WorkerID().String() != "agent-1" {
		t.Fatalf("get by id: %v / %+v", err, got.Snapshot())
	}
	// GetKeyByHash.
	byHash, err := repo.GetKeyByHash(ctx, domain.HashWorkloadToken(raw))
	if err != nil || byHash.ID() != key.ID() {
		t.Fatalf("get by hash: %v / %+v", err, byHash.Snapshot())
	}
	// Duplicate CreateKey rejected.
	if err := repo.CreateKey(ctx, key); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate create: want ErrConflict, got %v", err)
	}
	// ListKeysByWorker.
	list, err := repo.ListKeysByWorker(ctx, w)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v / %+v", err, list)
	}
	// DeleteKey unknown.
	if err := repo.DeleteKey(ctx, domain.KeyID("missing")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete unknown: want ErrNotFound, got %v", err)
	}
	// DeleteKey existing → hash index also cleared.
	if err := repo.DeleteKey(ctx, key.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetKeyByHash(ctx, domain.HashWorkloadToken(raw)); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("hash index not cleared on delete: %v", err)
	}
}

// TestWorkloadKeyRepo_Concurrency exercises the store under concurrent issue,
// validate, list, and revoke. Run with -race to detect data races.
func TestWorkloadKeyRepo_Concurrency(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewWorkloadKeyRepo()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewWorkloadKeyService(repo, func() time.Time { return now })
	w := wid(t, "agent-1")

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			key, raw, err := svc.IssueKey(ctx, domain.KeyRequest{
				WorkerID:  w,
				Scope:     scope(t, "tools:*"),
				ExpiresAt: now.Add(time.Hour),
			})
			if err != nil {
				t.Errorf("issue: %v", err)
				return
			}
			if _, err := svc.ValidateKey(ctx, raw); err != nil {
				t.Errorf("validate: %v", err)
			}
			if _, err := svc.ListKeys(ctx, w); err != nil {
				t.Errorf("list: %v", err)
			}
			if err := svc.RevokeKey(ctx, key.ID()); err != nil {
				t.Errorf("revoke: %v", err)
			}
		}()
	}
	wg.Wait()

	left, _ := svc.ListKeys(ctx, w)
	if len(left) != 0 {
		t.Fatalf("concurrent issue/revoke left keys: %d", len(left))
	}
}

// TestWorkloadKeyRepo_ConcurrentRotate exercises RotateKey concurrently against
// the in-memory store. RotateKey creates the new key before deleting the old,
// so the two briefly overlap; run with -race to detect data races in the
// store's two-map (byID/byHash) maintenance across that overlap window. After
// all rotations settle, exactly one key must survive and validate.
func TestWorkloadKeyRepo_ConcurrentRotate(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewWorkloadKeyRepo()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewWorkloadKeyService(repo, func() time.Time { return now })
	w := wid(t, "agent-rotate")

	const n = 40
	ids := make([]domain.KeyID, n)
	for i := 0; i < n; i++ {
		key, _, err := svc.IssueKey(ctx, domain.KeyRequest{
			WorkerID:  w,
			Scope:     scope(t, "tools:*"),
			ExpiresAt: now.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = key.ID()
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(id domain.KeyID) {
			defer wg.Done()
			newKey, newRaw, err := svc.RotateKey(ctx, id)
			if err != nil {
				t.Errorf("rotate %s: %v", id, err)
				return
			}
			// The rotated token must validate during/after the overlap window.
			if _, err := svc.ValidateKey(ctx, newRaw); err != nil {
				t.Errorf("validate rotated %s: %v", newKey.ID(), err)
			}
		}(ids[i])
	}
	wg.Wait()

	// Each rotation deletes exactly its old key and leaves its new one, so the
	// worker still has n keys total — no key was lost or duplicated.
	left, err := svc.ListKeys(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != n {
		t.Fatalf("after concurrent rotate: want %d keys, got %d", n, len(left))
	}
}

func TestSessionRepo_RotateAtomically(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewSessionRepo()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewSessionService(repo, time.Hour, func() time.Time { return now })

	old, err := svc.Issue(ctx, uid(t, "u1"), tid(t, "t1"))
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := svc.Rotate(ctx, old.Token())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Validate(ctx, old.Token()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("old survived: %v", err)
	}
	if _, err := svc.Validate(ctx, fresh.Token()); err != nil {
		t.Fatal(err)
	}
	absent, _ := domain.TokenFromString("nope")
	if err := repo.RotateAtomically(ctx, absent, fresh); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("absent: want ErrNotFound, got %v", err)
	}
}

func TestTOTPRepo_ConsumeStep(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewTOTPRepo()
	u := uid(t, "u1")
	fresh, err := repo.ConsumeStep(ctx, u, 100)
	if err != nil || !fresh {
		t.Fatalf("first step: fresh=%v err=%v", fresh, err)
	}
	again, err := repo.ConsumeStep(ctx, u, 100)
	if err != nil || again {
		t.Fatalf("replay: fresh=%v err=%v", again, err)
	}
	next, err := repo.ConsumeStep(ctx, u, 101)
	if err != nil || !next {
		t.Fatalf("advance: fresh=%v err=%v", next, err)
	}
}

func TestLoginAttemptRepo_RecordFailureAtomically(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewLoginAttemptRepo()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	var justLocked bool
	var err error
	for i := 0; i < 5; i++ {
		_, justLocked, err = repo.RecordFailureAtomically(ctx, "k", now, 5, 15*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !justLocked {
		t.Fatal("5th failure should engage the lock")
	}
	snap, _, err := repo.RecordFailureAtomically(ctx, "k", now.Add(time.Hour), 5, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if snap.FailureCount != 1 {
		t.Fatalf("expired lock should reset count, got %d", snap.FailureCount)
	}
}
