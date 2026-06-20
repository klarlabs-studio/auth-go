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

func TestSessionRepo(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewSessionRepo()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewSessionService(repo, time.Hour, func() time.Time { return now })

	s, err := svc.Issue(ctx, uid(t, "u1"), tid(t, "t1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.FindByToken(ctx, s.Token())
	if err != nil || got.UserID().String() != "u1" {
		t.Fatalf("find: %v / %+v", err, got.Snapshot())
	}
	if err := repo.Delete(ctx, s.Token()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindByToken(ctx, s.Token()); !errors.Is(err, domain.ErrNotFound) {
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
	if err := repo.MarkConsumed(ctx, "does-not-exist"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("mark unknown: want ErrNotFound, got %v", err)
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
