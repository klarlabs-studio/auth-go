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
	repo := memory.NewSessionRepo()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewSessionService(repo, time.Hour, func() time.Time { return now })

	s, err := svc.Issue(uid(t, "u1"), tid(t, "t1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := repo.FindByToken(s.Token())
	if err != nil || got.UserID().String() != "u1" {
		t.Fatalf("find: %v / %+v", err, got.Snapshot())
	}
	if err := repo.Delete(s.Token()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindByToken(s.Token()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}

	a, _ := svc.Issue(uid(t, "u2"), tid(t, "t2"))
	b, _ := svc.Issue(uid(t, "u2"), tid(t, "t2"))
	if err := repo.DeleteByUser(uid(t, "u2")); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []domain.Token{a.Token(), b.Token()} {
		if _, err := repo.FindByToken(tok); !errors.Is(err, domain.ErrNotFound) {
			t.Fatal("DeleteByUser missed a session")
		}
	}
}

func TestMagicLinkRepo(t *testing.T) {
	repo := memory.NewMagicLinkRepo()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewMagicLinkService(repo, 15*time.Minute, func() time.Time { return now })
	email, _ := domain.NewEmail("a@b.co")

	raw, err := svc.Issue(email, tid(t, "t1"))
	if err != nil {
		t.Fatal(err)
	}
	link, err := svc.Consume(raw)
	if err != nil || link.Email().String() != "a@b.co" {
		t.Fatalf("consume: %v / %+v", err, link.Snapshot())
	}
	if err := repo.MarkConsumed("does-not-exist"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("mark unknown: want ErrNotFound, got %v", err)
	}
}

func TestPasskeyRepo(t *testing.T) {
	repo := memory.NewPasskeyRepo()
	u := uid(t, "u1")
	_ = repo.Add(domain.PasskeyCredential{ID: []byte{1}, UserID: u, Name: "K"})
	got, _ := repo.ListByUser(u)
	if len(got) != 1 {
		t.Fatalf("list: %+v", got)
	}
	if err := repo.UpdateSignCount([]byte{1}, 5); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateSignCount([]byte{9}, 5); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown: want ErrNotFound, got %v", err)
	}
	_ = repo.Delete([]byte{1})
	final, _ := repo.ListByUser(u)
	if len(final) != 0 {
		t.Fatal("delete failed")
	}
}

func TestLoginAttemptRepo(t *testing.T) {
	repo := memory.NewLoginAttemptRepo()
	key := "k"

	// Unknown key → ErrNotFound.
	if _, err := repo.Get(key); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown: want ErrNotFound, got %v", err)
	}

	until := time.Date(2026, 6, 8, 12, 15, 0, 0, time.UTC)
	if err := repo.Save(domain.LoginAttemptSnapshot{Key: key, FailureCount: 5, LockedUntil: until}); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailureCount != 5 || !got.LockedUntil.Equal(until) {
		t.Fatalf("roundtrip: %+v", got)
	}
	if err := repo.Delete(key); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(key); !errors.Is(err, domain.ErrNotFound) {
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
