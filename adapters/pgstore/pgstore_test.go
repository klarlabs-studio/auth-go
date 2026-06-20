package pgstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/klarlabs-studio/auth-go/adapters/pgstore"
	"github.com/klarlabs-studio/auth-go/domain"
)

// openTestDB connects to TEST_DATABASE_URL, applies the schema, and returns a
// clean DB. Skips the suite if the env var is unset.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping Postgres integration tests")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
	for _, tbl := range []string{"authgo_users", "authgo_sessions", "authgo_magic_links", "authgo_totp_secrets", "authgo_passkeys", "authgo_login_attempts", "authgo_workload_keys"} {
		if _, err := db.Exec("TRUNCATE " + tbl); err != nil {
			t.Fatalf("truncate %s: %v", tbl, err)
		}
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

func tid(t *testing.T, s string) domain.TenantID {
	t.Helper()
	id, err := domain.NewTenantID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestUserRepo_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := pgstore.NewUserRepo(db)
	now := time.Now().UTC().Truncate(time.Microsecond)

	if _, err := repo.GetUser(ctx, uid(t, "user-pg")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing user: want ErrNotFound, got %v", err)
	}

	email, _ := domain.NewEmail("felix@klarlabs.de")
	u, err := domain.NewUser(uid(t, "user-pg"), tid(t, "tenant-pg"), email, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertUser(ctx, u); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := repo.GetUser(ctx, uid(t, "user-pg"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Email().String() != "felix@klarlabs.de" || got.TenantID().String() != "tenant-pg" {
		t.Fatalf("roundtrip mismatch: %+v", got.Snapshot())
	}

	// Upsert updates in place.
	later := now.Add(time.Hour)
	other, _ := domain.NewEmail("new@klarlabs.de")
	u2, _ := domain.NewUser(uid(t, "user-pg"), tid(t, "tenant-pg"), other, now, later)
	if err := repo.UpsertUser(ctx, u2); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = repo.GetUser(ctx, uid(t, "user-pg"))
	if got.Email().String() != "new@klarlabs.de" || !got.UpdatedAt().Equal(later) {
		t.Fatalf("upsert did not update: %+v", got.Snapshot())
	}
}

func TestSessionRepo_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := pgstore.NewSessionRepo(db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	svc := domain.NewSessionService(repo, time.Hour, func() time.Time { return now })

	s, err := svc.Issue(ctx, uid(t, "u1"), tid(t, "t1"))
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

	// upsert (Save twice) must not error
	if err := repo.Save(ctx, s); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := svc.RevokeAll(ctx, uid(t, "u1")); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindByToken(ctx, s.Token()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoke-all: want ErrNotFound, got %v", err)
	}
}

func TestMagicLinkRepo_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := pgstore.NewMagicLinkRepo(db)
	now := time.Now().UTC()
	svc := domain.NewMagicLinkService(repo, 15*time.Minute, func() time.Time { return now })

	email, _ := domain.NewEmail("felix@klarlabs.de")
	raw, err := svc.Issue(ctx, email, tid(t, "t1"))
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
	if _, err := svc.Consume(ctx, raw); !errors.Is(err, domain.ErrConsumed) {
		t.Fatalf("reuse: want ErrConsumed, got %v", err)
	}
}

func TestTOTPRepo_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := pgstore.NewTOTPRepo(db)
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

func TestPasskeyRepo_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := pgstore.NewPasskeyRepo(db)
	u := uid(t, "u1")

	if err := repo.Add(ctx, domain.PasskeyCredential{
		ID: []byte{1, 2, 3}, UserID: u, PublicKey: []byte{9, 9}, Name: "Touch ID",
	}); err != nil {
		t.Fatalf("add: %v", err)
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

func TestWorkloadKeyRepo_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := pgstore.NewWorkloadKeyRepo(db)
	now := time.Now().UTC().Truncate(time.Microsecond)
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

	// Validate + authorize round-trip through Postgres.
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

	// Scope persisted and rehydrated intact.
	got, err := repo.GetKey(ctx, key.ID())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Scope().Actions()) != 2 {
		t.Fatalf("scope lost across pg: %+v", got.Scope().Actions())
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

	// Delete unknown → ErrNotFound.
	if err := repo.DeleteKey(ctx, domain.KeyID("nope")); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete unknown: want ErrNotFound, got %v", err)
	}
}

// TestWorkloadKeyRepo_RotateAtomically_Integration proves the single-transaction
// swap over real Postgres: a successful rotate leaves exactly one key, an
// unknown old ID yields ErrNotFound and changes nothing, and a hash collision
// yields ErrConflict and rolls the swap back so the old key survives.
func TestWorkloadKeyRepo_RotateAtomically_Integration(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	repo := pgstore.NewWorkloadKeyRepo(db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	svc := domain.NewWorkloadKeyService(repo, func() time.Time { return now })
	w, _ := domain.NewWorkerID("agent-rot")
	sc, _ := domain.NewScope("tools:read")

	old, _, err := svc.IssueKey(ctx, domain.KeyRequest{WorkerID: w, Scope: sc, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	newSnap := domain.APIKeySnapshot{
		ID: "wk_new", Hash: "newhash", WorkerID: "agent-rot",
		Scope: []string{"tools:read"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	// Unknown old → ErrNotFound, nothing changes.
	if err := repo.RotateAtomically(ctx, domain.KeyID("wk_absent"), domain.APIKeyFromSnapshot(newSnap)); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("rotate unknown: want ErrNotFound, got %v", err)
	}
	if _, err := repo.GetKey(ctx, old.ID()); err != nil {
		t.Fatalf("old key lost after failed rotate: %v", err)
	}

	// Successful atomic swap.
	if err := repo.RotateAtomically(ctx, old.ID(), domain.APIKeyFromSnapshot(newSnap)); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := repo.GetKey(ctx, old.ID()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("old key survived atomic rotate: %v", err)
	}
	list, _ := repo.ListKeysByWorker(ctx, w)
	if len(list) != 1 {
		t.Fatalf("atomic rotate left %d keys, want 1", len(list))
	}

	// Hash collision rolls back: the second key survives.
	second, _, err := svc.IssueKey(ctx, domain.KeyRequest{WorkerID: w, Scope: sc, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatalf("issue second: %v", err)
	}
	collide := domain.APIKeySnapshot{
		ID: "wk_collide", Hash: "newhash", WorkerID: "agent-rot",
		Scope: []string{"tools:read"}, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	if err := repo.RotateAtomically(ctx, second.ID(), domain.APIKeyFromSnapshot(collide)); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("rotate collision: want ErrConflict, got %v", err)
	}
	if _, err := repo.GetKey(ctx, second.ID()); err != nil {
		t.Fatalf("second key lost after rolled-back rotate: %v", err)
	}
}
