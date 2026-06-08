package pgstore_test

import (
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
	for _, tbl := range []string{"authgo_sessions", "authgo_magic_links", "authgo_passkeys"} {
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

func TestSessionRepo_Integration(t *testing.T) {
	db := openTestDB(t)
	repo := pgstore.NewSessionRepo(db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	svc := domain.NewSessionService(repo, time.Hour, func() time.Time { return now })

	s, err := svc.Issue(uid(t, "u1"), tid(t, "t1"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := svc.Validate(s.Token())
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.UserID().String() != "u1" || got.TenantID().String() != "t1" {
		t.Fatalf("roundtrip mismatch: %+v", got.Snapshot())
	}

	// upsert (Save twice) must not error
	if err := repo.Save(s); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if err := svc.RevokeAll(uid(t, "u1")); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindByToken(s.Token()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoke-all: want ErrNotFound, got %v", err)
	}
}

func TestMagicLinkRepo_Integration(t *testing.T) {
	db := openTestDB(t)
	repo := pgstore.NewMagicLinkRepo(db)
	now := time.Now().UTC()
	svc := domain.NewMagicLinkService(repo, 15*time.Minute, func() time.Time { return now })

	email, _ := domain.NewEmail("felix@klarlabs.de")
	raw, err := svc.Issue(email, tid(t, "t1"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	link, err := svc.Consume(raw)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if link.Email().String() != "felix@klarlabs.de" {
		t.Fatalf("email mismatch: %s", link.Email())
	}
	if _, err := svc.Consume(raw); !errors.Is(err, domain.ErrConsumed) {
		t.Fatalf("reuse: want ErrConsumed, got %v", err)
	}
}

func TestPasskeyRepo_Integration(t *testing.T) {
	db := openTestDB(t)
	repo := pgstore.NewPasskeyRepo(db)
	u := uid(t, "u1")

	if err := repo.Add(domain.PasskeyCredential{
		ID: []byte{1, 2, 3}, UserID: u, PublicKey: []byte{9, 9}, Name: "Touch ID",
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, err := repo.ListByUser(u)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].Name != "Touch ID" {
		t.Fatalf("list mismatch: %+v", got)
	}
	if err := repo.UpdateSignCount([]byte{1, 2, 3}, 7); err != nil {
		t.Fatalf("update: %v", err)
	}
	again, _ := repo.ListByUser(u)
	if again[0].SignCount != 7 {
		t.Fatalf("sign count: %d", again[0].SignCount)
	}
	if err := repo.UpdateSignCount([]byte{0}, 1); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown update: want ErrNotFound, got %v", err)
	}
	if err := repo.Delete([]byte{1, 2, 3}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	final, _ := repo.ListByUser(u)
	if len(final) != 0 {
		t.Fatalf("delete left rows: %+v", final)
	}
}
