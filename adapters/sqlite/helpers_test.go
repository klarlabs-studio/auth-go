package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/domain"
)

// loginSnap is a minimal non-locked login-attempt snapshot for write smoke
// tests.
func loginSnap() domain.LoginAttemptSnapshot {
	return domain.LoginAttemptSnapshot{Key: "k", FailureCount: 1}
}

// These white-box tests cover the adapter's encoding helpers and Open's
// validation directly, exercising the pure logic (and a couple of error paths)
// that the port-level integration tests don't reach.

func TestEncodeDecodeTime_RoundTrip(t *testing.T) {
	want := time.Date(2026, 6, 20, 14, 30, 15, 123456789, time.UTC)
	got, err := decodeTime(encodeTime(want))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("round-trip mismatch: got %s want %s", got, want)
	}
	// A non-UTC input is normalized to UTC on encode.
	loc := time.FixedZone("CEST", 2*60*60)
	local := want.In(loc)
	got2, err := decodeTime(encodeTime(local))
	if err != nil {
		t.Fatalf("decode local: %v", err)
	}
	if !got2.Equal(want) {
		t.Fatalf("tz normalization failed: got %s want %s", got2, want)
	}
}

func TestDecodeTime_Invalid(t *testing.T) {
	if _, err := decodeTime("not-a-timestamp"); err == nil {
		t.Fatal("want error for malformed timestamp")
	}
}

func TestBoolToInt(t *testing.T) {
	if boolToInt(true) != 1 {
		t.Fatal("true must encode to 1")
	}
	if boolToInt(false) != 0 {
		t.Fatal("false must encode to 0")
	}
}

func TestEncodeDecodeScope(t *testing.T) {
	entries := []string{"tools:*", "memory:read"}
	got := decodeScope(encodeScope(entries))
	if len(got) != 2 || got[0] != "tools:*" || got[1] != "memory:read" {
		t.Fatalf("scope round-trip: %+v", got)
	}
	// Empty scope encodes to "" and decodes to nil.
	if encodeScope(nil) != "" {
		t.Fatal("empty scope must encode to empty string")
	}
	if decodeScope("") != nil {
		t.Fatal("empty string must decode to nil scope")
	}
}

func TestIsUniqueViolation_Nil(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Fatal("nil error is not a unique violation")
	}
	if isUniqueViolation(errors.New("some other error")) {
		t.Fatal("unrelated error is not a unique violation")
	}
	if !isUniqueViolation(errors.New("UNIQUE constraint failed: authgo_workload_keys.hash")) {
		t.Fatal("text fallback must detect a UNIQUE constraint failure")
	}
}

func TestOpen_RequiresPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("empty path must error")
	}
}

func TestOpen_InMemory(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open :memory:: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Schema applied: a port write/read round-trips.
	repo := NewLoginAttemptRepo(db)
	if err := repo.Save(context.Background(), loginSnap()); err != nil {
		t.Fatalf("save into :memory: db: %v", err)
	}
}
