package authgo

import (
	"errors"
	"testing"
	"time"
)

// fixedClock returns a controllable Clock.
func fixedClock(t *time.Time) Clock { return func() time.Time { return *t } }

func TestSessionManager_IssueValidate(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	m := NewSessionManager(NewMemorySessionStore(), time.Hour, fixedClock(&now))

	s, err := m.Issue("user-1", "tenant-1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if s.Token == "" || s.UserID != "user-1" || s.TenantID != "tenant-1" {
		t.Fatalf("unexpected session: %+v", s)
	}

	got, err := m.Validate(s.Token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.UserID != "user-1" {
		t.Fatalf("got user %q", got.UserID)
	}
}

func TestSessionManager_Expiry(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	store := NewMemorySessionStore()
	m := NewSessionManager(store, time.Hour, fixedClock(&now))
	s, _ := m.Issue("u", "t")

	now = now.Add(2 * time.Hour)
	if _, err := m.Validate(s.Token); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	// expired session deleted as side effect
	if _, err := store.Get(s.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want session purged, got %v", err)
	}
}

func TestSessionManager_RevokeAndRevokeAll(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	m := NewSessionManager(NewMemorySessionStore(), time.Hour, fixedClock(&now))
	s1, _ := m.Issue("u", "t")
	s2, _ := m.Issue("u", "t")
	other, _ := m.Issue("other", "t")

	if err := m.Revoke(s1.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(s1.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked session still valid: %v", err)
	}

	if err := m.RevokeAll("u"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(s2.Token); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoke-all missed a session")
	}
	if _, err := m.Validate(other.Token); err != nil {
		t.Fatalf("revoke-all hit another user: %v", err)
	}
}

func TestPassword_HashVerify(t *testing.T) {
	p := DefaultArgon2idParams()
	hash, err := HashPassword("correct horse battery staple", p)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := VerifyPassword("correct horse battery staple", hash); err != nil {
		t.Fatalf("verify good password: %v", err)
	}
	if err := VerifyPassword("wrong", hash); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("want mismatch, got %v", err)
	}
}

func TestPassword_SaltUniqueness(t *testing.T) {
	p := DefaultArgon2idParams()
	h1, _ := HashPassword("same", p)
	h2, _ := HashPassword("same", p)
	if h1 == h2 {
		t.Fatal("identical hashes — salt not random")
	}
}

func TestPassword_BadFormat(t *testing.T) {
	if err := VerifyPassword("x", "not-a-phc-string"); err == nil {
		t.Fatal("want error on malformed hash")
	}
}

func TestTOTP_GenerateValidateRoundTrip(t *testing.T) {
	cfg := DefaultTOTPConfig("Klarlabs")
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	code, err := cfg.Generate(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("want 6 digits, got %q", code)
	}
	if err := cfg.Validate(secret, code, at); err != nil {
		t.Fatalf("validate same step: %v", err)
	}
}

func TestTOTP_RFC6238Vector(t *testing.T) {
	// RFC 6238 Appendix B test vector: secret "12345678901234567890" (ASCII)
	// → base32, at T=59s the SHA1 8-digit code is 94287082; 6-digit = 287082.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cfg := TOTPConfig{Period: 30, Digits: 6, Skew: 0}
	at := time.Unix(59, 0).UTC()
	code, err := cfg.Generate(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Fatalf("RFC6238 vector: want 287082, got %s", code)
	}
}

func TestTOTP_Skew(t *testing.T) {
	cfg := DefaultTOTPConfig("Klarlabs") // skew 1
	secret, _ := NewTOTPSecret()
	at := time.Date(2026, 6, 8, 12, 0, 30, 0, time.UTC)
	prev := at.Add(-30 * time.Second)
	code, _ := cfg.Generate(secret, prev)
	if err := cfg.Validate(secret, code, at); err != nil {
		t.Fatalf("code from previous step should pass with skew=1: %v", err)
	}
	// two steps back must fail
	old, _ := cfg.Generate(secret, at.Add(-90*time.Second))
	if err := cfg.Validate(secret, old, at); !errors.Is(err, ErrInvalidTOTP) {
		t.Fatalf("want invalid beyond skew, got %v", err)
	}
}

func TestTOTP_ProvisioningURI(t *testing.T) {
	cfg := DefaultTOTPConfig("Klarlabs")
	uri := cfg.ProvisioningURI("SECRET123", "felix@klarlabs.de")
	for _, want := range []string{"otpauth://totp/", "secret=SECRET123", "issuer=Klarlabs"} {
		if !contains(uri, want) {
			t.Fatalf("URI %q missing %q", uri, want)
		}
	}
}

func TestMagicLink_IssueConsume(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	store := NewMemoryMagicLinkStore()
	m := NewMagicLinkManager(store, 15*time.Minute, fixedClock(&now))

	raw, err := m.Issue("felix@klarlabs.de", "t1")
	if err != nil {
		t.Fatal(err)
	}
	// raw token must not be the storage key
	if _, err := store.Get(raw); !errors.Is(err, ErrNotFound) {
		t.Fatal("raw token used as storage key — should be hashed")
	}

	ml, err := m.Consume(raw)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if ml.Email != "felix@klarlabs.de" || ml.TenantID != "t1" {
		t.Fatalf("unexpected link: %+v", ml)
	}
}

func TestMagicLink_SingleUse(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	m := NewMagicLinkManager(NewMemoryMagicLinkStore(), 15*time.Minute, fixedClock(&now))
	raw, _ := m.Issue("a@b.c", "t")
	if _, err := m.Consume(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Consume(raw); !errors.Is(err, ErrConsumed) {
		t.Fatalf("want ErrConsumed on reuse, got %v", err)
	}
}

func TestMagicLink_Expiry(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	m := NewMagicLinkManager(NewMemoryMagicLinkStore(), 15*time.Minute, fixedClock(&now))
	raw, _ := m.Issue("a@b.c", "t")
	now = now.Add(16 * time.Minute)
	if _, err := m.Consume(raw); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestMagicLink_UnknownToken(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	m := NewMagicLinkManager(NewMemoryMagicLinkStore(), 15*time.Minute, fixedClock(&now))
	if _, err := m.Consume("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestMemoryPasskeyStore(t *testing.T) {
	s := NewMemoryPasskeyStore()
	c := PasskeyCredential{ID: []byte{1, 2, 3}, UserID: "u1", PublicKey: []byte{9}, SignCount: 0, Name: "Key"}
	if err := s.Add(c); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(PasskeyCredential{ID: []byte{4}, UserID: "other"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListByUser("u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "Key" {
		t.Fatalf("listbyuser: %+v", got)
	}
	if err := s.UpdateSignCount([]byte{1, 2, 3}, 42); err != nil {
		t.Fatal(err)
	}
	again, _ := s.ListByUser("u1")
	if again[0].SignCount != 42 {
		t.Fatalf("sign count not updated: %d", again[0].SignCount)
	}
	if err := s.UpdateSignCount([]byte{0}, 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.Delete([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	final, _ := s.ListByUser("u1")
	if len(final) != 0 {
		t.Fatalf("delete failed: %+v", final)
	}
}
