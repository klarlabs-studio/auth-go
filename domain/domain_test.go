package domain_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/adapters/memory"
	"github.com/klarlabs-studio/auth-go/domain"
)

func TestMagicLinkService_ConsumeIsSingleUseUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	repo := memory.NewMagicLinkRepo()
	svc := domain.NewMagicLinkService(repo, 15*time.Minute, fixedClock(&now))

	raw, err := svc.Issue(ctx, mustEmail(t, "a@b.co"), mustTenantID(t, "t1"))
	if err != nil {
		t.Fatal(err)
	}

	// Many requests redeem the same link at once; exactly one may win — the link
	// is a passwordless login factor and must be strictly single-use.
	const n = 16
	var wg sync.WaitGroup
	var success, consumed int32
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			switch _, err := svc.Consume(ctx, raw); {
			case err == nil:
				atomic.AddInt32(&success, 1)
			case errors.Is(err, domain.ErrConsumed):
				atomic.AddInt32(&consumed, 1)
			default:
				t.Errorf("unexpected consume error: %v", err)
			}
		}()
	}
	wg.Wait()

	if success != 1 {
		t.Errorf("single-use violated: %d concurrent consumes succeeded, want exactly 1", success)
	}
	if consumed != n-1 {
		t.Errorf("want %d ErrConsumed, got %d", n-1, consumed)
	}
}

func fixedClock(t *time.Time) domain.Clock { return func() time.Time { return *t } }

func mustUserID(t *testing.T, s string) domain.UserID {
	t.Helper()
	id, err := domain.NewUserID(s)
	if err != nil {
		t.Fatalf("NewUserID(%q): %v", s, err)
	}
	return id
}

func mustTenantID(t *testing.T, s string) domain.TenantID {
	t.Helper()
	id, err := domain.NewTenantID(s)
	if err != nil {
		t.Fatalf("NewTenantID(%q): %v", s, err)
	}
	return id
}

func mustEmail(t *testing.T, s string) domain.Email {
	t.Helper()
	e, err := domain.NewEmail(s)
	if err != nil {
		t.Fatalf("NewEmail(%q): %v", s, err)
	}
	return e
}

// ── Value objects ───────────────────────────────────────────

func TestUserID_Validation(t *testing.T) {
	if _, err := domain.NewUserID(""); !errors.Is(err, domain.ErrInvalidUserID) {
		t.Fatalf("empty: want ErrInvalidUserID, got %v", err)
	}
	if _, err := domain.NewUserID("  "); !errors.Is(err, domain.ErrInvalidUserID) {
		t.Fatalf("blank: want ErrInvalidUserID, got %v", err)
	}
	id := mustUserID(t, "u1")
	if id.String() != "u1" || id.IsZero() {
		t.Fatalf("unexpected: %+v", id)
	}
}

func TestEmail_Normalization(t *testing.T) {
	e := mustEmail(t, "  Felix@Klarlabs.DE ")
	if e.String() != "felix@klarlabs.de" {
		t.Fatalf("normalize: got %q", e.String())
	}
	for _, bad := range []string{"", "no-at", "a@b", "@b.c", "a@"} {
		if _, err := domain.NewEmail(bad); !errors.Is(err, domain.ErrInvalidEmail) {
			t.Fatalf("NewEmail(%q): want ErrInvalidEmail, got %v", bad, err)
		}
	}
}

func TestToken_Random(t *testing.T) {
	a, _ := domain.NewToken()
	b, _ := domain.NewToken()
	if a.String() == b.String() || a.String() == "" {
		t.Fatal("tokens not random/non-empty")
	}
	if _, err := domain.TokenFromString(""); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("empty token: want ErrInvalidToken, got %v", err)
	}
}

// TestValueObject_LengthBounds asserts every constructor caps its input: a
// value at the documented limit is accepted, one past it is rejected. Guards
// against an unbounded email/token/id being hashed or stored (a cheap DoS).
func TestValueObject_LengthBounds(t *testing.T) {
	// UserID / TenantID: 255-char cap.
	if _, err := domain.NewUserID(strings.Repeat("a", 255)); err != nil {
		t.Fatalf("UserID at 255: %v", err)
	}
	if _, err := domain.NewUserID(strings.Repeat("a", 256)); !errors.Is(err, domain.ErrInvalidUserID) {
		t.Fatalf("UserID at 256: want ErrInvalidUserID, got %v", err)
	}
	if _, err := domain.NewTenantID(strings.Repeat("a", 256)); !errors.Is(err, domain.ErrInvalidTenantID) {
		t.Fatalf("TenantID at 256: want ErrInvalidTenantID, got %v", err)
	}

	// Email: 254-char cap (RFC 5321). Build valid addresses at and past it.
	atLimit := strings.Repeat("a", 249) + "@b.co" // 249 + 1 + 4 = 254
	if _, err := domain.NewEmail(atLimit); err != nil {
		t.Fatalf("Email at 254: %v", err)
	}
	overLimit := strings.Repeat("a", 250) + "@b.co" // 255
	if _, err := domain.NewEmail(overLimit); !errors.Is(err, domain.ErrInvalidEmail) {
		t.Fatalf("Email at 255: want ErrInvalidEmail, got %v", err)
	}

	// Token: 4096-char cap.
	if _, err := domain.TokenFromString(strings.Repeat("t", 4096)); err != nil {
		t.Fatalf("Token at 4096: %v", err)
	}
	if _, err := domain.TokenFromString(strings.Repeat("t", 4097)); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("Token at 4097: want ErrInvalidToken, got %v", err)
	}
}

// ── Password ────────────────────────────────────────────────

func TestPasswordHash_VerifyAndFormat(t *testing.T) {
	h, err := domain.HashPassword("correct horse battery staple", domain.DefaultArgon2idParams())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify("correct horse battery staple"); err != nil {
		t.Fatalf("verify good: %v", err)
	}
	if err := h.Verify("wrong"); !errors.Is(err, domain.ErrPasswordMismatch) {
		t.Fatalf("verify bad: want mismatch, got %v", err)
	}
	// rehydrate
	rt, err := domain.PasswordHashFromString(h.String())
	if err != nil {
		t.Fatalf("rehydrate: %v", err)
	}
	if err := rt.Verify("correct horse battery staple"); err != nil {
		t.Fatalf("rehydrated verify: %v", err)
	}
	if _, err := domain.PasswordHashFromString("garbage"); !errors.Is(err, domain.ErrInvalidHash) {
		t.Fatalf("bad format: want ErrInvalidHash, got %v", err)
	}
}

func TestPasswordHash_SaltUniqueness(t *testing.T) {
	p := domain.DefaultArgon2idParams()
	h1, _ := domain.HashPassword("same", p)
	h2, _ := domain.HashPassword("same", p)
	if h1.String() == h2.String() {
		t.Fatal("salt not random")
	}
}

// ── User ────────────────────────────────────────────────────

func TestUser_ValidationAndAccessors(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	id := mustUserID(t, "u1")
	tn := mustTenantID(t, "t1")
	em := mustEmail(t, "felix@klarlabs.de")

	u, err := domain.NewUser(id, tn, em, now, now)
	if err != nil {
		t.Fatalf("NewUser: %v", err)
	}
	if u.ID() != id || u.TenantID() != tn || u.Email().String() != "felix@klarlabs.de" {
		t.Fatalf("accessors mismatch: %+v", u)
	}
	if !u.CreatedAt().Equal(now) || !u.UpdatedAt().Equal(now) {
		t.Fatalf("timestamps mismatch: %+v", u)
	}
	if u.IsZero() {
		t.Fatal("constructed user reports zero")
	}
	if !(domain.User{}).IsZero() {
		t.Fatal("zero user must report zero")
	}

	// Identity fields are required.
	if _, err := domain.NewUser(domain.UserID{}, tn, em, now, now); !errors.Is(err, domain.ErrInvalidUserID) {
		t.Fatalf("zero id: want ErrInvalidUserID, got %v", err)
	}
	if _, err := domain.NewUser(id, domain.TenantID{}, em, now, now); !errors.Is(err, domain.ErrInvalidTenantID) {
		t.Fatalf("zero tenant: want ErrInvalidTenantID, got %v", err)
	}
	if _, err := domain.NewUser(id, tn, domain.Email{}, now, now); !errors.Is(err, domain.ErrInvalidEmail) {
		t.Fatalf("zero email: want ErrInvalidEmail, got %v", err)
	}
}

func TestUser_SnapshotRoundTrip(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	u, err := domain.NewUser(mustUserID(t, "u1"), mustTenantID(t, "t1"), mustEmail(t, "a@b.com"), now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	snap := u.Snapshot()
	if snap.ID != "u1" || snap.TenantID != "t1" || snap.Email != "a@b.com" {
		t.Fatalf("snapshot fields: %+v", snap)
	}
	got := domain.UserFromSnapshot(snap)
	if got.ID() != u.ID() || got.TenantID() != u.TenantID() || got.Email().String() != u.Email().String() {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, u)
	}
	if !got.CreatedAt().Equal(now) || !got.UpdatedAt().Equal(now.Add(time.Hour)) {
		t.Fatalf("round-trip timestamps: %+v", got)
	}
}

// ── TOTP ────────────────────────────────────────────────────

func TestTOTP_RFC6238Vector(t *testing.T) {
	secret, err := domain.TOTPSecretFromString("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	if err != nil {
		t.Fatal(err)
	}
	cfg := domain.TOTPConfig{Period: 30, Digits: 6, Skew: 0}
	code, err := cfg.Generate(secret, time.Unix(59, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if code != "287082" {
		t.Fatalf("RFC6238 vector: want 287082, got %s", code)
	}
}

func TestTOTP_RoundTripAndSkew(t *testing.T) {
	cfg := domain.DefaultTOTPConfig("Klarlabs")
	secret, _ := domain.NewTOTPSecret()
	at := time.Date(2026, 6, 8, 12, 0, 30, 0, time.UTC)
	code, _ := cfg.Generate(secret, at)
	if err := cfg.Validate(secret, code, at); err != nil {
		t.Fatalf("same step: %v", err)
	}
	prev, _ := cfg.Generate(secret, at.Add(-30*time.Second))
	if err := cfg.Validate(secret, prev, at); err != nil {
		t.Fatalf("prev step with skew=1: %v", err)
	}
	old, _ := cfg.Generate(secret, at.Add(-90*time.Second))
	if err := cfg.Validate(secret, old, at); !errors.Is(err, domain.ErrInvalidTOTP) {
		t.Fatalf("beyond skew: want ErrInvalidTOTP, got %v", err)
	}
}

func TestTOTP_SecretValidationAndURI(t *testing.T) {
	if _, err := domain.TOTPSecretFromString("1"); !errors.Is(err, domain.ErrInvalidSecret) {
		t.Fatalf("bad secret: want ErrInvalidSecret, got %v", err)
	}
	cfg := domain.DefaultTOTPConfig("Klarlabs")
	secret, _ := domain.NewTOTPSecret()
	uri := cfg.ProvisioningURI(secret, "felix@klarlabs.de")
	for _, want := range []string{"otpauth://totp/", "issuer=Klarlabs", "secret="} {
		if !strings.Contains(uri, want) {
			t.Fatalf("URI %q missing %q", uri, want)
		}
	}
}

func TestTOTPService_Verify(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 30, 0, time.UTC)
	repo := memory.NewTOTPRepo()
	cfg := domain.DefaultTOTPConfig("Klarlabs")
	uid := mustUserID(t, "u1")

	secret, _ := domain.NewTOTPSecret()
	if err := repo.SetSecret(ctx, uid, secret); err != nil {
		t.Fatal(err)
	}
	code, _ := cfg.Generate(secret, now)
	svc, err := domain.NewTOTPService(repo, cfg, fixedClock(&now))
	if err != nil {
		t.Fatal(err)
	}

	// First use of a valid code succeeds.
	if err := svc.Verify(ctx, uid, code); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// Replaying the same code within its window is rejected (RFC 6238 §5.2).
	if err := svc.Verify(ctx, uid, code); !errors.Is(err, domain.ErrTOTPReused) {
		t.Fatalf("replay: want ErrTOTPReused, got %v", err)
	}
	// A wrong code is ErrInvalidTOTP, not ErrTOTPReused.
	if err := svc.Verify(ctx, uid, "000000"); !errors.Is(err, domain.ErrInvalidTOTP) {
		t.Fatalf("wrong code: want ErrInvalidTOTP, got %v", err)
	}
	// An unenrolled user is ErrNotFound.
	if err := svc.Verify(ctx, mustUserID(t, "u2"), code); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unenrolled: want ErrNotFound, got %v", err)
	}

	// A fresh code from the next step is still accepted after the earlier one
	// was consumed — consumption gates on the step, not the whole secret.
	later := now.Add(30 * time.Second)
	next, _ := cfg.Generate(secret, later)
	svcLater, err := domain.NewTOTPService(repo, cfg, fixedClock(&later))
	if err != nil {
		t.Fatal(err)
	}
	if err := svcLater.Verify(ctx, uid, next); err != nil {
		t.Fatalf("next step: %v", err)
	}
}

func TestTOTPService_ConsumeIsSingleUseUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 30, 0, time.UTC)
	repo := memory.NewTOTPRepo()
	cfg := domain.DefaultTOTPConfig("Klarlabs")
	uid := mustUserID(t, "u1")

	secret, _ := domain.NewTOTPSecret()
	if err := repo.SetSecret(ctx, uid, secret); err != nil {
		t.Fatal(err)
	}
	code, _ := cfg.Generate(secret, now)
	svc, err := domain.NewTOTPService(repo, cfg, fixedClock(&now))
	if err != nil {
		t.Fatal(err)
	}

	const n = 20
	var wg sync.WaitGroup
	var ok, reused int64
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			switch err := svc.Verify(ctx, uid, code); {
			case err == nil:
				atomic.AddInt64(&ok, 1)
			case errors.Is(err, domain.ErrTOTPReused):
				atomic.AddInt64(&reused, 1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	if ok != 1 {
		t.Fatalf("exactly one Verify should succeed, got %d", ok)
	}
	if reused != n-1 {
		t.Fatalf("the other %d should be ErrTOTPReused, got %d", n-1, reused)
	}
}

// ── Session service ─────────────────────────────────────────

func TestSessionService_Lifecycle(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	repo := memory.NewSessionRepo()
	svc := domain.NewSessionService(repo, time.Hour, fixedClock(&now))

	s, err := svc.Issue(ctx, mustUserID(t, "u1"), mustTenantID(t, "t1"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if s.UserID().String() != "u1" || s.TenantID().String() != "t1" {
		t.Fatalf("unexpected session: %+v", s.Snapshot())
	}
	got, err := svc.Validate(ctx, s.Token())
	if err != nil || got.UserID().String() != "u1" {
		t.Fatalf("validate: %v / %+v", err, got.Snapshot())
	}
	// Validated sessions do not carry the raw cookie value.
	if got.Token().String() != "" {
		t.Fatal("Validate must not expose the raw cookie on Session.Token()")
	}

	// expiry purges
	now = now.Add(2 * time.Hour)
	if _, err := svc.Validate(ctx, s.Token()); !errors.Is(err, domain.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
	hashed, _ := domain.TokenFromString(domain.HashToken(s.Token()))
	if _, err := repo.FindByToken(ctx, hashed); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expired not purged: %v", err)
	}
}

func TestSessionService_RevokeAll(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewSessionService(memory.NewSessionRepo(), time.Hour, fixedClock(&now))
	u := mustUserID(t, "u")
	tn := mustTenantID(t, "t")
	s1, _ := svc.Issue(ctx, u, tn)
	s2, _ := svc.Issue(ctx, u, tn)
	other, _ := svc.Issue(ctx, mustUserID(t, "other"), tn)

	if err := svc.RevokeAll(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Validate(ctx, s1.Token()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("s1 survived revoke-all")
	}
	if _, err := svc.Validate(ctx, s2.Token()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("s2 survived revoke-all")
	}
	if _, err := svc.Validate(ctx, other.Token()); err != nil {
		t.Fatalf("revoke-all hit another user: %v", err)
	}
}

func TestSessionService_Rotate(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	repo := memory.NewSessionRepo()
	svc := domain.NewSessionService(repo, time.Hour, fixedClock(&now))

	old, err := svc.Issue(ctx, mustUserID(t, "u1"), mustTenantID(t, "t1"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Advance the clock so a fresh expiry window is observable.
	now = now.Add(10 * time.Minute)
	fresh, err := svc.Rotate(ctx, old.Token())
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// New token differs from the old one.
	if fresh.Token().String() == old.Token().String() {
		t.Fatal("rotate reused the session token")
	}
	// New session preserves the principal and tenant.
	if fresh.UserID().String() != "u1" || fresh.TenantID().String() != "t1" {
		t.Fatalf("rotate lost identity: %+v", fresh.Snapshot())
	}
	// New session carries a fresh full lifetime from the rotation instant
	// (session fixation: the lifetime restarts, it does not inherit the old one).
	if !fresh.ExpiresAt().Equal(now.Add(time.Hour)) {
		t.Fatalf("rotate did not reset lifetime: got %s want %s", fresh.ExpiresAt(), now.Add(time.Hour))
	}

	// Old token is invalidated.
	if _, err := svc.Validate(ctx, old.Token()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("old token survived rotate: %v", err)
	}
	// New token validates.
	if _, err := svc.Validate(ctx, fresh.Token()); err != nil {
		t.Fatalf("new token invalid: %v", err)
	}

	// Rotating an unknown token returns ErrNotFound and issues nothing.
	unknown, _ := domain.TokenFromString("does-not-exist")
	if _, err := svc.Rotate(ctx, unknown); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("rotate unknown: want ErrNotFound, got %v", err)
	}

	// Rotating an expired token returns ErrExpired and issues nothing.
	stale, _ := svc.Issue(ctx, mustUserID(t, "u9"), mustTenantID(t, "t1"))
	now = now.Add(2 * time.Hour)
	if _, err := svc.Rotate(ctx, stale.Token()); !errors.Is(err, domain.ErrExpired) {
		t.Fatalf("rotate expired: want ErrExpired, got %v", err)
	}
}

// failSessionRepo wraps a SessionRepository and forces Delete to fail for a
// specific token, to drive the Rotate rollback branch.
type failSessionRepo struct {
	domain.SessionRepository
	failToken string
	deleteErr error
}

func (f *failSessionRepo) Delete(ctx context.Context, token domain.Token) error {
	if f.deleteErr != nil && token.String() == f.failToken {
		return f.deleteErr
	}
	return f.SessionRepository.Delete(ctx, token)
}

func TestLockoutService_RecordFailureIsAtomicUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	store := memory.NewLoginAttemptRepo()
	policy, err := domain.NewLockoutPolicy(5, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	svc := domain.NewLockoutService(store, policy, fixedClock(&now))

	// 20 concurrent failures for one key: the non-atomic Get→Save path loses most
	// increments (all read the same count), so the account never locks. The
	// atomic path must count every one.
	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() { defer wg.Done(); _, _ = svc.RecordFailure(ctx, "user@x.co") }()
	}
	wg.Wait()

	locked, err := svc.IsLocked(ctx, "user@x.co")
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Error("20 concurrent failures must lock a 5-failure account — increments were lost")
	}
	snap, err := store.Get(ctx, "user@x.co")
	if err != nil {
		t.Fatal(err)
	}
	if snap.FailureCount != n {
		t.Errorf("failure count = %d, want %d (no lost increments)", snap.FailureCount, n)
	}
}

func TestSessionService_TokenHashedAtRest(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	repo := memory.NewSessionRepo()
	svc := domain.NewSessionService(repo, time.Hour, fixedClock(&now))

	sess, err := svc.Issue(ctx, mustUserID(t, "u1"), mustTenantID(t, "t1"))
	if err != nil {
		t.Fatal(err)
	}
	raw := sess.Token()

	// The issued cookie value is the raw high-entropy token, not its hash.
	if raw.String() == "" || raw.String() == domain.HashToken(raw) {
		t.Fatal("issued token must be the raw value")
	}
	// At rest the session is keyed by the hash: the raw token must NOT resolve
	// directly at the store (a leaked store must not hand out usable cookies)...
	if _, err := repo.FindByToken(ctx, raw); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("raw token resolved at the store — session not hashed at rest (err=%v)", err)
	}
	// ...but the hash does, and the service still validates by the raw cookie.
	hashed, _ := domain.TokenFromString(domain.HashToken(raw))
	if _, err := repo.FindByToken(ctx, hashed); err != nil {
		t.Errorf("hashed key should resolve the session, got %v", err)
	}
	got, err := svc.Validate(ctx, raw)
	if err != nil {
		t.Errorf("Validate by the raw cookie token must succeed, got %v", err)
	}
	// Hydrated Token() is empty — Revoke(sess.Token()) must not silently no-op.
	if got.Token().String() != "" {
		t.Fatal("validated Session.Token() must be empty")
	}
	if err := svc.Revoke(ctx, got.Token()); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("Revoke(validated Token()): want ErrInvalidToken, got %v", err)
	}
	// Revoking the raw cookie still works.
	if err := svc.Revoke(ctx, raw); err != nil {
		t.Fatalf("Revoke(raw): %v", err)
	}
	if _, err := svc.Validate(ctx, raw); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("session survived Revoke(raw): %v", err)
	}
}

func TestTOTPService_RequiresAtomicConsumer(t *testing.T) {
	// A TOTPRepository that does not implement AtomicTOTPConsumer must fail at
	// construction — silent replayable success is no longer allowed.
	type bareRepo struct{ domain.TOTPRepository }
	_, err := domain.NewTOTPService(bareRepo{memory.NewTOTPRepo()}, domain.DefaultTOTPConfig("x"), nil)
	if !errors.Is(err, domain.ErrTOTPNoReplayProtection) {
		t.Fatalf("want ErrTOTPNoReplayProtection, got %v", err)
	}
}

func TestPasswordHash_RejectsOverlongAndEmpty(t *testing.T) {
	p := domain.DefaultArgon2idParams()
	if _, err := domain.HashPassword("", p); !errors.Is(err, domain.ErrInvalidPassword) {
		t.Fatalf("empty: want ErrInvalidPassword, got %v", err)
	}
	if _, err := domain.HashPassword(strings.Repeat("x", 1025), p); !errors.Is(err, domain.ErrInvalidPassword) {
		t.Fatalf("overlong: want ErrInvalidPassword, got %v", err)
	}
	h, err := domain.HashPassword("ok", p)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Verify(strings.Repeat("x", 1025)); !errors.Is(err, domain.ErrInvalidPassword) {
		t.Fatalf("verify overlong: want ErrInvalidPassword, got %v", err)
	}
	bad := domain.Argon2idParams{}
	if _, err := domain.HashPassword("ok", bad); !errors.Is(err, domain.ErrInvalidArgon2Params) {
		t.Fatalf("zero params: want ErrInvalidArgon2Params, got %v", err)
	}
}

func TestLockoutKeyFromEmail(t *testing.T) {
	em := mustEmail(t, "Felix@Klarlabs.de")
	k := domain.LockoutKeyFromEmail(em)
	if len(k) != 64 {
		t.Fatalf("want 64 hex chars, got %d (%q)", len(k), k)
	}
	// NewEmail lowercases, so mixed-case input collapses to one key.
	if domain.LockoutKeyFromEmail(mustEmail(t, "felix@klarlabs.de")) != k {
		t.Fatal("key must be stable for the normalized email")
	}
	if k == em.String() {
		t.Fatal("lockout key must not be the plaintext email")
	}
}

func TestSessionService_RotateDeleteFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	base := memory.NewSessionRepo()
	fr := &failSessionRepo{SessionRepository: base}
	svc := domain.NewSessionService(fr, time.Hour, fixedClock(&now))

	old, err := svc.Issue(ctx, mustUserID(t, "u1"), mustTenantID(t, "t1"))
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("db down")
	// Sessions are keyed at rest (and on Delete) by the token hash, so match on it.
	fr.failToken = domain.HashToken(old.Token())
	fr.deleteErr = sentinel

	if _, err := svc.Rotate(ctx, old.Token()); !errors.Is(err, sentinel) {
		t.Fatalf("rotate delete error: want sentinel, got %v", err)
	}
	fr.deleteErr = nil

	// The new session was rolled back; only the old one remains.
	if _, err := svc.Validate(ctx, old.Token()); err != nil {
		t.Fatalf("old session lost after failed rotate: %v", err)
	}
}

func TestSessionService_RejectsZeroIDs(t *testing.T) {
	ctx := context.Background()
	svc := domain.NewSessionService(memory.NewSessionRepo(), time.Hour, nil)
	if _, err := svc.Issue(ctx, domain.UserID{}, mustTenantID(t, "t")); !errors.Is(err, domain.ErrInvalidUserID) {
		t.Fatalf("want ErrInvalidUserID, got %v", err)
	}
	if _, err := svc.Issue(ctx, mustUserID(t, "u"), domain.TenantID{}); !errors.Is(err, domain.ErrInvalidTenantID) {
		t.Fatalf("want ErrInvalidTenantID, got %v", err)
	}
}

// ── Magic link service ──────────────────────────────────────

func TestMagicLinkService_IssueInvalidatesPrior(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	repo := memory.NewMagicLinkRepo()
	svc := domain.NewMagicLinkService(repo, 15*time.Minute, fixedClock(&now))
	em := mustEmail(t, "a@b.co")
	tn := mustTenantID(t, "t1")

	first, err := svc.Issue(ctx, em, tn)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Issue(ctx, em, tn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Consume(ctx, first); !errors.Is(err, domain.ErrConsumed) {
		t.Fatalf("first link after re-issue: want ErrConsumed, got %v", err)
	}
	if _, err := svc.Consume(ctx, second); err != nil {
		t.Fatalf("second link should redeem: %v", err)
	}
	// A different tenant's outstanding link is untouched.
	other, err := svc.Issue(ctx, em, mustTenantID(t, "t2"))
	if err != nil {
		t.Fatal(err)
	}
	third, err := svc.Issue(ctx, em, tn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Consume(ctx, other); err != nil {
		t.Fatalf("cross-tenant link invalidated: %v", err)
	}
	_ = third
}

func TestMagicLinkService_SingleUse(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	repo := memory.NewMagicLinkRepo()
	svc := domain.NewMagicLinkService(repo, 15*time.Minute, fixedClock(&now))

	raw, err := svc.Issue(ctx, mustEmail(t, "felix@klarlabs.de"), mustTenantID(t, "t1"))
	if err != nil {
		t.Fatal(err)
	}
	// raw token is not the storage key
	if _, err := repo.FindByHash(ctx, raw.String()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("raw token used as key — must be hashed")
	}
	link, err := svc.Consume(ctx, raw)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if link.Email().String() != "felix@klarlabs.de" {
		t.Fatalf("unexpected link: %+v", link.Snapshot())
	}
	if _, err := svc.Consume(ctx, raw); !errors.Is(err, domain.ErrConsumed) {
		t.Fatalf("reuse: want ErrConsumed, got %v", err)
	}
}

func TestMagicLinkService_Expiry(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewMagicLinkService(memory.NewMagicLinkRepo(), 15*time.Minute, fixedClock(&now))
	raw, _ := svc.Issue(ctx, mustEmail(t, "a@b.co"), mustTenantID(t, "t"))
	now = now.Add(16 * time.Minute)
	if _, err := svc.Consume(ctx, raw); !errors.Is(err, domain.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestMagicLinkService_UnknownAndZeroTenant(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewMagicLinkService(memory.NewMagicLinkRepo(), 15*time.Minute, fixedClock(&now))
	if _, err := svc.Consume(ctx, domain.Token{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown: want ErrNotFound, got %v", err)
	}
	if _, err := svc.Issue(ctx, mustEmail(t, "a@b.co"), domain.TenantID{}); !errors.Is(err, domain.ErrInvalidTenantID) {
		t.Fatalf("zero tenant: want ErrInvalidTenantID, got %v", err)
	}
}

// ── Passkey repo (memory adapter) ───────────────────────────

func TestPasskeyRepo(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewPasskeyRepo()
	u := mustUserID(t, "u1")
	if err := repo.Add(ctx, domain.PasskeyCredential{ID: []byte{1, 2, 3}, UserID: u, Name: "Key"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Add(ctx, domain.PasskeyCredential{ID: []byte{4}, UserID: mustUserID(t, "other")}); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.ListByUser(ctx, u)
	if len(got) != 1 || got[0].Name != "Key" {
		t.Fatalf("listbyuser: %+v", got)
	}
	if err := repo.UpdateSignCount(ctx, []byte{1, 2, 3}, 42); err != nil {
		t.Fatal(err)
	}
	again, _ := repo.ListByUser(ctx, u)
	if again[0].SignCount != 42 {
		t.Fatalf("sign count: %d", again[0].SignCount)
	}
	if err := repo.UpdateSignCount(ctx, []byte{9}, 1); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown: want ErrNotFound, got %v", err)
	}
	if err := repo.Delete(ctx, []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	final, _ := repo.ListByUser(ctx, u)
	if len(final) != 0 {
		t.Fatalf("delete failed: %+v", final)
	}
}
