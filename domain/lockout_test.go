package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/adapters/memory"
	"github.com/klarlabs-studio/auth-go/domain"
)

// ── LockoutPolicy value object ──────────────────────────────

func TestLockoutPolicy_Validation(t *testing.T) {
	tests := []struct {
		name        string
		maxFailures int
		window      time.Duration
		wantErr     bool
	}{
		{"valid", 5, 15 * time.Minute, false},
		{"zero failures", 0, time.Minute, true},
		{"negative failures", -1, time.Minute, true},
		{"zero window", 5, 0, true},
		{"negative window", 5, -time.Second, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := domain.NewLockoutPolicy(tc.maxFailures, tc.window)
			if tc.wantErr {
				if !errors.Is(err, domain.ErrInvalidLockoutCfg) {
					t.Fatalf("want ErrInvalidLockoutCfg, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.MaxFailures() != tc.maxFailures || p.Window() != tc.window {
				t.Fatalf("unexpected policy: %+v", p)
			}
		})
	}
}

func TestDefaultLockoutPolicy(t *testing.T) {
	p := domain.DefaultLockoutPolicy()
	if p.MaxFailures() != 5 || p.Window() != 15*time.Minute {
		t.Fatalf("unexpected defaults: %d / %s", p.MaxFailures(), p.Window())
	}
}

func TestLockoutPolicy_LockedUntil(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	p := domain.DefaultLockoutPolicy() // 5 / 15m
	tests := []struct {
		name     string
		count    int
		wantLock bool
	}{
		{"below threshold", 4, false},
		{"at threshold", 5, true},
		{"above threshold", 6, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			until := p.LockedUntil(tc.count, now)
			if tc.wantLock {
				if !until.Equal(now.Add(15 * time.Minute)) {
					t.Fatalf("want lock at %s, got %s", now.Add(15*time.Minute), until)
				}
			} else if !until.IsZero() {
				t.Fatalf("want no lock, got %s", until)
			}
		})
	}
}

// ── LockoutService over the LoginAttemptStore port ──────────

func TestLockoutService_LocksAfterThreshold(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	store := memory.NewLoginAttemptRepo()
	svc := domain.NewLockoutService(store, domain.DefaultLockoutPolicy(), fixedClock(&now))

	key := "felix@klarlabs.de"

	for i := 1; i <= 4; i++ {
		locked, err := svc.RecordFailure(key)
		if err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
		if locked {
			t.Fatalf("locked too early at failure %d", i)
		}
		if l, _ := svc.IsLocked(key); l {
			t.Fatalf("IsLocked true too early at failure %d", i)
		}
	}

	locked, err := svc.RecordFailure(key)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatal("want locked on 5th failure")
	}
	if l, _ := svc.IsLocked(key); !l {
		t.Fatal("IsLocked should be true after threshold")
	}
}

func TestLockoutService_GuardReturnsErrAccountLocked(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	store := memory.NewLoginAttemptRepo()
	svc := domain.NewLockoutService(store, domain.DefaultLockoutPolicy(), fixedClock(&now))
	key := "u@x.co"
	for range 5 {
		_, _ = svc.RecordFailure(key)
	}
	if err := svc.Guard(key); !errors.Is(err, domain.ErrAccountLocked) {
		t.Fatalf("want ErrAccountLocked, got %v", err)
	}
}

func TestLockoutService_LockExpires(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	store := memory.NewLoginAttemptRepo()
	svc := domain.NewLockoutService(store, domain.DefaultLockoutPolicy(), fixedClock(&now))
	key := "u@x.co"
	for range 5 {
		_, _ = svc.RecordFailure(key)
	}
	if l, _ := svc.IsLocked(key); !l {
		t.Fatal("should be locked")
	}
	now = now.Add(16 * time.Minute) // window elapsed
	if l, _ := svc.IsLocked(key); l {
		t.Fatal("lock should have expired")
	}
	if err := svc.Guard(key); err != nil {
		t.Fatalf("guard after expiry: %v", err)
	}
}

func TestLockoutService_ClearOnSuccess(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	store := memory.NewLoginAttemptRepo()
	svc := domain.NewLockoutService(store, domain.DefaultLockoutPolicy(), fixedClock(&now))
	key := "u@x.co"
	for range 3 {
		_, _ = svc.RecordFailure(key)
	}
	if err := svc.Clear(key); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		locked, _ := svc.RecordFailure(key)
		if locked {
			t.Fatalf("locked too early after clear at %d", i)
		}
	}
}

func TestLockoutService_RejectsEmptyKey(t *testing.T) {
	svc := domain.NewLockoutService(memory.NewLoginAttemptRepo(), domain.DefaultLockoutPolicy(), nil)
	if _, err := svc.RecordFailure(""); !errors.Is(err, domain.ErrInvalidLockoutKey) {
		t.Fatalf("want ErrInvalidLockoutKey on empty key, got %v", err)
	}
	if _, err := svc.IsLocked("  "); !errors.Is(err, domain.ErrInvalidLockoutKey) {
		t.Fatalf("want ErrInvalidLockoutKey on blank key, got %v", err)
	}
	if err := svc.Clear(""); !errors.Is(err, domain.ErrInvalidLockoutKey) {
		t.Fatalf("Clear must reject empty key, got %v", err)
	}
}

// errStore is a LoginAttemptStore whose every method fails, used to prove the
// service surfaces persistence errors rather than swallowing them.
type errStore struct{ err error }

func (e errStore) Get(string) (domain.LoginAttemptSnapshot, error) {
	return domain.LoginAttemptSnapshot{}, e.err
}
func (e errStore) Save(domain.LoginAttemptSnapshot) error { return e.err }
func (e errStore) Delete(string) error                    { return e.err }

func TestLockoutService_PropagatesStoreErrors(t *testing.T) {
	boom := errors.New("store down")
	svc := domain.NewLockoutService(errStore{err: boom}, domain.DefaultLockoutPolicy(), nil)

	if _, err := svc.IsLocked("u@x.co"); !errors.Is(err, boom) {
		t.Fatalf("IsLocked must surface store error, got %v", err)
	}
	if err := svc.Guard("u@x.co"); !errors.Is(err, boom) {
		t.Fatalf("Guard must surface store error, got %v", err)
	}
	if _, err := svc.RecordFailure("u@x.co"); !errors.Is(err, boom) {
		t.Fatalf("RecordFailure must surface store Get error, got %v", err)
	}
	if err := svc.Clear("u@x.co"); !errors.Is(err, boom) {
		t.Fatalf("Clear must surface store error, got %v", err)
	}
}

// saveErrStore reports an empty key as absent (ErrNotFound on Get) but fails on
// Save, covering the RecordFailure write-error path after a fresh count.
type saveErrStore struct{ err error }

func (s saveErrStore) Get(string) (domain.LoginAttemptSnapshot, error) {
	return domain.LoginAttemptSnapshot{}, domain.ErrNotFound
}
func (s saveErrStore) Save(domain.LoginAttemptSnapshot) error { return s.err }
func (s saveErrStore) Delete(string) error                    { return nil }

func TestLockoutService_RecordFailureSaveError(t *testing.T) {
	boom := errors.New("save failed")
	svc := domain.NewLockoutService(saveErrStore{err: boom}, domain.DefaultLockoutPolicy(), nil)
	if _, err := svc.RecordFailure("u@x.co"); !errors.Is(err, boom) {
		t.Fatalf("RecordFailure must surface Save error, got %v", err)
	}
}
