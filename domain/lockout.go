package domain

import (
	"errors"
	"strings"
	"time"
)

// LockoutPolicy is a value object: the brute-force lockout parameters. After
// MaxFailures consecutive failed authentications for a key (typically a
// normalized email), the key is locked for Window.
type LockoutPolicy struct {
	maxFailures int
	window      time.Duration
}

// Default lockout parameters: 5 failures, 15-minute lock.
const (
	defaultMaxFailures = 5
	defaultLockWindow  = 15 * time.Minute
)

// NewLockoutPolicy validates and constructs a LockoutPolicy.
func NewLockoutPolicy(maxFailures int, window time.Duration) (LockoutPolicy, error) {
	if maxFailures <= 0 || window <= 0 {
		return LockoutPolicy{}, ErrInvalidLockoutCfg
	}
	return LockoutPolicy{maxFailures: maxFailures, window: window}, nil
}

// DefaultLockoutPolicy returns the standard 5-failure / 15-minute policy.
func DefaultLockoutPolicy() LockoutPolicy {
	return LockoutPolicy{maxFailures: defaultMaxFailures, window: defaultLockWindow}
}

// MaxFailures returns the failure threshold.
func (p LockoutPolicy) MaxFailures() int { return p.maxFailures }

// Window returns the lock duration.
func (p LockoutPolicy) Window() time.Duration { return p.window }

// LockedUntil is the pure policy decision: given the failure count reached and
// the time of that failure, return the lock-expiry instant, or the zero time
// if the threshold has not been met.
func (p LockoutPolicy) LockedUntil(failureCount int, at time.Time) time.Time {
	if failureCount >= p.maxFailures {
		return at.Add(p.window)
	}
	return time.Time{}
}

// LoginAttemptSnapshot is the flat, exportable shape of a key's brute-force
// state. Adapters convert between this and storage rows; the LockoutService
// owns the transition logic so persistence stays dumb.
type LoginAttemptSnapshot struct {
	Key          string
	FailureCount int
	LockedUntil  time.Time // zero when not locked
}

// LoginAttemptStore is the persistence port for brute-force counters. Keys are
// caller-chosen, opaque, and SHOULD be a hash of the email at the adapter
// boundary so no plaintext PII is persisted (see pgstore). Implementations
// must be safe for concurrent use.
type LoginAttemptStore interface {
	// Get returns the snapshot for a key or ErrNotFound.
	Get(key string) (LoginAttemptSnapshot, error)
	// Save upserts the snapshot.
	Save(s LoginAttemptSnapshot) error
	// Delete removes a key's state (used on successful auth).
	Delete(key string) error
}

// LockoutService is a domain service enforcing a LockoutPolicy over a
// LoginAttemptStore. It owns the count/lock transitions; the store only
// persists snapshots. The key is the caller's stable identifier for an
// authentication subject (typically a normalized email).
//
// Store errors are surfaced to the caller rather than swallowed: the library
// stays honest and the product decides its fail-open vs fail-closed posture.
type LockoutService struct {
	store  LoginAttemptStore
	policy LockoutPolicy
	now    Clock
}

// NewLockoutService builds the service. A nil clock uses the wall clock.
func NewLockoutService(store LoginAttemptStore, policy LockoutPolicy, clock Clock) *LockoutService {
	return &LockoutService{store: store, policy: policy, now: orSystemClock(clock)}
}

// IsLocked reports whether the key is currently within an active lockout
// window. Expired locks read as unlocked.
func (s *LockoutService) IsLocked(key string) (bool, error) {
	key, err := normalizeLockoutKey(key)
	if err != nil {
		return false, err
	}
	snap, err := s.store.Get(key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if snap.LockedUntil.IsZero() {
		return false, nil
	}
	return s.now().Before(snap.LockedUntil), nil
}

// Guard returns ErrAccountLocked if the key is currently locked, else nil.
// Call it before verifying credentials.
func (s *LockoutService) Guard(key string) error {
	locked, err := s.IsLocked(key)
	if err != nil {
		return err
	}
	if locked {
		return ErrAccountLocked
	}
	return nil
}

// RecordFailure increments the failure counter for a key and applies the lock
// when the policy threshold is met. It returns true when this call caused the
// key to transition into a locked state.
//
// While a key is within an active lock window this is a no-op: the lock was
// already decided, so counting further failures (and pushing LockedUntil
// forward from each new now) would make the lockout unbounded under repeated
// attempts. Callers should Guard before verifying, so failures during an
// active lock are not expected, but the no-op keeps the window honestly bounded
// to Window even if they occur.
//
// The Get→Save sequence is not atomic: under concurrent failures for the same
// key, a lost increment can delay the threshold by an attempt or two. The lock
// still triggers — the control is not defeated — but stores needing exact
// counts under high-concurrency attack should serialize per key (e.g. a
// SELECT … FOR UPDATE adapter). This is an accepted v0.3.0 trade-off of the
// dumb-store port.
func (s *LockoutService) RecordFailure(key string) (locked bool, err error) {
	key, err = normalizeLockoutKey(key)
	if err != nil {
		return false, err
	}
	snap, err := s.store.Get(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, err
	}
	if errors.Is(err, ErrNotFound) {
		snap = LoginAttemptSnapshot{Key: key}
	}

	now := s.now()
	if !snap.LockedUntil.IsZero() {
		if now.Before(snap.LockedUntil) {
			// Active lock: leave the window untouched.
			return false, nil
		}
		// A previously-expired lock starts a fresh count.
		snap.FailureCount = 0
		snap.LockedUntil = time.Time{}
	}

	snap.FailureCount++
	until := s.policy.LockedUntil(snap.FailureCount, now)
	justLocked := !until.IsZero()
	if justLocked {
		snap.LockedUntil = until
	}
	if err := s.store.Save(snap); err != nil {
		return false, err
	}
	return justLocked, nil
}

// Clear removes a key's brute-force state. Call on successful authentication.
func (s *LockoutService) Clear(key string) error {
	key, err := normalizeLockoutKey(key)
	if err != nil {
		return err
	}
	return s.store.Delete(key)
}

// normalizeLockoutKey validates the key without mutating it. The key is
// caller-chosen and opaque (the port docs recommend a hash of the email), so
// the service must not lowercase or trim it — doing so could alias distinct
// case-sensitive identifiers (e.g. base64 or raw hashes). Only blank keys are
// rejected.
func normalizeLockoutKey(key string) (string, error) {
	if strings.TrimSpace(key) == "" {
		return "", ErrInvalidLockoutKey
	}
	return key, nil
}
