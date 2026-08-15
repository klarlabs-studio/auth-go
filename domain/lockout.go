package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
// must be safe for concurrent use. Every method takes a context.Context first
// so storage I/O honors cancellation, deadlines, and trace propagation.
type LoginAttemptStore interface {
	// Get returns the snapshot for a key or ErrNotFound.
	Get(ctx context.Context, key string) (LoginAttemptSnapshot, error)
	// Save upserts the snapshot.
	Save(ctx context.Context, s LoginAttemptSnapshot) error
	// Delete removes a key's state (used on successful auth).
	Delete(ctx context.Context, key string) error
}

// AtomicLoginAttemptStore is an optional LoginAttemptStore capability: record a
// failure in a single atomic step. The plain Get→Save path in RecordFailure
// loses increments when failures for one key race (all read the same count),
// which lets an attacker with N-way concurrency land far more than MaxFailures
// verified guesses before the lock engages. A store implementing this — a
// conditional single-statement UPSERT (sqlite/pgstore) or a mutexed map
// (memory) — closes that gap; the LockoutService prefers it automatically.
type AtomicLoginAttemptStore interface {
	// RecordFailureAtomically, for key as of now, atomically resets the count if a
	// prior lock has expired, increments the failure count, and sets LockedUntil
	// to now+window once the count reaches maxFailures. It returns the resulting
	// snapshot and whether this call is the one that engaged the lock (the count
	// reached the threshold on this failure). Unlike the non-atomic fallback it
	// does not "freeze" the count during an already-active lock — callers Guard
	// before verifying, so a failure during an active lock is not expected.
	RecordFailureAtomically(ctx context.Context, key string, now time.Time, maxFailures int, window time.Duration) (LoginAttemptSnapshot, bool, error)
}

// LockoutService is a domain service enforcing a LockoutPolicy over a
// LoginAttemptStore. It owns the count/lock transitions; the store only
// persists snapshots. The key is the caller's stable identifier for an
// authentication subject (typically a normalized email).
//
// Store errors are surfaced to the caller rather than swallowed: the library
// stays honest and the product decides its fail-open vs fail-closed posture.
//
// DoS trade-off: keying on the account (email) means an attacker who knows a
// victim's address can lock them out on purpose by burning failures. That is
// the accepted cost of per-account lockout; it is not an oversight. Mitigate at
// the product edge by ALSO throttling on a network identity (client IP or ASN)
// so one source cannot drive another account's counter, and prefer a lock that
// expires (Window) over a permanent one so a targeted victim self-recovers.
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
func (s *LockoutService) IsLocked(ctx context.Context, key string) (bool, error) {
	key, err := normalizeLockoutKey(key)
	if err != nil {
		return false, err
	}
	snap, err := s.store.Get(ctx, key)
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
func (s *LockoutService) Guard(ctx context.Context, key string) error {
	locked, err := s.IsLocked(ctx, key)
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
func (s *LockoutService) RecordFailure(ctx context.Context, key string) (locked bool, err error) {
	key, err = normalizeLockoutKey(key)
	if err != nil {
		return false, err
	}
	// Atomic path: a store that can record-and-lock in a single statement closes
	// the Get→Save race below, where concurrent failures for one key lose
	// increments and let far more than MaxFailures guesses through before locking.
	if a, ok := s.store.(AtomicLoginAttemptStore); ok {
		_, justLocked, err := a.RecordFailureAtomically(ctx, key, s.now(), s.policy.maxFailures, s.policy.window)
		return justLocked, err
	}
	snap, err := s.store.Get(ctx, key)
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
	if err := s.store.Save(ctx, snap); err != nil {
		return false, err
	}
	return justLocked, nil
}

// Clear removes a key's brute-force state. Call on successful authentication.
func (s *LockoutService) Clear(ctx context.Context, key string) error {
	key, err := normalizeLockoutKey(key)
	if err != nil {
		return err
	}
	return s.store.Delete(ctx, key)
}

// LockoutKeyFromEmail returns a stable, non-reversible lockout key derived from
// email (SHA-256 hex of the normalized address). Prefer this over storing the
// raw email in authgo_login_attempts — the LoginAttemptStore port documents that
// keys SHOULD be hashed at the adapter boundary so no plaintext PII is
// persisted.
func LockoutKeyFromEmail(email Email) string {
	sum := sha256.Sum256([]byte(email.String()))
	return hex.EncodeToString(sum[:])
}

// normalizeLockoutKey validates the key without mutating it. The key is
// caller-chosen and opaque (the port docs recommend a hash of the email), so
// the service must not lowercase or trim it — doing so could alias distinct
// case-sensitive identifiers (e.g. base64 or raw hashes). Blank and over-long
// keys are rejected.
func normalizeLockoutKey(key string) (string, error) {
	if strings.TrimSpace(key) == "" || len(key) > maxLockoutKeyLen {
		return "", ErrInvalidLockoutKey
	}
	return key, nil
}
