// Package memory provides in-memory implementations of the auth domain
// repository ports, for tests and single-node development. Production backs the
// ports with Postgres (../pgstore) or SQLite (../sqlite) instead.
//
// Every method opens with a best-effort ctx.Err() entry guard: the in-memory
// store does no blocking I/O, so there is no mid-operation cancellation point.
// Checking ctx.Err() up front only honors an already-cancelled context for
// parity with the repository contracts (which require ctx propagation) — it is
// not a cancellation guarantee mid-flight.
package memory

import (
	"context"
	"sync"
	"time"

	"github.com/klarlabs-studio/auth-go/domain"
)

// UserRepo is an in-memory domain.UserRepository.
type UserRepo struct {
	mu sync.RWMutex
	m  map[string]domain.UserSnapshot
}

// NewUserRepo returns an empty user repository.
func NewUserRepo() *UserRepo {
	return &UserRepo{m: make(map[string]domain.UserSnapshot)}
}

// GetUser returns the user for an ID or domain.ErrNotFound.
func (r *UserRepo) GetUser(ctx context.Context, id domain.UserID) (domain.User, error) {
	if err := ctx.Err(); err != nil {
		return domain.User{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap, ok := r.m[id.String()]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return domain.UserFromSnapshot(snap), nil
}

// UpsertUser inserts or updates a user, keyed on its ID.
func (r *UserRepo) UpsertUser(ctx context.Context, u domain.User) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := u.Snapshot()
	r.m[snap.ID] = snap
	return nil
}

// SessionRepo is an in-memory domain.SessionRepository.
type SessionRepo struct {
	mu sync.RWMutex
	m  map[string]domain.SessionSnapshot
}

// NewSessionRepo returns an empty session repository.
func NewSessionRepo() *SessionRepo {
	return &SessionRepo{m: make(map[string]domain.SessionSnapshot)}
}

// Save persists a session.
func (r *SessionRepo) Save(ctx context.Context, s domain.Session) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := s.Snapshot()
	r.m[snap.Token] = snap
	return nil
}

// FindByToken returns the session for a token or domain.ErrNotFound.
func (r *SessionRepo) FindByToken(ctx context.Context, token domain.Token) (domain.Session, error) {
	if err := ctx.Err(); err != nil {
		return domain.Session{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap, ok := r.m[token.String()]
	if !ok {
		return domain.Session{}, domain.ErrNotFound
	}
	return domain.SessionFromSnapshot(snap), nil
}

// Delete removes one session.
func (r *SessionRepo) Delete(ctx context.Context, token domain.Token) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, token.String())
	return nil
}

// DeleteByUser removes every session for a user.
func (r *SessionRepo) DeleteByUser(ctx context.Context, userID domain.UserID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for tok, snap := range r.m {
		if snap.UserID == userID.String() {
			delete(r.m, tok)
		}
	}
	return nil
}

// MagicLinkRepo is an in-memory domain.MagicLinkRepository.
type MagicLinkRepo struct {
	mu sync.RWMutex
	m  map[string]domain.MagicLinkSnapshot
}

// NewMagicLinkRepo returns an empty magic-link repository.
func NewMagicLinkRepo() *MagicLinkRepo {
	return &MagicLinkRepo{m: make(map[string]domain.MagicLinkSnapshot)}
}

// Save persists a magic link.
func (r *MagicLinkRepo) Save(ctx context.Context, m domain.MagicLink) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := m.Snapshot()
	r.m[snap.Hash] = snap
	return nil
}

// FindByHash returns the link for a hash or domain.ErrNotFound.
func (r *MagicLinkRepo) FindByHash(ctx context.Context, hash string) (domain.MagicLink, error) {
	if err := ctx.Err(); err != nil {
		return domain.MagicLink{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap, ok := r.m[hash]
	if !ok {
		return domain.MagicLink{}, domain.ErrNotFound
	}
	return domain.MagicLinkFromSnapshot(snap), nil
}

// MarkConsumed flags a link as used.
func (r *MagicLinkRepo) MarkConsumed(ctx context.Context, hash string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	snap, ok := r.m[hash]
	if !ok || snap.Consumed {
		// Absent or already consumed — this call did not perform the flip.
		return false, nil
	}
	snap.Consumed = true
	r.m[hash] = snap
	return true, nil
}

// TOTPRepo is an in-memory domain.TOTPRepository.
type TOTPRepo struct {
	mu    sync.RWMutex
	m     map[string]string // userID -> base32 secret
	steps map[string]int64  // userID -> last consumed TOTP step
}

// NewTOTPRepo returns an empty TOTP secret repository.
func NewTOTPRepo() *TOTPRepo {
	return &TOTPRepo{m: make(map[string]string), steps: make(map[string]int64)}
}

// GetSecret returns the user's secret or domain.ErrNotFound.
func (r *TOTPRepo) GetSecret(ctx context.Context, userID domain.UserID) (domain.TOTPSecret, error) {
	if err := ctx.Err(); err != nil {
		return domain.TOTPSecret{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	enc, ok := r.m[userID.String()]
	if !ok {
		return domain.TOTPSecret{}, domain.ErrNotFound
	}
	return domain.TOTPSecretFromString(enc)
}

// SetSecret enrolls or replaces the user's secret.
func (r *TOTPRepo) SetSecret(ctx context.Context, userID domain.UserID, secret domain.TOTPSecret) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[userID.String()] = secret.String()
	return nil
}

// DeleteSecret removes the user's secret. Removing an absent secret returns
// domain.ErrNotFound.
func (r *TOTPRepo) DeleteSecret(ctx context.Context, userID domain.UserID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.m[userID.String()]; !ok {
		return domain.ErrNotFound
	}
	delete(r.m, userID.String())
	delete(r.steps, userID.String())
	return nil
}

// ConsumeStep implements domain.AtomicTOTPConsumer: record step as used,
// accepting it only if it advances past the user's last consumed step.
func (r *TOTPRepo) ConsumeStep(ctx context.Context, userID domain.UserID, step int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if last, ok := r.steps[userID.String()]; ok && step <= last {
		return false, nil
	}
	r.steps[userID.String()] = step
	return true, nil
}

// PasskeyRepo is an in-memory domain.PasskeyRepository.
type PasskeyRepo struct {
	mu sync.RWMutex
	m  map[string]domain.PasskeyCredential // key: string(ID)
}

// NewPasskeyRepo returns an empty passkey repository.
func NewPasskeyRepo() *PasskeyRepo {
	return &PasskeyRepo{m: make(map[string]domain.PasskeyCredential)}
}

// Add stores a credential.
func (r *PasskeyRepo) Add(ctx context.Context, c domain.PasskeyCredential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[string(c.ID)] = c
	return nil
}

// ListByUser returns a user's credentials.
func (r *PasskeyRepo) ListByUser(ctx context.Context, userID domain.UserID) ([]domain.PasskeyCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []domain.PasskeyCredential
	for _, c := range r.m {
		if c.UserID.String() == userID.String() {
			out = append(out, c)
		}
	}
	return out, nil
}

// UpdateSignCount advances a credential's sign count.
func (r *PasskeyRepo) UpdateSignCount(ctx context.Context, id []byte, count uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.m[string(id)]
	if !ok {
		return domain.ErrNotFound
	}
	r.m[string(id)] = c.WithSignCount(count)
	return nil
}

// Delete removes a credential.
func (r *PasskeyRepo) Delete(ctx context.Context, id []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, string(id))
	return nil
}

// LoginAttemptRepo is an in-memory domain.LoginAttemptStore.
type LoginAttemptRepo struct {
	mu sync.RWMutex
	m  map[string]domain.LoginAttemptSnapshot
}

// NewLoginAttemptRepo returns an empty login-attempt store.
func NewLoginAttemptRepo() *LoginAttemptRepo {
	return &LoginAttemptRepo{m: make(map[string]domain.LoginAttemptSnapshot)}
}

// Get returns the snapshot for a key or domain.ErrNotFound.
func (r *LoginAttemptRepo) Get(ctx context.Context, key string) (domain.LoginAttemptSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.LoginAttemptSnapshot{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap, ok := r.m[key]
	if !ok {
		return domain.LoginAttemptSnapshot{}, domain.ErrNotFound
	}
	return snap, nil
}

// Save upserts the snapshot.
func (r *LoginAttemptRepo) Save(ctx context.Context, s domain.LoginAttemptSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[s.Key] = s
	return nil
}

// Delete removes a key's state.
func (r *LoginAttemptRepo) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, key)
	return nil
}

// RecordFailureAtomically implements domain.AtomicLoginAttemptStore: the whole
// read-modify-write runs under the store mutex, so concurrent failures for one
// key can't lose increments.
func (r *LoginAttemptRepo) RecordFailureAtomically(ctx context.Context, key string, now time.Time, maxFailures int, window time.Duration) (domain.LoginAttemptSnapshot, bool, error) {
	if err := ctx.Err(); err != nil {
		return domain.LoginAttemptSnapshot{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := r.m[key]
	snap.Key = key
	// A previously-expired lock starts a fresh count.
	if !snap.LockedUntil.IsZero() && !now.Before(snap.LockedUntil) {
		snap.FailureCount = 0
		snap.LockedUntil = time.Time{}
	}
	snap.FailureCount++
	// Engage the lock the moment the threshold is reached; don't re-extend an
	// already-active one.
	if snap.FailureCount >= maxFailures && snap.LockedUntil.IsZero() {
		snap.LockedUntil = now.Add(window)
	}
	r.m[key] = snap
	justLocked := !snap.LockedUntil.IsZero() && snap.FailureCount == maxFailures
	return snap, justLocked, nil
}

// WorkloadKeyRepo is an in-memory domain.WorkloadStore. It indexes keys by both
// ID and token hash so the validation hot path (GetKeyByHash) is O(1) without
// scanning. The two maps are kept consistent under a single lock.
type WorkloadKeyRepo struct {
	mu     sync.RWMutex
	byID   map[string]domain.APIKeySnapshot
	byHash map[string]string // hash -> id
}

// NewWorkloadKeyRepo returns an empty workload-key store.
func NewWorkloadKeyRepo() *WorkloadKeyRepo {
	return &WorkloadKeyRepo{
		byID:   make(map[string]domain.APIKeySnapshot),
		byHash: make(map[string]string),
	}
}

// CreateKey inserts a new key, rejecting a duplicate ID or hash. Like every
// method here it opens with the package-wide best-effort ctx.Err() entry guard
// (see the package doc).
func (r *WorkloadKeyRepo) CreateKey(ctx context.Context, k domain.APIKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := k.Snapshot()
	if _, exists := r.byID[snap.ID]; exists {
		return domain.ErrConflict
	}
	if _, exists := r.byHash[snap.Hash]; exists {
		return domain.ErrConflict
	}
	r.byID[snap.ID] = snap
	r.byHash[snap.Hash] = snap.ID
	return nil
}

// GetKeyByHash returns the key for a token hash or domain.ErrNotFound.
func (r *WorkloadKeyRepo) GetKeyByHash(ctx context.Context, hash string) (domain.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return domain.APIKey{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byHash[hash]
	if !ok {
		return domain.APIKey{}, domain.ErrNotFound
	}
	return domain.APIKeyFromSnapshot(r.byID[id]), nil
}

// GetKey returns the key for an ID or domain.ErrNotFound.
func (r *WorkloadKeyRepo) GetKey(ctx context.Context, id domain.KeyID) (domain.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return domain.APIKey{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap, ok := r.byID[id.String()]
	if !ok {
		return domain.APIKey{}, domain.ErrNotFound
	}
	return domain.APIKeyFromSnapshot(snap), nil
}

// ListKeysByWorker returns every key for a worker.
func (r *WorkloadKeyRepo) ListKeysByWorker(ctx context.Context, workerID domain.WorkerID) ([]domain.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []domain.APIKey
	for _, snap := range r.byID {
		if snap.WorkerID == workerID.String() {
			out = append(out, domain.APIKeyFromSnapshot(snap))
		}
	}
	return out, nil
}

// DeleteKey removes a key by ID. Deleting an absent key returns ErrNotFound.
func (r *WorkloadKeyRepo) DeleteKey(ctx context.Context, id domain.KeyID) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	snap, ok := r.byID[id.String()]
	if !ok {
		return domain.ErrNotFound
	}
	delete(r.byID, snap.ID)
	delete(r.byHash, snap.Hash)
	return nil
}

// Port assertions.
var (
	_ domain.UserRepository      = (*UserRepo)(nil)
	_ domain.SessionRepository   = (*SessionRepo)(nil)
	_ domain.MagicLinkRepository = (*MagicLinkRepo)(nil)
	_ domain.TOTPRepository      = (*TOTPRepo)(nil)
	_ domain.PasskeyRepository   = (*PasskeyRepo)(nil)
	_ domain.LoginAttemptStore   = (*LoginAttemptRepo)(nil)
	_ domain.WorkloadStore       = (*WorkloadKeyRepo)(nil)
)
