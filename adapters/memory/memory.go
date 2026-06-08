// Package memory provides in-memory implementations of the auth domain
// repository ports, for tests and single-node development. Production backs the
// ports with Postgres (../pgstore) instead.
package memory

import (
	"sync"

	"github.com/klarlabs-studio/auth-go/domain"
)

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
func (r *SessionRepo) Save(s domain.Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := s.Snapshot()
	r.m[snap.Token] = snap
	return nil
}

// FindByToken returns the session for a token or domain.ErrNotFound.
func (r *SessionRepo) FindByToken(token domain.Token) (domain.Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap, ok := r.m[token.String()]
	if !ok {
		return domain.Session{}, domain.ErrNotFound
	}
	return domain.SessionFromSnapshot(snap), nil
}

// Delete removes one session.
func (r *SessionRepo) Delete(token domain.Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, token.String())
	return nil
}

// DeleteByUser removes every session for a user.
func (r *SessionRepo) DeleteByUser(userID domain.UserID) error {
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
func (r *MagicLinkRepo) Save(m domain.MagicLink) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := m.Snapshot()
	r.m[snap.Hash] = snap
	return nil
}

// FindByHash returns the link for a hash or domain.ErrNotFound.
func (r *MagicLinkRepo) FindByHash(hash string) (domain.MagicLink, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap, ok := r.m[hash]
	if !ok {
		return domain.MagicLink{}, domain.ErrNotFound
	}
	return domain.MagicLinkFromSnapshot(snap), nil
}

// MarkConsumed flags a link as used.
func (r *MagicLinkRepo) MarkConsumed(hash string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap, ok := r.m[hash]
	if !ok {
		return domain.ErrNotFound
	}
	snap.Consumed = true
	r.m[hash] = snap
	return nil
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
func (r *PasskeyRepo) Add(c domain.PasskeyCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[string(c.ID)] = c
	return nil
}

// ListByUser returns a user's credentials.
func (r *PasskeyRepo) ListByUser(userID domain.UserID) ([]domain.PasskeyCredential, error) {
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
func (r *PasskeyRepo) UpdateSignCount(id []byte, count uint32) error {
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
func (r *PasskeyRepo) Delete(id []byte) error {
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
func (r *LoginAttemptRepo) Get(key string) (domain.LoginAttemptSnapshot, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap, ok := r.m[key]
	if !ok {
		return domain.LoginAttemptSnapshot{}, domain.ErrNotFound
	}
	return snap, nil
}

// Save upserts the snapshot.
func (r *LoginAttemptRepo) Save(s domain.LoginAttemptSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[s.Key] = s
	return nil
}

// Delete removes a key's state.
func (r *LoginAttemptRepo) Delete(key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, key)
	return nil
}

// Port assertions.
var (
	_ domain.SessionRepository   = (*SessionRepo)(nil)
	_ domain.MagicLinkRepository = (*MagicLinkRepo)(nil)
	_ domain.PasskeyRepository   = (*PasskeyRepo)(nil)
	_ domain.LoginAttemptStore   = (*LoginAttemptRepo)(nil)
)
