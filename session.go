// Package authgo is the Klarlabs shared authentication library.
//
// It implements the auth methods mandated by the Klarlabs product standard:
// magic link, password + TOTP, and passkeys (WebAuthn, via an adapter). All
// methods converge on a single server-side [Session] with HttpOnly-cookie
// semantics, so a product wires one session store and gets every method.
package authgo

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Errors returned across the package.
var (
	ErrNotFound = errors.New("authgo: not found")
	ErrExpired  = errors.New("authgo: expired")
	ErrConsumed = errors.New("authgo: already consumed")
)

// Clock returns the current time. Injected for deterministic tests.
type Clock func() time.Time

// SystemClock is the default wall-clock.
func SystemClock() time.Time { return time.Now() }

// Session is an authenticated server-side session. The opaque Token is what
// rides in the HttpOnly cookie; everything else stays server-side.
type Session struct {
	Token     string
	UserID    string
	TenantID  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Expired reports whether the session is past its expiry as of now.
func (s Session) Expired(now time.Time) bool { return !now.Before(s.ExpiresAt) }

// SessionStore persists sessions. Implementations must be safe for concurrent
// use. Products back this with Postgres/Redis; the in-memory store is for
// tests and single-node dev.
type SessionStore interface {
	Create(s Session) error
	Get(token string) (Session, error)
	Delete(token string) error
	// DeleteByUser revokes every session for a user (logout-everywhere).
	DeleteByUser(userID string) error
}

// newToken returns a 256-bit URL-safe random token.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SessionManager issues and validates sessions over a SessionStore.
type SessionManager struct {
	store SessionStore
	ttl   time.Duration
	now   Clock
}

// NewSessionManager builds a manager. ttl is the session lifetime.
func NewSessionManager(store SessionStore, ttl time.Duration, clock Clock) *SessionManager {
	if clock == nil {
		clock = SystemClock
	}
	return &SessionManager{store: store, ttl: ttl, now: clock}
}

// Issue creates a fresh session for a user/tenant and returns it.
func (m *SessionManager) Issue(userID, tenantID string) (Session, error) {
	tok, err := newToken()
	if err != nil {
		return Session{}, err
	}
	t := m.now()
	s := Session{
		Token:     tok,
		UserID:    userID,
		TenantID:  tenantID,
		CreatedAt: t,
		ExpiresAt: t.Add(m.ttl),
	}
	if err := m.store.Create(s); err != nil {
		return Session{}, err
	}
	return s, nil
}

// Validate returns the session for a token, or ErrExpired/ErrNotFound. Expired
// sessions are deleted as a side effect.
func (m *SessionManager) Validate(token string) (Session, error) {
	s, err := m.store.Get(token)
	if err != nil {
		return Session{}, err
	}
	if s.Expired(m.now()) {
		_ = m.store.Delete(token)
		return Session{}, ErrExpired
	}
	return s, nil
}

// Revoke deletes a single session (logout).
func (m *SessionManager) Revoke(token string) error { return m.store.Delete(token) }

// RevokeAll deletes every session for a user (logout-everywhere).
func (m *SessionManager) RevokeAll(userID string) error { return m.store.DeleteByUser(userID) }

// MemorySessionStore is an in-memory SessionStore for tests and dev.
type MemorySessionStore struct {
	mu sync.RWMutex
	m  map[string]Session
}

// NewMemorySessionStore returns an empty in-memory store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{m: make(map[string]Session)}
}

func (s *MemorySessionStore) Create(sess Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[sess.Token] = sess
	return nil
}

func (s *MemorySessionStore) Get(token string) (Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.m[token]
	if !ok {
		return Session{}, ErrNotFound
	}
	return sess, nil
}

func (s *MemorySessionStore) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, token)
	return nil
}

func (s *MemorySessionStore) DeleteByUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, sess := range s.m {
		if sess.UserID == userID {
			delete(s.m, tok)
		}
	}
	return nil
}
