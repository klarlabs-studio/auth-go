package authgo

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// MagicLink is a single-use, time-boxed login token sent by email. Only the
// SHA-256 hash of the token is stored; the raw token lives only in the link.
type MagicLink struct {
	Hash      string
	Email     string
	TenantID  string
	ExpiresAt time.Time
	Consumed  bool
}

// MagicLinkStore persists magic links. Concurrency-safe.
type MagicLinkStore interface {
	Save(ml MagicLink) error
	Get(hash string) (MagicLink, error)
	MarkConsumed(hash string) error
}

// hashToken returns the hex SHA-256 of a raw token (storage key).
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// MagicLinkManager issues and consumes magic links.
type MagicLinkManager struct {
	store MagicLinkStore
	ttl   time.Duration
	now   Clock
}

// NewMagicLinkManager builds a manager. ttl is the link lifetime (standard: 15m).
func NewMagicLinkManager(store MagicLinkStore, ttl time.Duration, clock Clock) *MagicLinkManager {
	if clock == nil {
		clock = SystemClock
	}
	return &MagicLinkManager{store: store, ttl: ttl, now: clock}
}

// Issue creates a link for an email/tenant and returns the RAW token to embed
// in the emailed URL. The raw token is never persisted.
func (m *MagicLinkManager) Issue(email, tenantID string) (rawToken string, err error) {
	rawToken, err = newToken()
	if err != nil {
		return "", err
	}
	t := m.now()
	ml := MagicLink{
		Hash:      hashToken(rawToken),
		Email:     email,
		TenantID:  tenantID,
		ExpiresAt: t.Add(m.ttl),
	}
	if err := m.store.Save(ml); err != nil {
		return "", err
	}
	return rawToken, nil
}

// Consume validates a raw token and, on success, marks it consumed and returns
// the link. Returns ErrNotFound, ErrExpired, or ErrConsumed otherwise.
func (m *MagicLinkManager) Consume(rawToken string) (MagicLink, error) {
	ml, err := m.store.Get(hashToken(rawToken))
	if err != nil {
		return MagicLink{}, err
	}
	if ml.Consumed {
		return MagicLink{}, ErrConsumed
	}
	if !m.now().Before(ml.ExpiresAt) {
		return MagicLink{}, ErrExpired
	}
	if err := m.store.MarkConsumed(ml.Hash); err != nil {
		return MagicLink{}, err
	}
	ml.Consumed = true
	return ml, nil
}

// MemoryMagicLinkStore is an in-memory MagicLinkStore for tests and dev.
type MemoryMagicLinkStore struct {
	mu sync.RWMutex
	m  map[string]MagicLink
}

// NewMemoryMagicLinkStore returns an empty in-memory store.
func NewMemoryMagicLinkStore() *MemoryMagicLinkStore {
	return &MemoryMagicLinkStore{m: make(map[string]MagicLink)}
}

func (s *MemoryMagicLinkStore) Save(ml MagicLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[ml.Hash] = ml
	return nil
}

func (s *MemoryMagicLinkStore) Get(hash string) (MagicLink, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ml, ok := s.m[hash]
	if !ok {
		return MagicLink{}, ErrNotFound
	}
	return ml, nil
}

func (s *MemoryMagicLinkStore) MarkConsumed(hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ml, ok := s.m[hash]
	if !ok {
		return ErrNotFound
	}
	ml.Consumed = true
	s.m[hash] = ml
	return nil
}
