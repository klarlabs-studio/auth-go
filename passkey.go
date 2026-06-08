package authgo

import "sync"

// Passkey support (WebAuthn) is exposed as an interface so the dependency-free
// core stays light. A concrete adapter (authgo/webauthn, wrapping
// github.com/go-webauthn/webauthn) implements Authenticator; products that
// want passkeys import the adapter, the rest pay nothing.

// PasskeyCredential is a stored WebAuthn credential bound to a user.
type PasskeyCredential struct {
	ID        []byte // credential ID
	UserID    string
	PublicKey []byte
	SignCount uint32
	Name      string // user-facing label ("MacBook Touch ID")
}

// PasskeyStore persists passkey credentials.
type PasskeyStore interface {
	Add(c PasskeyCredential) error
	ListByUser(userID string) ([]PasskeyCredential, error)
	UpdateSignCount(id []byte, count uint32) error
	Delete(id []byte) error
}

// PasskeyAuthenticator drives the WebAuthn ceremonies. Implemented by the
// authgo/webauthn adapter. Opaque byte blobs are the JSON challenge/response
// payloads exchanged with the browser's navigator.credentials API.
type PasskeyAuthenticator interface {
	// BeginRegistration starts enrolling a new passkey for a user.
	BeginRegistration(userID, displayName string) (options []byte, state []byte, err error)
	// FinishRegistration verifies the browser response and returns the credential to store.
	FinishRegistration(state []byte, response []byte) (PasskeyCredential, error)
	// BeginLogin starts an assertion for a user's known credentials.
	BeginLogin(userID string) (options []byte, state []byte, err error)
	// FinishLogin verifies the assertion and returns the credential ID that signed.
	FinishLogin(state []byte, response []byte) (credentialID []byte, err error)
}

// MemoryPasskeyStore is an in-memory PasskeyStore for tests and dev.
type MemoryPasskeyStore struct {
	mu sync.RWMutex
	m  map[string]PasskeyCredential // key: hex(ID)
}

// NewMemoryPasskeyStore returns an empty in-memory store.
func NewMemoryPasskeyStore() *MemoryPasskeyStore {
	return &MemoryPasskeyStore{m: make(map[string]PasskeyCredential)}
}

func (s *MemoryPasskeyStore) Add(c PasskeyCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[string(c.ID)] = c
	return nil
}

func (s *MemoryPasskeyStore) ListByUser(userID string) ([]PasskeyCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []PasskeyCredential
	for _, c := range s.m {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *MemoryPasskeyStore) UpdateSignCount(id []byte, count uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[string(id)]
	if !ok {
		return ErrNotFound
	}
	c.SignCount = count
	s.m[string(id)] = c
	return nil
}

func (s *MemoryPasskeyStore) Delete(id []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, string(id))
	return nil
}
