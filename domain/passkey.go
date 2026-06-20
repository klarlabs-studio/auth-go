package domain

import "context"

// PasskeyCredential is an entity: a stored WebAuthn credential bound to a user.
// Identity is its credential ID.
type PasskeyCredential struct {
	ID        []byte // credential ID (identity)
	UserID    UserID
	PublicKey []byte
	SignCount uint32
	Name      string // user-facing label ("MacBook Touch ID")
}

// WithSignCount returns a copy with the sign count advanced — used after a
// successful assertion to detect cloned authenticators.
func (c PasskeyCredential) WithSignCount(n uint32) PasskeyCredential {
	c.SignCount = n
	return c
}

// PasskeyRepository is the persistence port for passkey credentials. Every
// method takes a context.Context first so storage I/O honors cancellation,
// deadlines, and trace propagation.
type PasskeyRepository interface {
	Add(ctx context.Context, c PasskeyCredential) error
	ListByUser(ctx context.Context, userID UserID) ([]PasskeyCredential, error)
	UpdateSignCount(ctx context.Context, id []byte, count uint32) error
	Delete(ctx context.Context, id []byte) error
}

// PasskeyAuthenticator is the port for the WebAuthn ceremony engine,
// implemented by adapters/webauthn. Opaque byte blobs are the JSON
// challenge/response payloads exchanged with navigator.credentials. Each
// ceremony method takes a context.Context first because it loads/advances the
// user's credentials through a PasskeyRepository, so the storage I/O honors
// cancellation, deadlines, and trace propagation.
type PasskeyAuthenticator interface {
	BeginRegistration(ctx context.Context, userID UserID, displayName string) (options []byte, state []byte, err error)
	FinishRegistration(ctx context.Context, state []byte, response []byte) (PasskeyCredential, error)
	BeginLogin(ctx context.Context, userID UserID) (options []byte, state []byte, err error)
	FinishLogin(ctx context.Context, state []byte, response []byte) (credentialID []byte, err error)
}
