package domain

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

// PasskeyRepository is the persistence port for passkey credentials.
type PasskeyRepository interface {
	Add(c PasskeyCredential) error
	ListByUser(userID UserID) ([]PasskeyCredential, error)
	UpdateSignCount(id []byte, count uint32) error
	Delete(id []byte) error
}

// PasskeyAuthenticator is the port for the WebAuthn ceremony engine,
// implemented by adapters/webauthn. Opaque byte blobs are the JSON
// challenge/response payloads exchanged with navigator.credentials.
type PasskeyAuthenticator interface {
	BeginRegistration(userID UserID, displayName string) (options []byte, state []byte, err error)
	FinishRegistration(state []byte, response []byte) (PasskeyCredential, error)
	BeginLogin(userID UserID) (options []byte, state []byte, err error)
	FinishLogin(state []byte, response []byte) (credentialID []byte, err error)
}
