package authgo

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
