// Package webauthn is the passkey adapter for auth-go. It wraps
// github.com/go-webauthn/webauthn and implements authgo.PasskeyAuthenticator,
// so the auth-go core stays dependency-light — only products that want
// passkeys import this subpackage and pull the WebAuthn dependency.
package webauthn

import (
	"bytes"
	"encoding/json"
	"errors"

	authgo "github.com/klarlabs-studio/auth-go"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Config configures the relying party (your app).
type Config struct {
	// RPDisplayName is shown to users ("Klarlabs").
	RPDisplayName string
	// RPID is the registrable domain ("klarlabs.de").
	RPID string
	// RPOrigins are the allowed origins ("https://app.klarlabs.de").
	RPOrigins []string
}

// Authenticator implements authgo.PasskeyAuthenticator over go-webauthn,
// loading a user's existing credentials from an authgo.PasskeyStore.
type Authenticator struct {
	wa    *webauthn.WebAuthn
	store authgo.PasskeyStore
}

// New builds an Authenticator. The store supplies a user's existing
// credentials during login ceremonies.
func New(cfg Config, store authgo.PasskeyStore) (*Authenticator, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, err
	}
	return &Authenticator{wa: wa, store: store}, nil
}

// waUser adapts a Klarlabs user + its stored credentials to webauthn.User.
type waUser struct {
	id          []byte
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.id }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// loadUser builds a webauthn.User for userID, hydrating stored credentials.
func (a *Authenticator) loadUser(userID, displayName string) (*waUser, error) {
	stored, err := a.store.ListByUser(userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		creds = append(creds, webauthn.Credential{
			ID:        c.ID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
		})
	}
	name := displayName
	if name == "" {
		name = userID
	}
	return &waUser{id: []byte(userID), name: name, displayName: name, creds: creds}, nil
}

// BeginRegistration starts enrolling a new passkey. Returns JSON options for
// navigator.credentials.create and an opaque state to round-trip.
func (a *Authenticator) BeginRegistration(userID, displayName string) (options []byte, state []byte, err error) {
	user, err := a.loadUser(userID, displayName)
	if err != nil {
		return nil, nil, err
	}
	creation, session, err := a.wa.BeginRegistration(user)
	if err != nil {
		return nil, nil, err
	}
	options, err = json.Marshal(creation)
	if err != nil {
		return nil, nil, err
	}
	state, err = json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return options, state, nil
}

// FinishRegistration verifies the browser response and returns the credential
// to persist via PasskeyStore.Add.
func (a *Authenticator) FinishRegistration(state []byte, response []byte) (authgo.PasskeyCredential, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal(state, &session); err != nil {
		return authgo.PasskeyCredential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(response))
	if err != nil {
		return authgo.PasskeyCredential{}, err
	}
	// Registration verifies against the challenge in session; existing creds unneeded.
	user := &waUser{id: session.UserID, name: string(session.UserID), displayName: string(session.UserID)}
	cred, err := a.wa.CreateCredential(user, session, parsed)
	if err != nil {
		return authgo.PasskeyCredential{}, err
	}
	return authgo.PasskeyCredential{
		ID:        cred.ID,
		UserID:    string(session.UserID),
		PublicKey: cred.PublicKey,
		SignCount: cred.Authenticator.SignCount,
	}, nil
}

// BeginLogin starts an assertion for a user's known credentials.
func (a *Authenticator) BeginLogin(userID string) (options []byte, state []byte, err error) {
	user, err := a.loadUser(userID, "")
	if err != nil {
		return nil, nil, err
	}
	if len(user.creds) == 0 {
		return nil, nil, errors.New("authgo/webauthn: user has no passkeys")
	}
	assertion, session, err := a.wa.BeginLogin(user)
	if err != nil {
		return nil, nil, err
	}
	options, err = json.Marshal(assertion)
	if err != nil {
		return nil, nil, err
	}
	state, err = json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return options, state, nil
}

// FinishLogin verifies the assertion, updates the stored sign count, and
// returns the credential ID that signed.
func (a *Authenticator) FinishLogin(state []byte, response []byte) (credentialID []byte, err error) {
	var session webauthn.SessionData
	if err := json.Unmarshal(state, &session); err != nil {
		return nil, err
	}
	user, err := a.loadUser(string(session.UserID), "")
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(response))
	if err != nil {
		return nil, err
	}
	cred, err := a.wa.ValidateLogin(user, session, parsed)
	if err != nil {
		return nil, err
	}
	// Persist the advanced sign count to detect cloned authenticators.
	if err := a.store.UpdateSignCount(cred.ID, cred.Authenticator.SignCount); err != nil {
		return nil, err
	}
	return cred.ID, nil
}

// compile-time guarantee the adapter satisfies the core interface.
var _ authgo.PasskeyAuthenticator = (*Authenticator)(nil)
