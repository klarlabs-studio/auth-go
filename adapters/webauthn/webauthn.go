// Package webauthn is the passkey adapter — it implements
// domain.PasskeyAuthenticator over github.com/go-webauthn/webauthn. Kept as an
// adapter so the domain and the dependency-light core stay free of the
// WebAuthn dependency; only products that enable passkeys import this package.
package webauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/klarlabs-studio/auth-go/domain"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ErrNoPasskeys is returned when a login is begun for a user with no
// registered credentials.
var ErrNoPasskeys = errors.New("authgo/webauthn: user has no passkeys")

// Config configures the relying party (your app).
type Config struct {
	RPDisplayName string   // "Klarlabs"
	RPID          string   // registrable domain, "klarlabs.de"
	RPOrigins     []string // allowed origins, "https://app.klarlabs.de"
}

// Authenticator implements domain.PasskeyAuthenticator over go-webauthn,
// loading a user's existing credentials from a domain.PasskeyRepository.
type Authenticator struct {
	wa   *webauthn.WebAuthn
	repo domain.PasskeyRepository
}

// New builds an Authenticator. The repository supplies a user's existing
// credentials during login ceremonies.
func New(cfg Config, repo domain.PasskeyRepository) (*Authenticator, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, err
	}
	return &Authenticator{wa: wa, repo: repo}, nil
}

// waUser adapts a domain user + its stored credentials to webauthn.User.
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

func (a *Authenticator) loadUser(ctx context.Context, userID domain.UserID, displayName string) (*waUser, error) {
	stored, err := a.repo.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		creds = append(creds, webauthn.Credential{
			ID:            c.ID,
			PublicKey:     c.PublicKey,
			Authenticator: webauthn.Authenticator{SignCount: c.SignCount},
		})
	}
	name := displayName
	if name == "" {
		name = userID.String()
	}
	return &waUser{id: []byte(userID.String()), name: name, displayName: name, creds: creds}, nil
}

// BeginRegistration starts enrolling a new passkey, returning JSON options for
// navigator.credentials.create and opaque state to round-trip.
func (a *Authenticator) BeginRegistration(ctx context.Context, userID domain.UserID, displayName string) (options, state []byte, err error) {
	user, err := a.loadUser(ctx, userID, displayName)
	if err != nil {
		return nil, nil, err
	}
	creation, session, err := a.wa.BeginRegistration(user)
	if err != nil {
		return nil, nil, err
	}
	return marshalPair(creation, session)
}

// FinishRegistration verifies the browser response and returns the credential
// to persist via PasskeyRepository.Add.
// The context is accepted to satisfy the port and keep the ceremony signatures
// uniform; this step does no storage I/O (it only verifies the browser
// response), so ctx is currently unused here.
func (a *Authenticator) FinishRegistration(_ context.Context, state, response []byte) (domain.PasskeyCredential, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal(state, &session); err != nil {
		return domain.PasskeyCredential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(response))
	if err != nil {
		return domain.PasskeyCredential{}, err
	}
	user := &waUser{id: session.UserID, name: string(session.UserID), displayName: string(session.UserID)}
	cred, err := a.wa.CreateCredential(user, session, parsed)
	if err != nil {
		return domain.PasskeyCredential{}, err
	}
	uid, err := domain.NewUserID(string(session.UserID))
	if err != nil {
		return domain.PasskeyCredential{}, err
	}
	return domain.PasskeyCredential{
		ID:        cred.ID,
		UserID:    uid,
		PublicKey: cred.PublicKey,
		SignCount: cred.Authenticator.SignCount,
	}, nil
}

// BeginLogin starts an assertion for a user's known credentials.
func (a *Authenticator) BeginLogin(ctx context.Context, userID domain.UserID) (options, state []byte, err error) {
	user, err := a.loadUser(ctx, userID, "")
	if err != nil {
		return nil, nil, err
	}
	if len(user.creds) == 0 {
		return nil, nil, ErrNoPasskeys
	}
	assertion, session, err := a.wa.BeginLogin(user)
	if err != nil {
		return nil, nil, err
	}
	return marshalPair(assertion, session)
}

// FinishLogin verifies the assertion, advances the stored sign count, and
// returns the credential ID that signed.
func (a *Authenticator) FinishLogin(ctx context.Context, state, response []byte) (credentialID []byte, err error) {
	var session webauthn.SessionData
	if err := json.Unmarshal(state, &session); err != nil {
		return nil, err
	}
	uid, err := domain.NewUserID(string(session.UserID))
	if err != nil {
		return nil, err
	}
	user, err := a.loadUser(ctx, uid, "")
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
	if err := a.repo.UpdateSignCount(ctx, cred.ID, cred.Authenticator.SignCount); err != nil {
		return nil, err
	}
	return cred.ID, nil
}

func marshalPair(options, state any) ([]byte, []byte, error) {
	o, err := json.Marshal(options)
	if err != nil {
		return nil, nil, err
	}
	s, err := json.Marshal(state)
	if err != nil {
		return nil, nil, err
	}
	return o, s, nil
}

var _ domain.PasskeyAuthenticator = (*Authenticator)(nil)
