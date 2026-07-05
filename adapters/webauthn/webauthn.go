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
	"time"

	"github.com/klarlabs-studio/auth-go/domain"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ErrNoPasskeys is returned when a login is begun for a user with no
// registered credentials.
var ErrNoPasskeys = errors.New("authgo/webauthn: user has no passkeys")

// ErrCredentialCloned is returned by FinishLogin when the authenticator's
// signature counter did not advance (it regressed or repeated). Per the
// WebAuthn spec this is a signal that at least two copies of the credential
// private key exist and are being used in parallel — i.e. the authenticator
// may have been cloned. The login is rejected and the stored sign count is
// left untouched.
var ErrCredentialCloned = errors.New("authgo/webauthn: credential sign count regressed; authenticator may be cloned")

// defaultCeremonyTimeout bounds how long a registration or login ceremony may
// stay outstanding before its challenge expires. It is enforced server-side
// (see New) so a stale challenge cannot be replayed indefinitely.
const (
	defaultCeremonyTimeout    = 5 * time.Minute
	defaultCeremonyTimeoutUVD = 2 * time.Minute // user-verification "discouraged"
)

// Ceremony state security requirement
//
// The opaque `state` blob returned by BeginRegistration and BeginLogin is the
// serialized WebAuthn session: it carries the ceremony challenge AND the
// UserID, and Finish* trusts the UserID it reads back out of that blob. The
// blob is NOT integrity-protected (it is plain JSON, neither signed nor
// encrypted).
//
// It MUST therefore be:
//   - stored server-side (e.g. in the session store keyed by the browser
//     session), never round-tripped through the client;
//   - kept secret (it contains the live challenge);
//   - used exactly once (delete it as soon as Finish* is called, whether or
//     not it succeeds).
//
// If the state is ever accepted back from the client unsigned, an attacker can
// substitute an arbitrary UserID and complete a ceremony as another user.

// Config configures the relying party (your app).
type Config struct {
	RPDisplayName string   // "Klarlabs"
	RPID          string   // registrable domain, "klarlabs.de"
	RPOrigins     []string // allowed origins, "https://app.klarlabs.de"

	// UserVerification controls whether the authenticator must verify the user
	// (biometric, PIN, ...) — not merely confirm presence — during login and
	// registration. It defaults to protocol.VerificationRequired when empty,
	// which is the correct default for passwordless passkeys: a presence-only
	// authenticator must not satisfy the factor. Set it to
	// protocol.VerificationPreferred or protocol.VerificationDiscouraged only
	// if you are deliberately using passkeys as a non-passwordless second
	// factor where UV is not needed.
	UserVerification protocol.UserVerificationRequirement
}

// Authenticator implements domain.PasskeyAuthenticator over go-webauthn,
// loading a user's existing credentials from a domain.PasskeyRepository.
type Authenticator struct {
	wa   *webauthn.WebAuthn
	repo domain.PasskeyRepository
	uv   protocol.UserVerificationRequirement
}

// New builds an Authenticator. The repository supplies a user's existing
// credentials during login ceremonies.
func New(cfg Config, repo domain.PasskeyRepository) (*Authenticator, error) {
	uv := cfg.UserVerification
	if uv == "" {
		uv = protocol.VerificationRequired
	}
	// Enforce challenge expiry server-side. Without Enforce the library sets no
	// session.Expires and never times a ceremony out, so a leaked/stale
	// challenge could be replayed indefinitely.
	timeouts := webauthn.TimeoutConfig{
		Enforce:    true,
		Timeout:    defaultCeremonyTimeout,
		TimeoutUVD: defaultCeremonyTimeoutUVD,
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        timeouts,
			Registration: timeouts,
		},
	})
	if err != nil {
		return nil, err
	}
	return &Authenticator{wa: wa, repo: repo, uv: uv}, nil
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
// navigator.credentials.create and opaque state.
//
// SECURITY: the returned state is a secret, single-use, integrity-unprotected
// session blob (challenge + UserID). It MUST be stored server-side and never
// round-tripped through the client. See the "Ceremony state security
// requirement" note above.
func (a *Authenticator) BeginRegistration(ctx context.Context, userID domain.UserID, displayName string) (options, state []byte, err error) {
	user, err := a.loadUser(ctx, userID, displayName)
	if err != nil {
		return nil, nil, err
	}
	creation, session, err := a.wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			UserVerification: a.uv,
		}),
	)
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
//
// SECURITY: state must be the exact blob produced by BeginRegistration, read
// from trusted server-side storage and used once. It is not integrity-
// protected — the UserID is trusted verbatim — so it must never be accepted
// from the client. See the "Ceremony state security requirement" note above.
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
//
// SECURITY: the returned state is a secret, single-use, integrity-unprotected
// session blob (challenge + UserID). It MUST be stored server-side and never
// round-tripped through the client. See the "Ceremony state security
// requirement" note above.
func (a *Authenticator) BeginLogin(ctx context.Context, userID domain.UserID) (options, state []byte, err error) {
	user, err := a.loadUser(ctx, userID, "")
	if err != nil {
		return nil, nil, err
	}
	if len(user.creds) == 0 {
		return nil, nil, ErrNoPasskeys
	}
	assertion, session, err := a.wa.BeginLogin(user,
		webauthn.WithUserVerification(a.uv),
	)
	if err != nil {
		return nil, nil, err
	}
	return marshalPair(assertion, session)
}

// FinishLogin verifies the assertion, advances the stored sign count, and
// returns the credential ID that signed. If the authenticator's signature
// counter did not advance it returns ErrCredentialCloned and leaves the stored
// sign count unchanged.
//
// SECURITY: state must be the exact blob produced by BeginLogin, read from
// trusted server-side storage and used once. It is not integrity-protected —
// the UserID is trusted verbatim — so it must never be accepted from the
// client. See the "Ceremony state security requirement" note above.
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
	// A cloned authenticator is the whole reason SignCount is persisted: if the
	// counter did not advance, reject the login and do NOT overwrite the stored
	// count (overwriting would erase the evidence and let the clone in).
	if cred.Authenticator.CloneWarning {
		return nil, ErrCredentialCloned
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
