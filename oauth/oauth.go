// Package oauth is the relying-party side of a browser sign-in through an
// OAuth 2.0 provider: the authorization code flow with state and PKCE
// (RFC 7636, S256), and the provider profile that turns the granted access
// token into a verified identity. GitHub is the provider implemented
// (NewGitHub); the flow pieces here are provider-neutral.
//
// A sign-in has two legs. Begin mints a LoginState — a random state value
// and a PKCE verifier — and the URL to send the browser to. The product
// seals the LoginState into a short-lived HttpOnly cookie with a
// StateSealer (AES-256-GCM: the verifier stays secret, the cookie cannot be
// forged or altered) and redirects. On the callback, Open checks the cookie
// against the state the provider echoed (constant time, with an expiry), and
// Complete exchanges the code with the verifier and reads the identity.
//
// stdlib only. Requests go over HTTPS (AllowInsecureHTTPHosts for tests),
// redirects are not followed, and every response is capped at
// MaxResponseBytes. The provider's access token is used for the identity
// reads and then dropped: it is never returned, stored or logged.
package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// Errors. Callers match with errors.Is; every one means "not signed in".
var (
	// ErrInvalidConfig is returned by constructors for an unusable config.
	ErrInvalidConfig = errors.New("oauth: invalid config")
	// ErrState: the callback's state is missing, does not match the sealed
	// login state, or the login state is forged, altered or expired. A
	// cross-site request forgery or a replayed callback ends here.
	ErrState = errors.New("oauth: state mismatch or expired")
	// ErrDenied: the person declined at the provider (error=access_denied
	// on the callback).
	ErrDenied = errors.New("oauth: authorization denied")
	// ErrExchange: the token endpoint refused the code (expired, used,
	// wrong verifier or redirect URI).
	ErrExchange = errors.New("oauth: code exchange refused")
	// ErrUnverifiedEmail: the account has no verified primary e-mail
	// address, so it cannot be identified by one.
	ErrUnverifiedEmail = errors.New("oauth: no verified primary e-mail")
	// ErrProvider: the provider could not be reached or answered with
	// something unexpected.
	ErrProvider = errors.New("oauth: provider error")
)

// MaxResponseBytes caps every response read from a provider.
const MaxResponseBytes = 1 << 20

// DefaultStateTTL is how long a login state is accepted after Begin.
const DefaultStateTTL = 10 * time.Minute

// LoginState is what one sign-in attempt must remember between leaving for
// the provider and coming back: the state value the provider echoes, the
// PKCE verifier, and an optional product-chosen value (for example where
// to send the browser afterwards, or an intent such as "link"). It is
// sealed into a cookie, never sent to the provider whole.
type LoginState struct {
	State    string    `json:"s"`
	Verifier string    `json:"v"`
	Extra    string    `json:"x,omitempty"`
	IssuedAt time.Time `json:"t"`
}

// randomString is 32 random bytes as unpadded base64url (43 characters),
// within RFC 7636's 43..128 verifier length.
func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewLoginState mints a state value and a PKCE verifier.
func NewLoginState(extra string, now time.Time) (LoginState, error) {
	st, err := randomString()
	if err != nil {
		return LoginState{}, err
	}
	v, err := randomString()
	if err != nil {
		return LoginState{}, err
	}
	return LoginState{State: st, Verifier: v, Extra: extra, IssuedAt: now.UTC()}, nil
}

// PKCEChallenge is the S256 code challenge for verifier (RFC 7636 §4.2).
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// StateSealer seals a LoginState into a cookie value and opens it again.
// AES-256-GCM keeps the PKCE verifier secret and makes the cookie
// tamper-evident; the expiry bounds how long a callback is accepted.
type StateSealer struct {
	aead cipher.AEAD
	ttl  time.Duration
}

// NewStateSealer builds a sealer from a 32-byte key (keep it with the
// product's other secrets; rotating it only fails sign-ins in flight). A
// zero ttl means DefaultStateTTL.
func NewStateSealer(key []byte, ttl time.Duration) (*StateSealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: state key must be 32 bytes", ErrInvalidConfig)
	}
	if ttl < 0 {
		return nil, fmt.Errorf("%w: negative state TTL", ErrInvalidConfig)
	}
	if ttl == 0 {
		ttl = DefaultStateTTL
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return &StateSealer{aead: aead, ttl: ttl}, nil
}

// TTL is how long a sealed state is accepted; use it as the cookie's
// Max-Age.
func (s *StateSealer) TTL() time.Duration { return s.ttl }

// sealedAAD binds a sealed value to this use, so a value sealed with the
// same key for another purpose does not open here.
var sealedAAD = []byte("auth-go/oauth login state v1")

// Seal encrypts st for a cookie: unpadded base64url of nonce || ciphertext.
func (s *StateSealer) Seal(st LoginState) (string, error) {
	plain, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := s.aead.Seal(nonce, nonce, plain, sealedAAD)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// maxSealedLen bounds a cookie value Open will decode.
const maxSealedLen = 4096

// Open decrypts a sealed cookie value and checks it against the state the
// provider echoed on the callback and the expiry. Any failure is ErrState.
func (s *StateSealer) Open(sealed, state string, now time.Time) (LoginState, error) {
	if sealed == "" || state == "" || len(sealed) > maxSealedLen {
		return LoginState{}, ErrState
	}
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return LoginState{}, ErrState
	}
	ns := s.aead.NonceSize()
	plain, err := s.aead.Open(nil, raw[:ns], raw[ns:], sealedAAD)
	if err != nil {
		return LoginState{}, ErrState
	}
	var st LoginState
	if err := json.Unmarshal(plain, &st); err != nil || st.State == "" || st.Verifier == "" {
		return LoginState{}, ErrState
	}
	if subtle.ConstantTimeCompare([]byte(st.State), []byte(state)) != 1 {
		return LoginState{}, ErrState
	}
	if now.Before(st.IssuedAt.Add(-time.Minute)) || !now.Before(st.IssuedAt.Add(s.ttl)) {
		return LoginState{}, ErrState
	}
	return st, nil
}

// CallbackError reads a provider's error redirect (RFC 6749 §4.1.2.1):
// ErrDenied for access_denied, ErrProvider for any other error, nil when
// the callback carries none.
func CallbackError(q url.Values) error {
	switch e := q.Get("error"); e {
	case "":
		return nil
	case "access_denied":
		return ErrDenied
	default:
		return fmt.Errorf("%w: %s", ErrProvider, e)
	}
}

// urlPolicy admits https URLs, and http only for the named hosts.
type urlPolicy struct{ insecureHosts []string }

func (p urlPolicy) check(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Host == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("%q is not an absolute URL without credentials or fragment", raw)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if slices.Contains(p.insecureHosts, u.Hostname()) {
			return u, nil
		}
	}
	return nil, fmt.Errorf("%q must use https", raw)
}

// defaultHTTPTimeout bounds each provider request made with the default
// client.
const defaultHTTPTimeout = 15 * time.Second

func noRedirectClient(c *http.Client) *http.Client {
	var cp http.Client
	if c != nil {
		cp = *c
	} else {
		cp.Timeout = defaultHTTPTimeout
	}
	cp.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not followed")
	}
	return &cp
}
