// Package middleware holds inbound HTTP adapters for the auth bounded context.
//
// BasicAuthMiddleware is a bootstrap-then-session handshake: it accepts an
// Authorization: Basic credential on first contact, verifies it, mints a
// server-side session, and sets the session cookie. Every subsequent request
// rides that cookie — the credential is presented once, not replayed on each
// call. This is exactly what browser SPAs need: the document load can carry
// basic-auth, but browsers do not replay those credentials on fetch(); the
// session cookie is the only thing that survives.
//
// It is an inbound adapter over the existing credential/session domain — it
// reuses domain.SessionService for the session invariants and depends on a
// caller-supplied Authenticator port for credential verification. No new
// storage, no new crypto.
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/klarlabs-studio/auth-go/domain"
)

// ErrInvalidCredentials is the verification failure an Authenticator returns
// for any bad username/password. Callers MUST return it for both an unknown
// user and a wrong password so the boundary does not leak which was wrong.
var ErrInvalidCredentials = errors.New("middleware: invalid credentials")

// ErrInvalidRealm is returned by NewBasicAuthMiddleware when Realm contains
// characters that would break or inject into the WWW-Authenticate header.
var ErrInvalidRealm = errors.New("middleware: invalid realm")

// Authenticator verifies basic-auth credentials and returns the identity to
// mint a session for. Implementations own credential storage and MUST verify
// the password in constant time — domain.PasswordHash.Verify does this. Return
// ErrInvalidCredentials for any authentication failure.
//
// The port deliberately lives here, in the inbound adapter, rather than in the
// domain: how a product stores and checks credentials is its concern; the
// middleware only needs the resulting identity. ctx carries cancellation,
// deadlines, and trace from the inbound request into credential I/O.
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (domain.UserID, domain.TenantID, error)
}

// AuthenticatorFunc adapts a function to the Authenticator interface.
type AuthenticatorFunc func(ctx context.Context, username, password string) (domain.UserID, domain.TenantID, error)

// Authenticate calls f.
func (f AuthenticatorFunc) Authenticate(ctx context.Context, username, password string) (domain.UserID, domain.TenantID, error) {
	return f(ctx, username, password)
}

// CookieOptions tunes the session cookie's attributes. The zero value is a
// secure default: Path "/", Secure, HttpOnly, SameSite=Lax.
type CookieOptions struct {
	// Path scopes the cookie. Default "/".
	Path string
	// Domain optionally scopes the cookie to a domain.
	Domain string
	// Insecure drops the Secure attribute. Development only — never set this in
	// production, as it allows the session cookie to travel over plain HTTP.
	Insecure bool
	// SameSite controls cross-site sending. Default http.SameSiteLaxMode.
	//
	// SameSite=Lax is a CSRF mitigation, not a complete defense: it stops the
	// cookie riding cross-site POST/PUT/DELETE, but same-site sub-resources and
	// top-level GET navigations still carry it. For state-changing endpoints,
	// pair this cookie with an application-layer anti-CSRF control — a
	// double-submit or synchronizer token, or an Origin/Sec-Fetch-Site check.
	// Use http.SameSiteStrictMode when no legitimate cross-site navigation needs
	// the session (it breaks inbound links that must land authenticated).
	SameSite http.SameSite
}

// BasicAuthConfig configures a BasicAuthMiddleware.
type BasicAuthConfig struct {
	// Verifier checks basic-auth credentials. Required.
	Verifier Authenticator
	// Sessions mints and validates the server-side session. Required.
	Sessions *domain.SessionService
	// Realm is the WWW-Authenticate realm presented on challenge.
	// Default "Restricted". Must not contain '"' or control characters.
	Realm string
	// CookieName is the session cookie name. Required.
	CookieName string
	// Cookie tunes the Set-Cookie attributes.
	Cookie CookieOptions
	// Now is injected for deterministic tests. Defaults to the wall clock.
	Now domain.Clock
}

// BasicAuthMiddleware turns a basic-auth credential into a session cookie on
// first contact, then authenticates subsequent requests from the cookie.
// Construct it with NewBasicAuthMiddleware.
type BasicAuthMiddleware struct {
	verifier   Authenticator
	sessions   *domain.SessionService
	realm      string
	cookieName string
	cookie     CookieOptions
	now        domain.Clock
}

// NewBasicAuthMiddleware validates the config and builds the middleware.
func NewBasicAuthMiddleware(cfg BasicAuthConfig) (*BasicAuthMiddleware, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("middleware: Verifier is required")
	}
	if cfg.Sessions == nil {
		return nil, errors.New("middleware: Sessions is required")
	}
	if cfg.CookieName == "" {
		return nil, errors.New("middleware: CookieName is required")
	}
	cookie := cfg.Cookie
	if cookie.Path == "" {
		cookie.Path = "/"
	}
	if cookie.SameSite == 0 {
		cookie.SameSite = http.SameSiteLaxMode
	}
	realm := cfg.Realm
	if realm == "" {
		realm = "Restricted"
	}
	if err := validateRealm(realm); err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = domain.SystemClock
	}
	return &BasicAuthMiddleware{
		verifier:   cfg.Verifier,
		sessions:   cfg.Sessions,
		realm:      realm,
		cookieName: cfg.CookieName,
		cookie:     cookie,
		now:        now,
	}, nil
}

// validateRealm rejects values that would break or inject into
// `WWW-Authenticate: Basic realm="…"`.
func validateRealm(realm string) error {
	if strings.ContainsRune(realm, '"') || strings.ContainsRune(realm, '\\') {
		return ErrInvalidRealm
	}
	for _, r := range realm {
		if unicode.IsControl(r) {
			return ErrInvalidRealm
		}
	}
	return nil
}

// Middleware wraps next, authenticating each request. On success the
// authenticated session is attached to the request context (SessionFromContext)
// before next runs. Requests without a valid session and without valid
// credentials get a 401 with a WWW-Authenticate: Basic challenge.
func (m *BasicAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. A valid session cookie rides through untouched.
		if sess, ok := m.sessionFromCookie(r); ok {
			next.ServeHTTP(w, r.WithContext(withSession(r.Context(), sess)))
			return
		}

		// 2. No (valid) session — try the basic-auth handshake.
		user, pass, ok := r.BasicAuth()
		if !ok {
			m.challenge(w)
			return
		}
		uid, tid, err := m.verifier.Authenticate(r.Context(), user, pass)
		if err != nil {
			// Opaque 401 regardless of why verification failed.
			m.challenge(w)
			return
		}
		sess, err := m.sessions.Issue(r.Context(), uid, tid)
		if err != nil {
			http.Error(w, "could not establish session", http.StatusInternalServerError)
			return
		}
		m.setCookie(w, sess)
		next.ServeHTTP(w, r.WithContext(withSession(r.Context(), sess)))
	})
}

// sessionFromCookie validates the session named by the cookie. Any miss
// (no cookie, malformed, unknown, expired) reports false so the caller falls
// back to the basic-auth handshake and re-bootstraps.
func (m *BasicAuthMiddleware) sessionFromCookie(r *http.Request) (domain.Session, bool) {
	c, err := r.Cookie(m.cookieName)
	if err != nil {
		return domain.Session{}, false
	}
	tok, err := domain.TokenFromString(c.Value)
	if err != nil {
		return domain.Session{}, false
	}
	sess, err := m.sessions.Validate(r.Context(), tok)
	if err != nil {
		return domain.Session{}, false
	}
	return sess, true
}

// challenge writes a 401 with a Basic auth challenge.
func (m *BasicAuthMiddleware) challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+m.realm+`", charset="UTF-8"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// setCookie emits the session cookie, expiring it in lockstep with the session.
func (m *BasicAuthMiddleware) setCookie(w http.ResponseWriter, sess domain.Session) {
	maxAge := max(int(sess.ExpiresAt().Sub(m.now()).Seconds()), 1)
	// Secure defaults to true; CookieOptions.Insecure is an explicit local-dev
	// opt-out. gosec G124 cannot see through the boolean expression.
	c := &http.Cookie{ //nolint:gosec // G124: Secure true by default; Insecure is documented opt-out
		Name:     m.cookieName,
		Value:    sess.Token().String(),
		Path:     m.cookie.Path,
		Domain:   m.cookie.Domain,
		Expires:  sess.ExpiresAt(),
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: m.cookie.SameSite,
	}
	if m.cookie.Insecure {
		c.Secure = false
	}
	http.SetCookie(w, c)
}

// ClearCookie writes an expired session cookie, instructing the browser to drop
// it. Pair it with domain.SessionService.Revoke on logout — or use Logout, which
// revokes from the request cookie and clears in one step.
func (m *BasicAuthMiddleware) ClearCookie(w http.ResponseWriter) {
	c := &http.Cookie{ //nolint:gosec // G124: Secure true by default; Insecure is documented opt-out
		Name:     m.cookieName,
		Value:    "",
		Path:     m.cookie.Path,
		Domain:   m.cookie.Domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: m.cookie.SameSite,
	}
	if m.cookie.Insecure {
		c.Secure = false
	}
	http.SetCookie(w, c)
}

// Logout revokes the session named by the request's session cookie (if present
// and well-formed) and clears the cookie. Prefer this over
// Revoke(sess.Token()) after Validate — a validated Session does not carry the
// raw cookie value, so that pattern is a silent no-op.
func (m *BasicAuthMiddleware) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(m.cookieName); err == nil {
		if tok, err := domain.TokenFromString(c.Value); err == nil {
			_ = m.sessions.Revoke(r.Context(), tok)
		}
	}
	m.ClearCookie(w)
}

type ctxKey int

const sessionCtxKey ctxKey = iota

func withSession(ctx context.Context, sess domain.Session) context.Context {
	return context.WithValue(ctx, sessionCtxKey, sess)
}

// SessionFromContext returns the authenticated session attached by the
// middleware, and whether one was present. The Session's Token() is only set
// immediately after a Basic handshake (Issue); on cookie-authenticated
// requests it is zero — use Logout or Revoke with the cookie value to log out.
func SessionFromContext(ctx context.Context) (domain.Session, bool) {
	sess, ok := ctx.Value(sessionCtxKey).(domain.Session)
	return sess, ok
}
