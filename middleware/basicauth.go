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
	"time"

	"github.com/klarlabs-studio/auth-go/domain"
)

// ErrInvalidCredentials is the verification failure an Authenticator returns
// for any bad username/password. Callers MUST return it for both an unknown
// user and a wrong password so the boundary does not leak which was wrong.
var ErrInvalidCredentials = errors.New("middleware: invalid credentials")

// Authenticator verifies basic-auth credentials and returns the identity to
// mint a session for. Implementations own credential storage and MUST verify
// the password in constant time — domain.PasswordHash.Verify does this. Return
// ErrInvalidCredentials for any authentication failure.
//
// The port deliberately lives here, in the inbound adapter, rather than in the
// domain: how a product stores and checks credentials is its concern; the
// middleware only needs the resulting identity.
type Authenticator interface {
	Authenticate(username, password string) (domain.UserID, domain.TenantID, error)
}

// AuthenticatorFunc adapts a function to the Authenticator interface.
type AuthenticatorFunc func(username, password string) (domain.UserID, domain.TenantID, error)

// Authenticate calls f.
func (f AuthenticatorFunc) Authenticate(username, password string) (domain.UserID, domain.TenantID, error) {
	return f(username, password)
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
	// Default "Restricted".
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
		uid, tid, err := m.verifier.Authenticate(user, pass)
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
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    sess.Token().String(),
		Path:     m.cookie.Path,
		Domain:   m.cookie.Domain,
		Expires:  sess.ExpiresAt(),
		MaxAge:   maxAge,
		Secure:   !m.cookie.Insecure,
		HttpOnly: true,
		SameSite: m.cookie.SameSite,
	})
}

// ClearCookie writes an expired session cookie, instructing the browser to drop
// it. Pair it with domain.SessionService.Revoke on logout.
func (m *BasicAuthMiddleware) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     m.cookie.Path,
		Domain:   m.cookie.Domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   !m.cookie.Insecure,
		HttpOnly: true,
		SameSite: m.cookie.SameSite,
	})
}

type ctxKey int

const sessionCtxKey ctxKey = iota

func withSession(ctx context.Context, sess domain.Session) context.Context {
	return context.WithValue(ctx, sessionCtxKey, sess)
}

// SessionFromContext returns the authenticated session attached by the
// middleware, and whether one was present.
func SessionFromContext(ctx context.Context) (domain.Session, bool) {
	sess, ok := ctx.Value(sessionCtxKey).(domain.Session)
	return sess, ok
}
