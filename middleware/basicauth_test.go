package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/adapters/memory"
	"github.com/klarlabs-studio/auth-go/domain"
	"github.com/klarlabs-studio/auth-go/middleware"
)

// fixedAuthenticator accepts one credential pair and maps it to an identity.
func fixedAuthenticator(t *testing.T, wantUser, wantPass, uid, tid string) middleware.Authenticator {
	t.Helper()
	u, err := domain.NewUserID(uid)
	if err != nil {
		t.Fatalf("user id: %v", err)
	}
	ti, err := domain.NewTenantID(tid)
	if err != nil {
		t.Fatalf("tenant id: %v", err)
	}
	return middleware.AuthenticatorFunc(func(ctx context.Context, user, pass string) (domain.UserID, domain.TenantID, error) {
		if user != wantUser || pass != wantPass {
			return domain.UserID{}, domain.TenantID{}, middleware.ErrInvalidCredentials
		}
		return u, ti, nil
	})
}

// newMW builds a middleware over an in-memory session store with a fixed clock.
func newMW(t *testing.T, auth middleware.Authenticator, now *time.Time) *middleware.BasicAuthMiddleware {
	t.Helper()
	sessions := domain.NewSessionService(memory.NewSessionRepo(), time.Hour, func() time.Time { return *now })
	mw, err := middleware.NewBasicAuthMiddleware(middleware.BasicAuthConfig{
		Verifier:   auth,
		Sessions:   sessions,
		Realm:      "test",
		CookieName: "sid",
		Now:        func() time.Time { return *now },
	})
	if err != nil {
		t.Fatalf("build middleware: %v", err)
	}
	return mw
}

// probe is a terminal handler that records whether it ran and the session it saw.
func probe(seen *bool, gotSession *domain.Session) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = true
		if s, ok := middleware.SessionFromContext(r.Context()); ok {
			*gotSession = s
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestNewBasicAuthMiddleware_RequiredFields(t *testing.T) {
	sessions := domain.NewSessionService(memory.NewSessionRepo(), time.Hour, nil)
	auth := middleware.AuthenticatorFunc(func(context.Context, string, string) (domain.UserID, domain.TenantID, error) {
		return domain.UserID{}, domain.TenantID{}, nil
	})
	tests := []struct {
		name string
		cfg  middleware.BasicAuthConfig
	}{
		{"no verifier", middleware.BasicAuthConfig{Sessions: sessions, CookieName: "sid"}},
		{"no sessions", middleware.BasicAuthConfig{Verifier: auth, CookieName: "sid"}},
		{"no cookie name", middleware.BasicAuthConfig{Verifier: auth, Sessions: sessions}},
		{"bad realm", middleware.BasicAuthConfig{Verifier: auth, Sessions: sessions, CookieName: "sid", Realm: `evil"realm`}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := middleware.NewBasicAuthMiddleware(tc.cfg); err == nil {
				t.Fatal("want error for missing required field")
			}
		})
	}
}

func TestBasicAuth_HandshakeMintsSessionAndCookie(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	mw := newMW(t, fixedAuthenticator(t, "admin", "s3cret", "user-1", "tenant-1"), &now)

	var seen bool
	var got domain.Session
	h := mw.Middleware(probe(&seen, &got))

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.SetBasicAuth("admin", "s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !seen {
		t.Fatal("next handler did not run")
	}
	if got.UserID().String() != "user-1" || got.TenantID().String() != "tenant-1" {
		t.Fatalf("context session identity = %s/%s", got.UserID(), got.TenantID())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("want 1 Set-Cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != "sid" || c.Value == "" {
		t.Fatalf("unexpected cookie %+v", c)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie security attrs wrong: HttpOnly=%v Secure=%v SameSite=%v", c.HttpOnly, c.Secure, c.SameSite)
	}
	if c.Value != got.Token().String() {
		t.Fatal("cookie value must be the session token")
	}
}

func TestBasicAuth_SubsequentRequestUsesCookieNotCredentials(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	mw := newMW(t, fixedAuthenticator(t, "admin", "s3cret", "user-1", "tenant-1"), &now)

	// Handshake to obtain the cookie.
	var seen bool
	var got domain.Session
	h := mw.Middleware(probe(&seen, &got))
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.SetBasicAuth("admin", "s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	cookie := rec.Result().Cookies()[0]

	// Second request: cookie only, NO Authorization header.
	seen = false
	req2 := httptest.NewRequest(http.MethodGet, "/ui/data", nil)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK || !seen {
		t.Fatalf("cookie request rejected: status=%d ran=%v", rec2.Code, seen)
	}
	if len(rec2.Result().Cookies()) != 0 {
		t.Fatal("no new cookie should be minted when riding an existing session")
	}
	if got.UserID().String() != "user-1" {
		t.Fatalf("session identity lost: %s", got.UserID())
	}
	if got.Token().String() != "" {
		t.Fatal("cookie-authenticated Session.Token() must be empty (raw is only on Issue)")
	}
}

func TestBasicAuth_NoCredentialsChallenges(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	mw := newMW(t, fixedAuthenticator(t, "admin", "s3cret", "u", "t"), &now)

	var seen bool
	var got domain.Session
	h := mw.Middleware(probe(&seen, &got))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if seen {
		t.Fatal("next handler must not run unauthenticated")
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="test", charset="UTF-8"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
}

func TestBasicAuth_BadCredentialsChallengeNoCookie(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	mw := newMW(t, fixedAuthenticator(t, "admin", "s3cret", "u", "t"), &now)

	var seen bool
	var got domain.Session
	h := mw.Middleware(probe(&seen, &got))
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.SetBasicAuth("admin", "wrong")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if seen {
		t.Fatal("next handler must not run on bad credentials")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("no cookie on failed auth")
	}
}

func TestBasicAuth_ExpiredCookieReBootstrapsViaCredentials(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	mw := newMW(t, fixedAuthenticator(t, "admin", "s3cret", "user-1", "tenant-1"), &now)

	var seen bool
	var got domain.Session
	h := mw.Middleware(probe(&seen, &got))

	// Handshake.
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.SetBasicAuth("admin", "s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	cookie := rec.Result().Cookies()[0]
	firstToken := cookie.Value

	// Advance past the session TTL: the cookie is now stale.
	now = now.Add(2 * time.Hour)

	// Stale cookie alone → challenge.
	seen = false
	req2 := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized || seen {
		t.Fatalf("stale cookie should challenge: status=%d ran=%v", rec2.Code, seen)
	}

	// Stale cookie + valid credentials → fresh session minted.
	seen = false
	req3 := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req3.AddCookie(cookie)
	req3.SetBasicAuth("admin", "s3cret")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK || !seen {
		t.Fatalf("re-bootstrap failed: status=%d ran=%v", rec3.Code, seen)
	}
	fresh := rec3.Result().Cookies()
	if len(fresh) != 1 || fresh[0].Value == firstToken {
		t.Fatal("expected a new session token after re-bootstrap")
	}
}

func TestBasicAuth_InsecureCookieOption(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	sessions := domain.NewSessionService(memory.NewSessionRepo(), time.Hour, func() time.Time { return now })
	mw, err := middleware.NewBasicAuthMiddleware(middleware.BasicAuthConfig{
		Verifier:   fixedAuthenticator(t, "admin", "s3cret", "u", "t"),
		Sessions:   sessions,
		CookieName: "sid",
		Cookie:     middleware.CookieOptions{Insecure: true, SameSite: http.SameSiteStrictMode},
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h := mw.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	c := rec.Result().Cookies()[0]
	if c.Secure {
		t.Fatal("Insecure option should drop Secure attribute")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("SameSite = %v, want Strict", c.SameSite)
	}
}

func TestBasicAuth_ClearCookie(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	mw := newMW(t, fixedAuthenticator(t, "a", "b", "u", "t"), &now)
	rec := httptest.NewRecorder()
	mw.ClearCookie(rec)
	c := rec.Result().Cookies()[0]
	if c.MaxAge >= 0 {
		t.Fatalf("ClearCookie MaxAge = %d, want negative", c.MaxAge)
	}
	if c.Value != "" {
		t.Fatal("ClearCookie value must be empty")
	}
}

func TestBasicAuth_LogoutRevokesFromCookie(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	sessions := domain.NewSessionService(memory.NewSessionRepo(), time.Hour, func() time.Time { return now })
	mw, err := middleware.NewBasicAuthMiddleware(middleware.BasicAuthConfig{
		Verifier:   fixedAuthenticator(t, "admin", "s3cret", "user-1", "tenant-1"),
		Sessions:   sessions,
		CookieName: "sid",
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	var seen bool
	var got domain.Session
	h := mw.Middleware(probe(&seen, &got))
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.SetBasicAuth("admin", "s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	cookie := rec.Result().Cookies()[0]
	raw, err := domain.TokenFromString(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}

	// Logout with the cookie: session revoked + cookie cleared.
	req2 := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	mw.Logout(rec2, req2)
	if _, err := sessions.Validate(context.Background(), raw); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("session survived Logout: %v", err)
	}
	cleared := rec2.Result().Cookies()[0]
	if cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Fatalf("Logout must clear cookie, got %+v", cleared)
	}

	// Cookie alone no longer authenticates.
	seen = false
	req3 := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req3.AddCookie(cookie)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized || seen {
		t.Fatalf("post-logout cookie should challenge: status=%d ran=%v", rec3.Code, seen)
	}
}
