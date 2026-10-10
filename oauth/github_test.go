package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGitHub is GitHub's token endpoint and the two API reads, checking
// what a real one checks: the client, the code, the redirect and the PKCE
// verifier against the challenge sent to authorize.
type fakeGitHub struct {
	mu        sync.Mutex
	challenge string // from the authorize URL
	code      string
	used      bool
	emails    string
	user      string
	tokenBody string // overrides the token answer
	userCode  int
	seenAuth  []string
}

const (
	fakeClientID     = "Iv1.client"
	fakeClientSecret = "secret-value"
	fakeAccessToken  = "gho_fake_access_token"
)

func (f *fakeGitHub) handler(t *testing.T, redirect string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("token request Accept %q", r.Header.Get("Accept"))
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if f.tokenBody != "" {
			_, _ = w.Write([]byte(f.tokenBody))
			return
		}
		switch {
		case r.PostForm.Get("client_id") != fakeClientID || r.PostForm.Get("client_secret") != fakeClientSecret:
			_, _ = w.Write([]byte(`{"error":"incorrect_client_credentials"}`))
		case r.PostForm.Get("redirect_uri") != redirect:
			_, _ = w.Write([]byte(`{"error":"redirect_uri_mismatch"}`))
		case r.PostForm.Get("code") != f.code || f.used:
			_, _ = w.Write([]byte(`{"error":"bad_verification_code"}`))
		case PKCEChallenge(r.PostForm.Get("code_verifier")) != f.challenge:
			_, _ = w.Write([]byte(`{"error":"bad_verification_code","error_description":"code_verifier mismatch"}`))
		default:
			f.used = true
			_, _ = w.Write([]byte(`{"access_token":"` + fakeAccessToken + `","token_type":"bearer","scope":"read:user,user:email"}`))
		}
	})
	api := func(body func() (int, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			f.seenAuth = append(f.seenAuth, r.Header.Get("Authorization"))
			f.mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer "+fakeAccessToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			code, s := body()
			w.WriteHeader(code)
			_, _ = w.Write([]byte(s))
		}
	}
	mux.HandleFunc("GET /user", api(func() (int, string) {
		if f.userCode != 0 {
			return f.userCode, `{}`
		}
		return http.StatusOK, f.user
	}))
	mux.HandleFunc("GET /user/emails", api(func() (int, string) { return http.StatusOK, f.emails }))
	return mux
}

func newFake(t *testing.T) (*fakeGitHub, *GitHub) {
	t.Helper()
	f := &fakeGitHub{
		code:   "code-123",
		user:   `{"id":583231,"login":"octocat","name":"The Octocat"}`,
		emails: `[{"email":"octo@other.example","primary":false,"verified":true},{"email":"Octocat@GitHub.example","primary":true,"verified":true}]`,
	}
	redirect := "https://team.example.eu/auth/github/callback"
	srv := httptest.NewServer(f.handler(t, redirect))
	t.Cleanup(srv.Close)
	g, err := NewGitHub(GitHubConfig{
		ClientID: fakeClientID, ClientSecret: fakeClientSecret, RedirectURL: redirect,
		AuthorizeURL: srv.URL + "/login/oauth/authorize", TokenURL: srv.URL + "/login/oauth/access_token", APIURL: srv.URL,
		AllowInsecureHTTPHosts: []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, g
}

// begin runs the first leg and records the challenge the fake will check.
func begin(t *testing.T, f *fakeGitHub, g *GitHub) LoginState {
	t.Helper()
	st, raw, err := g.Begin("", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	for k, want := range map[string]string{"client_id": fakeClientID, "state": st.State,
		"code_challenge_method": "S256", "scope": "read:user user:email",
		"redirect_uri": "https://team.example.eu/auth/github/callback"} {
		if q.Get(k) != want {
			t.Errorf("authorize %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if strings.Contains(raw, st.Verifier) {
		t.Error("authorize URL carries the PKCE verifier")
	}
	f.challenge = q.Get("code_challenge")
	return st
}

func TestGitHubSignIn(t *testing.T) {
	f, g := newFake(t)
	st := begin(t, f, g)
	id, err := g.Complete(context.Background(), st, "code-123")
	if err != nil {
		t.Fatal(err)
	}
	if id.UserID != 583231 || id.Login != "octocat" || id.Name != "The Octocat" || id.Email.String() != "octocat@github.example" {
		t.Fatalf("identity %+v", id)
	}
	// The code is single-use at the provider: a replayed callback fails.
	if _, err := g.Complete(context.Background(), st, "code-123"); !errors.Is(err, ErrExchange) {
		t.Errorf("replayed code: %v", err)
	}
}

func TestGitHubRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(f *fakeGitHub, st *LoginState, code *string)
		want   error
	}{
		"wrong verifier (stolen code)": {func(_ *fakeGitHub, st *LoginState, _ *string) { st.Verifier = strings.Repeat("x", 43) }, ErrExchange},
		"wrong code":                   {func(_ *fakeGitHub, _ *LoginState, c *string) { *c = "guess" }, ErrExchange},
		"empty code":                   {func(_ *fakeGitHub, _ *LoginState, c *string) { *c = "" }, ErrExchange},
		"primary unverified": {func(f *fakeGitHub, _ *LoginState, _ *string) {
			f.emails = `[{"email":"a@b.example","primary":true,"verified":false},{"email":"c@d.example","primary":false,"verified":true}]`
		}, ErrUnverifiedEmail},
		"no primary": {func(f *fakeGitHub, _ *LoginState, _ *string) {
			f.emails = `[{"email":"c@d.example","primary":false,"verified":true}]`
		}, ErrUnverifiedEmail},
		"no emails":         {func(f *fakeGitHub, _ *LoginState, _ *string) { f.emails = `[]` }, ErrUnverifiedEmail},
		"emails scope lost": {func(f *fakeGitHub, _ *LoginState, _ *string) { f.emails = `not json` }, ErrProvider},
		"user forbidden":    {func(f *fakeGitHub, _ *LoginState, _ *string) { f.userCode = http.StatusForbidden }, ErrProvider},
		"user without id":   {func(f *fakeGitHub, _ *LoginState, _ *string) { f.user = `{"login":"x"}` }, ErrProvider},
		"token not bearer": {func(f *fakeGitHub, _ *LoginState, _ *string) {
			f.tokenBody = `{"access_token":"x","token_type":"mac"}`
		}, ErrProvider},
		"token not json": {func(f *fakeGitHub, _ *LoginState, _ *string) { f.tokenBody = `<html>` }, ErrProvider},
		"oversized": {func(f *fakeGitHub, _ *LoginState, _ *string) {
			f.tokenBody = `{"access_token":"` + strings.Repeat("a", MaxResponseBytes) + `"}`
		}, ErrProvider},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, g := newFake(t)
			st := begin(t, f, g)
			code := "code-123"
			c.mutate(f, &st, &code)
			_, err := g.Complete(context.Background(), st, code)
			if !errors.Is(err, c.want) {
				t.Fatalf("err %v, want %v", err, c.want)
			}
			if err != nil && strings.Contains(err.Error(), fakeAccessToken) {
				t.Error("error carries the access token")
			}
		})
	}
}

func TestGitHubDoesNotFollowRedirects(t *testing.T) {
	var hit bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	g, err := NewGitHub(GitHubConfig{ClientID: "c", ClientSecret: "s", RedirectURL: "https://x.example/cb",
		TokenURL: srv.URL, APIURL: srv.URL, AllowInsecureHTTPHosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Complete(context.Background(), LoginState{State: "s", Verifier: "v"}, "c"); !errors.Is(err, ErrProvider) {
		t.Errorf("err %v", err)
	}
	if hit {
		t.Error("followed a redirect with the client secret")
	}
}

func TestNewGitHubConfig(t *testing.T) {
	ok := GitHubConfig{ClientID: "c", ClientSecret: "s", RedirectURL: "https://x.example/cb"}
	if _, err := NewGitHub(ok); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for name, mutate := range map[string]func(*GitHubConfig){
		"no id":          func(c *GitHubConfig) { c.ClientID = "" },
		"no secret":      func(c *GitHubConfig) { c.ClientSecret = "" },
		"http redirect":  func(c *GitHubConfig) { c.RedirectURL = "http://x.example/cb" },
		"no redirect":    func(c *GitHubConfig) { c.RedirectURL = "" },
		"http token URL": func(c *GitHubConfig) { c.TokenURL = "http://evil.example/token" },
		"userinfo API":   func(c *GitHubConfig) { c.APIURL = "https://u:p@api.example" },
	} {
		c := ok
		mutate(&c)
		if _, err := NewGitHub(c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestGitHubContextCanceled(t *testing.T) {
	f, g := newFake(t)
	st := begin(t, f, g)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.Complete(ctx, st, "code-123"); !errors.Is(err, ErrProvider) || !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
}

// The sealed state and the flow together: what a product's two handlers do.
func TestGitHubFlowWithSealer(t *testing.T) {
	f, g := newFake(t)
	sealer, _ := NewStateSealer(testKey, 0)
	st := begin(t, f, g)
	cookie, err := sealer.Seal(st)
	if err != nil {
		t.Fatal(err)
	}
	// An attacker's callback with their own state is refused before any
	// exchange.
	if _, err := sealer.Open(cookie, "attacker", time.Now()); !errors.Is(err, ErrState) {
		t.Fatalf("forged state: %v", err)
	}
	opened, err := sealer.Open(cookie, st.State, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id, err := g.Complete(context.Background(), opened, "code-123")
	if err != nil || id.UserID != 583231 {
		t.Fatalf("%+v %v", id, err)
	}
}
