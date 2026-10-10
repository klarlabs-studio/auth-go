package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/klarlabs-studio/auth-go/domain"
)

// GitHub's endpoints on github.com. GitHub Enterprise Server uses
// https://<host>/login/oauth/... and https://<host>/api/v3.
const (
	GitHubAuthorizeURL = "https://github.com/login/oauth/authorize"
	GitHubTokenURL     = "https://github.com/login/oauth/access_token" //nolint:gosec // an endpoint URL, not a credential
	GitHubAPIURL       = "https://api.github.com"
)

// GitHubScopes are the scopes a sign-in needs: the public profile and the
// account's e-mail addresses (to find the verified primary one). Neither
// grants access to repositories.
var GitHubScopes = []string{"read:user", "user:email"}

// GitHubConfig configures sign-in with GitHub through an OAuth App (or a
// GitHub App's user authorization, which works the same way).
type GitHubConfig struct {
	// ClientID and ClientSecret are the OAuth App's credentials. Keep the
	// secret out of the database and logs.
	ClientID     string
	ClientSecret string
	// RedirectURL is the callback registered on the app, exactly, e.g.
	// https://team.example.eu/auth/github/callback.
	RedirectURL string
	// Scopes default to GitHubScopes.
	Scopes []string
	// AuthorizeURL, TokenURL and APIURL default to github.com's; set them
	// for GitHub Enterprise Server or tests.
	AuthorizeURL string
	TokenURL     string
	APIURL       string
	// AllowInsecureHTTPHosts names hosts (without port) that may be reached
	// over plain http — for tests against a local fake only.
	AllowInsecureHTTPHosts []string
	// HTTPClient makes the requests; nil uses a client with a 15 s timeout.
	// Redirects are never followed either way.
	HTTPClient *http.Client
}

// GitHub signs people in with their GitHub account.
type GitHub struct {
	cfg       GitHubConfig
	authorize *url.URL
	client    *http.Client
}

// NewGitHub validates cfg. It performs no I/O.
func NewGitHub(cfg GitHubConfig) (*GitHub, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("%w: client ID and secret are required", ErrInvalidConfig)
	}
	if cfg.AuthorizeURL == "" {
		cfg.AuthorizeURL = GitHubAuthorizeURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = GitHubTokenURL
	}
	if cfg.APIURL == "" {
		cfg.APIURL = GitHubAPIURL
	}
	cfg.APIURL = strings.TrimRight(cfg.APIURL, "/")
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = GitHubScopes
	}
	policy := urlPolicy{insecureHosts: cfg.AllowInsecureHTTPHosts}
	auth, err := policy.check(cfg.AuthorizeURL)
	if err != nil {
		return nil, fmt.Errorf("%w: authorize URL: %w", ErrInvalidConfig, err)
	}
	for name, raw := range map[string]string{"token URL": cfg.TokenURL, "API URL": cfg.APIURL, "redirect URL": cfg.RedirectURL} {
		if _, err := policy.check(raw); err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrInvalidConfig, name, err)
		}
	}
	return &GitHub{cfg: cfg, authorize: auth, client: noRedirectClient(cfg.HTTPClient)}, nil
}

// Begin mints a login state and the URL to send the browser to. Seal the
// state into a cookie (StateSealer) before redirecting.
func (g *GitHub) Begin(extra string, now time.Time) (LoginState, string, error) {
	st, err := NewLoginState(extra, now)
	if err != nil {
		return LoginState{}, "", err
	}
	return st, g.AuthCodeURL(st), nil
}

// AuthCodeURL is the authorize URL for st: client, redirect, scopes, state
// and the S256 PKCE challenge.
func (g *GitHub) AuthCodeURL(st LoginState) string {
	u := *g.authorize
	q := u.Query()
	q.Set("client_id", g.cfg.ClientID)
	q.Set("redirect_uri", g.cfg.RedirectURL)
	q.Set("scope", strings.Join(g.cfg.Scopes, " "))
	q.Set("state", st.State)
	q.Set("code_challenge", PKCEChallenge(st.Verifier))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String()
}

// GitHubIdentity is who signed in. Key accounts on UserID: it is immutable,
// while a login can be renamed and then registered by someone else, and an
// e-mail address can move between accounts.
type GitHubIdentity struct {
	UserID int64
	Login  string
	// Name is the profile's display name; empty when the person set none.
	Name string
	// Email is the account's primary e-mail address, verified by GitHub.
	Email domain.Email
}

// Complete finishes a sign-in on the callback: it exchanges code with the
// state's PKCE verifier and reads the account and its verified primary
// e-mail address. Call it only with a LoginState that StateSealer.Open
// returned for this callback. The access token is dropped afterwards.
func (g *GitHub) Complete(ctx context.Context, st LoginState, code string) (GitHubIdentity, error) {
	if code == "" || len(code) > 512 {
		return GitHubIdentity{}, fmt.Errorf("%w: missing or oversized code", ErrExchange)
	}
	token, err := g.exchange(ctx, code, st.Verifier)
	if err != nil {
		return GitHubIdentity{}, err
	}
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := g.api(ctx, token, "/user", &user); err != nil {
		return GitHubIdentity{}, err
	}
	if user.ID <= 0 || user.Login == "" {
		return GitHubIdentity{}, fmt.Errorf("%w: /user without an id or login", ErrProvider)
	}
	var emails []githubEmail
	if err := g.api(ctx, token, "/user/emails", &emails); err != nil {
		return GitHubIdentity{}, err
	}
	i := slices.IndexFunc(emails, func(e githubEmail) bool { return e.Primary })
	if i < 0 || !emails[i].Verified {
		return GitHubIdentity{}, ErrUnverifiedEmail
	}
	email, err := domain.NewEmail(emails[i].Email)
	if err != nil {
		return GitHubIdentity{}, fmt.Errorf("%w: primary e-mail: %w", ErrProvider, err)
	}
	return GitHubIdentity{UserID: user.ID, Login: user.Login, Name: user.Name, Email: email}, nil
}

// githubEmail is one entry of GET /user/emails.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// exchange trades the code for an access token. GitHub answers a refused
// code with 200 and an "error" member, so both shapes are read.
func (g *GitHub) exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"client_id":     {g.cfg.ClientID},
		"client_secret": {g.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {g.cfg.RedirectURL},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrProvider, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	body, status, err := g.do(req)
	if err != nil {
		return "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("%w: token response is not JSON (status %d)", ErrProvider, status)
	}
	switch {
	case tok.Error != "":
		// bad_verification_code, incorrect_client_credentials,
		// redirect_uri_mismatch, ... — never echo the description, which
		// can quote the request.
		return "", fmt.Errorf("%w: %s", ErrExchange, tok.Error)
	case status != http.StatusOK:
		return "", fmt.Errorf("%w: token endpoint answered %d", ErrProvider, status)
	case tok.AccessToken == "" || !strings.EqualFold(tok.TokenType, "bearer"):
		return "", fmt.Errorf("%w: no bearer access token", ErrProvider)
	}
	return tok.AccessToken, nil
}

// api GETs an API path with the access token and decodes the JSON answer.
func (g *GitHub) api(ctx context.Context, token, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.cfg.APIURL+path, nil)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrProvider, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	body, status, err := g.do(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		// 401/403/404: the token lacks the scope (the person narrowed it) or
		// was revoked in between.
		return fmt.Errorf("%w: %s answered %d", ErrProvider, path, status)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrProvider, path, err)
	}
	return nil
}

func (g *GitHub) do(req *http.Request) ([]byte, int, error) {
	resp, err := g.client.Do(req)
	if err != nil {
		if ctxErr := req.Context().Err(); ctxErr != nil {
			return nil, 0, fmt.Errorf("%w: %w", ErrProvider, ctxErr)
		}
		// The URL can carry nothing secret (the token travels in a header
		// or the body), but keep the error terse all the same.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return nil, 0, fmt.Errorf("%w: %w", ErrProvider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrProvider, err)
	}
	if len(body) > MaxResponseBytes {
		return nil, 0, fmt.Errorf("%w: response over %d bytes", ErrProvider, MaxResponseBytes)
	}
	return body, resp.StatusCode, nil
}
