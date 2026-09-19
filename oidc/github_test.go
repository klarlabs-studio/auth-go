package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/klarlabs-studio/auth-go/oidc"
)

// githubClaims is the shape of a real GitHub Actions ID token's payload (IDs
// are decimal strings, as GitHub sends them).
func githubClaims(fi *fakeIssuer, clock *fakeClock) map[string]any {
	c := claims(fi, clock)
	c["aud"] = "glossa"
	c["sub"] = "repo:acme/web:pull_request"
	c["jti"] = "0f7f6c1c-2b1e-4c1d-9d3e-5b1c9b2f8f00"
	for k, v := range map[string]any{
		"repository":            "acme/web",
		"repository_id":         "123456789",
		"repository_owner":      "acme",
		"repository_owner_id":   "4242",
		"ref":                   "refs/pull/42/merge",
		"sha":                   "2f0ea0c3b5e6f1f5e6a4f7a2c7b8d9e0f1a2b3c4",
		"event_name":            "pull_request",
		"job_workflow_ref":      "acme/web/.github/workflows/glossa.yml@refs/pull/42/merge",
		"runner_environment":    "github-hosted",
		"repository_visibility": "private",
	} {
		c[k] = v
	}
	return c
}

func TestGitHubActions_Config(t *testing.T) {
	cfg := oidc.GitHubActions("glossa")
	if cfg.Issuer != "https://token.actions.githubusercontent.com" {
		t.Fatalf("issuer = %q", cfg.Issuer)
	}
	if len(cfg.Audiences) != 1 || cfg.Audiences[0] != "glossa" {
		t.Fatalf("audiences = %q", cfg.Audiences)
	}
	if len(cfg.Algorithms) != 1 || cfg.Algorithms[0] != "RS256" || !cfg.RequireSubject || !cfg.RequireJTI {
		t.Fatalf("cfg = %+v", cfg)
	}
	if _, err := oidc.New(cfg); err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := oidc.New(oidc.GitHubActions("")); !errors.Is(err, oidc.ErrInvalidConfig) {
		t.Fatalf("empty audience: want ErrInvalidConfig, got %v", err)
	}
}

// TestGitHubActions_EndToEnd runs the profile against a fake issuer standing
// in for token.actions.githubusercontent.com.
func TestGitHubActions_EndToEnd(t *testing.T) {
	fi := newFakeIssuer(t, true, rsaJWK("gh-1", &rsaKeyA().PublicKey, "RS256"))
	clock := newClock()
	cfg := oidc.GitHubActions("glossa")
	cfg.Issuer = fi.URL()
	cfg.HTTPClient = fi.srv.Client()
	cfg.Now = clock.Now
	v, err := oidc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := v.Verify(context.Background(),
		signJWS(t, "RS256", rsaKeyA(), header("RS256", "gh-1"), mustJSON(githubClaims(fi, clock))))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	gh, err := oidc.ParseGitHubActionsClaims(tok)
	if err != nil {
		t.Fatalf("ParseGitHubActionsClaims: %v", err)
	}
	want := oidc.GitHubActionsClaims{
		RepositoryID:      123456789,
		RepositoryOwnerID: 4242,
		Repository:        "acme/web",
		Ref:               "refs/pull/42/merge",
		SHA:               "2f0ea0c3b5e6f1f5e6a4f7a2c7b8d9e0f1a2b3c4",
		EventName:         "pull_request",
		JobWorkflowRef:    "acme/web/.github/workflows/glossa.yml@refs/pull/42/merge",
		RunnerEnvironment: "github-hosted",
	}
	if gh != want {
		t.Fatalf("claims = %+v\nwant     %+v", gh, want)
	}

	// The profile demands jti (GitHub always sends it).
	c := githubClaims(fi, clock)
	delete(c, "jti")
	_, err = v.Verify(context.Background(), signJWS(t, "RS256", rsaKeyA(), header("RS256", "gh-1"), mustJSON(c)))
	if !errors.Is(err, oidc.ErrMissingClaim) {
		t.Fatalf("missing jti: want ErrMissingClaim, got %v", err)
	}
}

func TestParseGitHubActionsClaims(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"repository_id":       "123456789",
			"repository_owner_id": "4242",
			"repository":          "acme/web",
		}
	}
	cases := []struct {
		name    string
		mut     func(map[string]any)
		wantErr error
		wantID  int64
	}{
		{"decimal strings", func(map[string]any) {}, nil, 123456789},
		{"JSON numbers", func(c map[string]any) {
			c["repository_id"] = json.Number("9007199254740993")
			c["repository_owner_id"] = json.Number("1")
		}, nil, 9007199254740993},
		{"max int64", func(c map[string]any) { c["repository_id"] = "9223372036854775807" }, nil, 9223372036854775807},
		{"optional strings absent", func(c map[string]any) { delete(c, "repository") }, nil, 123456789},
		{"repository_id missing", func(c map[string]any) { delete(c, "repository_id") }, oidc.ErrMissingClaim, 0},
		{"repository_owner_id missing", func(c map[string]any) { delete(c, "repository_owner_id") }, oidc.ErrMissingClaim, 0},
		{"repository_id empty", func(c map[string]any) { c["repository_id"] = "" }, oidc.ErrMalformed, 0},
		{"repository_id zero", func(c map[string]any) { c["repository_id"] = "0" }, oidc.ErrMalformed, 0},
		{"repository_id leading zero", func(c map[string]any) { c["repository_id"] = "0123" }, oidc.ErrMalformed, 0},
		{"repository_id signed", func(c map[string]any) { c["repository_id"] = "+123" }, oidc.ErrMalformed, 0},
		{"repository_id negative", func(c map[string]any) { c["repository_id"] = json.Number("-5") }, oidc.ErrMalformed, 0},
		{"repository_id exponent", func(c map[string]any) { c["repository_id"] = json.Number("1e9") }, oidc.ErrMalformed, 0},
		{"repository_id fraction", func(c map[string]any) { c["repository_id"] = json.Number("12.0") }, oidc.ErrMalformed, 0},
		{"repository_id overflows", func(c map[string]any) { c["repository_id"] = "9223372036854775808" }, oidc.ErrMalformed, 0},
		{"repository_id whitespace", func(c map[string]any) { c["repository_id"] = " 123" }, oidc.ErrMalformed, 0},
		{"repository_id bool", func(c map[string]any) { c["repository_id"] = true }, oidc.ErrMalformed, 0},
		{"repository_owner_id name", func(c map[string]any) { c["repository_owner_id"] = "acme" }, oidc.ErrMalformed, 0},
		{"ref not a string", func(c map[string]any) { c["ref"] = []any{"refs/heads/main"} }, oidc.ErrMalformed, 0},
		{"runner_environment not a string", func(c map[string]any) { c["runner_environment"] = 1 }, oidc.ErrMalformed, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := base()
			tc.mut(raw)
			got, err := oidc.ParseGitHubActionsClaims(&oidc.Token{Raw: raw})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got.RepositoryID != tc.wantID {
				t.Fatalf("RepositoryID = %d, want %d", got.RepositoryID, tc.wantID)
			}
		})
	}
}
