package oidc

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// GitHubActionsIssuer is the issuer of GitHub Actions OIDC tokens on
// github.com. GitHub Enterprise Cloud with a customised issuer uses
// "https://token.actions.githubusercontent.com/<enterprise>", and GitHub
// Enterprise Server "https://<host>/_services/token"; set Config.Issuer to
// that value instead.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// GitHubActions returns a Config for GitHub Actions ID tokens with the given
// audience: the github.com issuer, RS256 only, and sub and jti required.
// Adjust fields (Issuer, HTTPClient, Now) before passing it to New.
//
// A job requests the token with the audience in the query of
// ACTIONS_ID_TOKEN_REQUEST_URL (for example `core.getIDToken("glossa")`).
// Choose an audience unique to your service: the default audience GitHub
// issues is the repository owner's URL, which is not specific to you.
func GitHubActions(audience string) Config {
	return Config{
		Issuer:         GitHubActionsIssuer,
		Audiences:      []string{audience},
		Algorithms:     []string{"RS256"},
		RequireSubject: true,
		RequireJTI:     true,
	}
}

// GitHubActionsClaims are the GitHub-specific claims of a verified Actions ID
// token that an authorisation decision typically rests on.
//
// Authorise on the numeric IDs. repository_id and repository_owner_id are
// immutable; repository ("owner/name") and the owner's login can be renamed,
// deleted and re-registered by someone else, so a policy keyed on names can
// be inherited by a stranger. The string fields are for display, audit logs,
// and narrowing (ref, event_name, job_workflow_ref) after the ID matched.
type GitHubActionsClaims struct {
	// RepositoryID is repository_id: the repository's immutable numeric ID.
	// This is the claim to match against a stored Git connection.
	RepositoryID int64
	// RepositoryOwnerID is repository_owner_id: the owning user or
	// organisation's immutable numeric ID.
	RepositoryOwnerID int64
	// Repository is "owner/name" at the time the token was issued.
	Repository string
	// Ref is the git ref that triggered the run, e.g. "refs/heads/main" or
	// "refs/pull/42/merge".
	Ref string
	// SHA is the commit the run is for.
	SHA string
	// EventName is the triggering event, e.g. "push" or "pull_request".
	EventName string
	// JobWorkflowRef is the workflow file running the job, pinned to a ref:
	// "owner/repo/.github/workflows/ci.yml@refs/heads/main". For a reusable
	// workflow it names the called workflow, not the caller.
	JobWorkflowRef string
	// RunnerEnvironment is "github-hosted" or "self-hosted".
	RunnerEnvironment string
}

// ParseGitHubActionsClaims extracts the GitHub Actions claims from a verified
// token. repository_id and repository_owner_id are required and must be
// positive integers (GitHub sends them as decimal strings; JSON numbers are
// accepted too): absent is ErrMissingClaim, anything else ErrMalformed. The
// string claims are optional, but must be strings when present.
//
// It checks shape only. Deciding whether this repository may act — matching
// RepositoryID against a stored connection, and optionally Ref or
// JobWorkflowRef — is the caller's policy.
func ParseGitHubActionsClaims(t *Token) (GitHubActionsClaims, error) {
	if t == nil {
		return GitHubActionsClaims{}, fmt.Errorf("%w: nil token", ErrMalformed)
	}
	var c GitHubActionsClaims
	var err error
	if c.RepositoryID, err = numericIDClaim(t.Raw, "repository_id"); err != nil {
		return GitHubActionsClaims{}, err
	}
	if c.RepositoryOwnerID, err = numericIDClaim(t.Raw, "repository_owner_id"); err != nil {
		return GitHubActionsClaims{}, err
	}
	for _, s := range []struct {
		name string
		dst  *string
	}{
		{"repository", &c.Repository},
		{"ref", &c.Ref},
		{"sha", &c.SHA},
		{"event_name", &c.EventName},
		{"job_workflow_ref", &c.JobWorkflowRef},
		{"runner_environment", &c.RunnerEnvironment},
	} {
		if *s.dst, err = stringClaim(t.Raw, s.name); err != nil {
			return GitHubActionsClaims{}, err
		}
	}
	return c, nil
}

// numericIDClaim reads a positive int64 given as a decimal string or a JSON
// integer. Only plain decimal digits are accepted: no sign, no exponent, no
// leading zeros, no fraction, so each ID has one spelling.
func numericIDClaim(raw map[string]any, name string) (int64, error) {
	var s string
	switch v := raw[name].(type) {
	case nil:
		return 0, fmt.Errorf("%w: %s", ErrMissingClaim, name)
	case string:
		s = v
	case json.Number:
		s = v.String()
	default:
		return 0, fmt.Errorf("%w: %s is not a numeric ID", ErrMalformed, name)
	}
	if !isCanonicalDecimal(s) {
		return 0, fmt.Errorf("%w: %s is not a numeric ID", ErrMalformed, name)
	}
	id, err := strconv.ParseInt(s, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("%w: %s is not a numeric ID", ErrMalformed, name)
	}
	return id, nil
}

func isCanonicalDecimal(s string) bool {
	if s == "" || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
