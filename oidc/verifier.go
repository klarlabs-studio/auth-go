// Package oidc verifies OpenID Connect ID tokens issued by a third party —
// GitHub Actions, a cloud workload identity, a corporate IdP — against that
// issuer's published keys.
//
// It is the inbound half of workload federation: a CI job presents a
// short-lived ID token instead of a stored secret, and the product verifies it
// and maps its claims (for GitHub Actions: repository_id) to something it
// already trusts. It does not implement an OIDC client or login flow.
//
// A Verifier is built for exactly one issuer. It discovers jwks_uri from
// {issuer}/.well-known/openid-configuration, caches the key set, and verifies
// compact JWS tokens with the stdlib only:
//
//   - Parsing is strict: three segments of canonical unpadded base64url, JSON
//     objects in valid UTF-8 with no duplicate members, a required kid, and
//     no "crit". Keys come only from the issuer's key set, never from the
//     token (jku, jwk, x5u and x5c are ignored).
//   - alg must be in the configured allow-list (default RS256) and match the
//     key's kty, curve and pinned alg. "none" and HS* cannot be configured.
//   - iss must equal the issuer exactly; aud must contain a configured
//     audience; exp and iat are required, and exp, iat and nbf are checked
//     with a clock skew (default 60 s).
//
// The key set is fetched on first use and kept for its Cache-Control max-age,
// clamped to [MinKeySetTTL, MaxKeySetTTL]. A token with an unknown kid
// triggers a refetch (key rotation), single-flight and at most once per
// MinRefreshInterval. When a refetch fails the last good key set keeps
// serving for up to Config.MaxStale after its fetch (default 24 h), then
// verification fails closed until a refetch succeeds. A Verifier is safe for
// concurrent use.
package oidc

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DefaultClockSkew is the leeway applied to exp, nbf and iat when
// Config.ClockSkew is zero.
const DefaultClockSkew = 60 * time.Second

// defaultHTTPTimeout bounds each discovery or JWKS request made with the
// default client.
const defaultHTTPTimeout = 10 * time.Second

// Config configures a Verifier. Issuer and Audiences are required.
type Config struct {
	// Issuer is the exact iss value, e.g. "https://token.actions.githubusercontent.com".
	// It must be an https URL (see AllowInsecureHTTPHosts) with no query or
	// fragment. Discovery fetches Issuer + "/.well-known/openid-configuration",
	// and the document's issuer must equal Issuer exactly.
	Issuer string
	// Audiences lists the accepted aud values. A token is accepted when its aud
	// contains at least one of them. Use a value unique to your service (the
	// GitHub Actions default audience is the repository owner's URL, which any
	// other service could also request).
	Audiences []string
	// Algorithms is the alg allow-list. Default: ["RS256"]. Allowed values:
	// RS256/384/512, PS256/384/512, ES256/384/512. "none" and HS* are refused.
	Algorithms []string
	// ClockSkew is the leeway for exp, nbf and iat. Zero means
	// DefaultClockSkew; negative is invalid.
	ClockSkew time.Duration
	// RequireSubject rejects tokens without a non-empty sub (ErrMissingClaim).
	RequireSubject bool
	// RequireJTI rejects tokens without a non-empty jti (ErrMissingClaim) —
	// set it when the caller tracks jti to refuse replays.
	RequireJTI bool
	// MaxStale bounds how long after the last successful key-set fetch the
	// set may still verify tokens when refetches fail (issuer down, endpoint
	// blocked). Past it, Verify fails with ErrKeySetUnavailable until a
	// refetch succeeds, so a key the issuer has revoked cannot stay trusted
	// just because its JWKS endpoint is unreachable. It is measured from the
	// fetch, so it includes the fresh period; the key set is refetched no
	// later than MaxStale even if its max-age is longer. Zero means
	// DefaultMaxStale (24 h); otherwise it must exceed MinKeySetTTL.
	MaxStale time.Duration
	// HTTPClient fetches discovery and the key set. Default: a client with a
	// 10 s timeout. The Verifier uses a copy that never follows redirects, so
	// the https policy cannot be bypassed by a redirect.
	HTTPClient *http.Client
	// AllowInsecureHTTPHosts names hosts (by hostname, without port) that may be
	// reached over plain http — tests and local development only, e.g.
	// "127.0.0.1". Everything else must use https.
	AllowInsecureHTTPHosts []string
	// Now is the clock. Default: time.Now.
	Now func() time.Time
}

// Claims are the registered claims of a verified token.
type Claims struct {
	Issuer    string    // iss
	Subject   string    // sub ("" when absent)
	Audience  []string  // aud, always as a list
	Expiry    time.Time // exp
	IssuedAt  time.Time // iat
	NotBefore time.Time // nbf (zero when absent)
	ID        string    // jti ("" when absent)
}

// Token is a verified ID token.
type Token struct {
	Header Header
	Claims Claims
	// Raw holds every payload claim as decoded JSON. Numbers are json.Number,
	// so large numeric IDs survive without float rounding.
	Raw map[string]any
}

// Verifier verifies ID tokens from one issuer. Build it with New.
type Verifier struct {
	issuer         string
	audiences      []string
	algs           map[string]algorithm
	skew           time.Duration
	requireSubject bool
	requireJTI     bool
	now            func() time.Time
	keys           *keyCache
}

// New validates cfg and returns a Verifier. It performs no I/O: discovery and
// the key-set fetch happen on the first Verify.
func New(cfg Config) (*Verifier, error) {
	policy := urlPolicy{insecureHosts: cfg.AllowInsecureHTTPHosts}
	u, err := policy.check(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: issuer: %w", ErrInvalidConfig, err)
	}
	if u.RawQuery != "" || u.ForceQuery {
		return nil, fmt.Errorf("%w: issuer must not have a query", ErrInvalidConfig)
	}
	if len(cfg.Audiences) == 0 || slices.Contains(cfg.Audiences, "") {
		return nil, fmt.Errorf("%w: at least one non-empty audience is required", ErrInvalidConfig)
	}
	if cfg.ClockSkew < 0 {
		return nil, fmt.Errorf("%w: negative clock skew", ErrInvalidConfig)
	}
	if cfg.MaxStale != 0 && cfg.MaxStale <= MinKeySetTTL {
		return nil, fmt.Errorf("%w: MaxStale must exceed %s", ErrInvalidConfig, MinKeySetTTL)
	}
	algs, err := allowList(cfg.Algorithms)
	if err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	v := &Verifier{
		issuer:         cfg.Issuer,
		audiences:      slices.Clone(cfg.Audiences),
		algs:           algs,
		skew:           cmp.Or(cfg.ClockSkew, DefaultClockSkew),
		requireSubject: cfg.RequireSubject,
		requireJTI:     cfg.RequireJTI,
		now:            now,
	}
	v.keys = &keyCache{
		now:      now,
		maxStale: cmp.Or(cfg.MaxStale, DefaultMaxStale),
		src: &keySource{
			issuer:       cfg.Issuer,
			discoveryURL: strings.TrimSuffix(cfg.Issuer, "/") + "/.well-known/openid-configuration",
			client:       noRedirectClient(cfg.HTTPClient),
			urls:         policy,
		},
	}
	return v, nil
}

func allowList(names []string) (map[string]algorithm, error) {
	if len(names) == 0 {
		names = []string{"RS256"}
	}
	algs := make(map[string]algorithm, len(names))
	for _, n := range names {
		a, ok := supportedAlgorithms[n]
		if !ok {
			return nil, fmt.Errorf("%w: algorithm %q is not supported", ErrInvalidConfig, n)
		}
		algs[n] = a
	}
	return algs, nil
}

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

// Verify parses rawToken, verifies its signature against the issuer's key
// set and validates its claims. Every failure wraps one of the package's
// errors (ErrMalformed, ErrAlgorithm, ErrUnknownKey, ErrSignature, ErrIssuer,
// ErrAudience, ErrExpired, ErrNotYetValid, ErrMissingClaim,
// ErrKeySetUnavailable); a context error is wrapped in ErrKeySetUnavailable.
//
// ctx bounds only this caller's wait for a key-set fetch; the fetch itself is
// shared and runs to completion for other waiters.
func (v *Verifier) Verify(ctx context.Context, rawToken string) (*Token, error) {
	jws, err := parseCompact(rawToken)
	if err != nil {
		return nil, err
	}
	alg, ok := v.algs[jws.header.Algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithm, jws.header.Algorithm)
	}
	candidates, err := v.keys.lookup(ctx, jws.header.KeyID)
	if err != nil {
		return nil, err
	}
	var key *jwk
	for _, k := range candidates {
		if k.usableWith(jws.header.Algorithm, alg) {
			key = k
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("%w: key %q cannot verify %s", ErrAlgorithm, jws.header.KeyID, jws.header.Algorithm)
	}
	if err := verifySignature(alg, key.key, jws.signingInput, jws.signature); err != nil {
		return nil, err
	}

	raw, claims, err := decodeClaims(jws.payload)
	if err != nil {
		return nil, err
	}
	if err := v.validate(claims); err != nil {
		return nil, err
	}
	return &Token{Header: jws.header, Claims: claims, Raw: raw}, nil
}

func (v *Verifier) validate(c Claims) error {
	if c.Issuer != v.issuer {
		return fmt.Errorf("%w: got %q", ErrIssuer, c.Issuer)
	}
	if !slices.ContainsFunc(c.Audience, func(a string) bool { return slices.Contains(v.audiences, a) }) {
		return fmt.Errorf("%w: got %q", ErrAudience, c.Audience)
	}
	if c.Expiry.IsZero() {
		return fmt.Errorf("%w: exp", ErrMissingClaim)
	}
	if c.IssuedAt.IsZero() {
		return fmt.Errorf("%w: iat", ErrMissingClaim)
	}
	now := v.now()
	if !now.Before(c.Expiry.Add(v.skew)) {
		return fmt.Errorf("%w: at %s", ErrExpired, c.Expiry.UTC().Format(time.RFC3339))
	}
	if c.IssuedAt.After(now.Add(v.skew)) {
		return fmt.Errorf("%w: issued at %s", ErrNotYetValid, c.IssuedAt.UTC().Format(time.RFC3339))
	}
	if !c.NotBefore.IsZero() && c.NotBefore.After(now.Add(v.skew)) {
		return fmt.Errorf("%w: not before %s", ErrNotYetValid, c.NotBefore.UTC().Format(time.RFC3339))
	}
	if v.requireSubject && c.Subject == "" {
		return fmt.Errorf("%w: sub", ErrMissingClaim)
	}
	if v.requireJTI && c.ID == "" {
		return fmt.Errorf("%w: jti", ErrMissingClaim)
	}
	return nil
}

// decodeClaims decodes the (already structurally checked) payload and
// extracts the registered claims. A registered claim of the wrong JSON type is
// ErrMalformed.
func decodeClaims(payload []byte) (map[string]any, Claims, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, Claims{}, fmt.Errorf("%w: claims: %w", ErrMalformed, err)
	}
	var c Claims
	var err error
	for _, s := range []struct {
		name string
		dst  *string
	}{{"iss", &c.Issuer}, {"sub", &c.Subject}, {"jti", &c.ID}} {
		if *s.dst, err = stringClaim(raw, s.name); err != nil {
			return nil, Claims{}, err
		}
	}
	if c.Audience, err = audienceClaim(raw); err != nil {
		return nil, Claims{}, err
	}
	for _, d := range []struct {
		name string
		dst  *time.Time
	}{{"exp", &c.Expiry}, {"iat", &c.IssuedAt}, {"nbf", &c.NotBefore}} {
		if *d.dst, err = numericDate(raw, d.name); err != nil {
			return nil, Claims{}, err
		}
	}
	return raw, c, nil
}

// stringClaim returns a string claim, "" when absent, ErrMalformed when it is
// present with another type.
func stringClaim(raw map[string]any, name string) (string, error) {
	v, ok := raw[name]
	if !ok {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s is not a string", ErrMalformed, name)
	}
	return s, nil
}

// audienceClaim accepts aud as a string or a non-empty array of strings
// (RFC 7519 §4.1.3).
func audienceClaim(raw map[string]any) ([]string, error) {
	switch v := raw["aud"].(type) {
	case nil:
		return nil, nil
	case string:
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%w: aud contains a non-string", ErrMalformed)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: aud is neither a string nor an array", ErrMalformed)
	}
}

// maxNumericDate is far beyond any real token (year 5138) and well inside
// int64 seconds, so the conversion below cannot overflow.
const maxNumericDate = 1e11

// numericDate reads a NumericDate (RFC 7519 §2): seconds since the epoch as a
// JSON number, possibly fractional. Fractions are truncated, which can only
// make exp earlier. Absent is the zero time.
func numericDate(raw map[string]any, name string) (time.Time, error) {
	v, ok := raw[name]
	if !ok {
		return time.Time{}, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, fmt.Errorf("%w: %s is not a number", ErrMalformed, name)
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || math.IsNaN(f) || f <= 0 || f > maxNumericDate {
		return time.Time{}, fmt.Errorf("%w: %s is out of range", ErrMalformed, name)
	}
	return time.Unix(int64(f), 0), nil
}
