package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Key-set cache policy. Fixed rather than configurable: they bound what an
// attacker (random kids force refreshes) and a failing issuer (every request
// would otherwise refetch) can cost, and there is no safe reason to loosen them.
const (
	// MaxDocumentBytes caps a discovery document or JWKS response. Real key
	// sets are a few KiB; a larger body is refused rather than buffered.
	MaxDocumentBytes = 1 << 20
	// MinRefreshInterval is the minimum time between two fetch attempts of the
	// key set, successful or not. An unknown kid inside this window is
	// rejected with ErrUnknownKey instead of triggering another fetch.
	MinRefreshInterval = 30 * time.Second
	// MinKeySetTTL and MaxKeySetTTL bound how long a fetched key set is
	// considered fresh, whatever its Cache-Control max-age says.
	MinKeySetTTL = 5 * time.Minute
	MaxKeySetTTL = 24 * time.Hour
	// DefaultKeySetTTL applies when the response carries no max-age.
	DefaultKeySetTTL = time.Hour

	fetchTimeout = 15 * time.Second
	minRSABits   = 2048
	maxRSABits   = 8192
)

// jwk is one usable public verification key from the issuer's key set.
type jwk struct {
	kid string
	kty string // "RSA" or "EC"
	crv string // EC only
	alg string // "" when the JWK does not pin one
	key crypto.PublicKey
}

// usableWith reports whether the key may verify a signature made with alg.
func (k *jwk) usableWith(name string, a algorithm) bool {
	if k.alg != "" && k.alg != name {
		return false
	}
	return k.kty == a.kty && k.crv == a.crv
}

type rawJWK struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
}

// parseJWKS parses a JWK Set (RFC 7517 §5) into usable keys by kid. Keys this
// package cannot use — other key types, encryption keys, unsupported algs,
// RSA moduli under 2048 bits, points not on their curve, no kid — are skipped
// rather than failing the set, so an issuer adding an OKP key does not break
// verification of its RSA-signed tokens. A set with no usable key is an error.
func parseJWKS(b []byte) (map[string][]*jwk, error) {
	if err := checkJSONObject(b); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	keys := make(map[string][]*jwk)
	for _, raw := range doc.Keys {
		var rk rawJWK
		if json.Unmarshal(raw, &rk) != nil {
			continue
		}
		if k, ok := rk.toKey(); ok {
			keys[k.kid] = append(keys[k.kid], k)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks: no usable signing keys")
	}
	return keys, nil
}

func (rk *rawJWK) toKey() (*jwk, bool) {
	if rk.Kid == "" || (rk.Use != "" && rk.Use != "sig") {
		return nil, false
	}
	if rk.KeyOps != nil && !slices.Contains(rk.KeyOps, "verify") {
		return nil, false
	}
	k := &jwk{kid: rk.Kid, kty: rk.Kty, alg: rk.Alg}
	var ok bool
	switch rk.Kty {
	case "RSA":
		k.key, ok = rk.rsaKey()
	case "EC":
		k.crv = rk.Crv
		k.key, ok = rk.ecKey()
	}
	if !ok {
		return nil, false
	}
	if k.alg != "" {
		a, supported := supportedAlgorithms[k.alg]
		if !supported || a.kty != k.kty || a.crv != k.crv {
			return nil, false
		}
	}
	return k, true
}

func (rk *rawJWK) rsaKey() (*rsa.PublicKey, bool) {
	n, err := decodeSegment(rk.N)
	if err != nil {
		return nil, false
	}
	e, err := decodeSegment(rk.E)
	if err != nil || len(e) > 4 {
		return nil, false
	}
	mod := new(big.Int).SetBytes(n)
	exp := new(big.Int).SetBytes(e).Int64()
	if bits := mod.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, false
	}
	if exp < 3 || exp > 1<<31-1 || exp%2 == 0 {
		return nil, false
	}
	return &rsa.PublicKey{N: mod, E: int(exp)}, true
}

func (rk *rawJWK) ecKey() (*ecdsa.PublicKey, bool) {
	var curve elliptic.Curve
	switch rk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, false
	}
	size := (curve.Params().BitSize + 7) / 8
	x, errX := decodeSegment(rk.X)
	y, errY := decodeSegment(rk.Y)
	// RFC 7518 §6.2.1.2: coordinates are the full, fixed-width octet string.
	if errX != nil || errY != nil || len(x) != size || len(y) != size {
		return nil, false
	}
	point := make([]byte, 0, 1+2*size)
	point = append(point, 0x04)
	point = append(point, x...)
	point = append(point, y...)
	// Rejects points not on the curve (invalid-curve attacks).
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, false
	}
	return pub, true
}

// keySource fetches the issuer's discovery document and key set.
type keySource struct {
	issuer       string
	discoveryURL string
	client       *http.Client
	urls         urlPolicy
}

// discover resolves jwks_uri from {issuer}/.well-known/openid-configuration.
// The document's issuer must equal the configured issuer exactly (OIDC
// Discovery §4.3), and jwks_uri must satisfy the same scheme policy.
func (s *keySource) discover(ctx context.Context) (string, error) {
	body, _, err := s.get(ctx, s.discoveryURL)
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	if err := checkJSONObject(body); err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	if doc.Issuer != s.issuer {
		return "", fmt.Errorf("discovery: issuer %q does not match %q", doc.Issuer, s.issuer)
	}
	if _, err := s.urls.check(doc.JWKSURI); err != nil {
		return "", fmt.Errorf("discovery: jwks_uri: %w", err)
	}
	return doc.JWKSURI, nil
}

// fetchKeys retrieves and parses the key set, returning it with its TTL.
func (s *keySource) fetchKeys(ctx context.Context, jwksURI string) (map[string][]*jwk, time.Duration, error) {
	body, hdr, err := s.get(ctx, jwksURI)
	if err != nil {
		return nil, 0, fmt.Errorf("jwks: %w", err)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, 0, err
	}
	return keys, cacheTTL(hdr.Get("Cache-Control")), nil
}

func (s *keySource) get(ctx context.Context, target string) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("GET %s: status %d", target, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocumentBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("GET %s: %w", target, err)
	}
	if len(body) > MaxDocumentBytes {
		return nil, nil, fmt.Errorf("GET %s: response exceeds %d bytes", target, MaxDocumentBytes)
	}
	return body, resp.Header, nil
}

// cacheTTL derives the key set's freshness from Cache-Control: max-age, clamped
// to [MinKeySetTTL, MaxKeySetTTL]. no-store and no-cache mean the minimum.
func cacheTTL(cacheControl string) time.Duration {
	ttl := DefaultKeySetTTL
	for _, d := range strings.Split(cacheControl, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		switch {
		case d == "no-store" || d == "no-cache":
			return MinKeySetTTL
		case strings.HasPrefix(d, "max-age="):
			secs, err := strconv.ParseInt(strings.Trim(d[len("max-age="):], `"`), 10, 64)
			if err == nil && secs >= 0 {
				ttl = time.Duration(min(secs, int64(MaxKeySetTTL/time.Second))) * time.Second
			}
		}
	}
	return min(max(ttl, MinKeySetTTL), MaxKeySetTTL)
}

// keyCache holds the last good key set and decides when to refetch it:
// on first use, after its TTL, and when a token names an unknown kid. Fetches
// are single-flight and at most one per MinRefreshInterval. A failed fetch
// never discards the last good set.
type keyCache struct {
	src *keySource
	now func() time.Time

	mu          sync.Mutex
	jwksURI     string // discovered once, then reused
	keys        map[string][]*jwk
	expiresAt   time.Time
	lastAttempt time.Time
	lastErr     error
	inflight    chan struct{} // closed when the running fetch finishes
}

// lookup returns the keys with the given kid, fetching the key set when it
// has none, when it is stale, or when kid is not in it — subject to the rate
// limit. A stale set is still used when a refetch fails or is rate-limited.
func (c *keyCache) lookup(ctx context.Context, kid string) ([]*jwk, error) {
	fetched := false
	for {
		c.mu.Lock()
		now := c.now()
		found := c.keys[kid]
		fresh := c.keys != nil && now.Before(c.expiresAt)
		if len(found) > 0 && (fresh || fetched) {
			c.mu.Unlock()
			return found, nil
		}
		done := c.inflight
		if done == nil {
			if fetched || !c.mayFetchLocked(now) {
				err := c.missLocked(kid)
				c.mu.Unlock()
				if len(found) > 0 {
					return found, nil // stale, but the last good set
				}
				return nil, err
			}
			done = c.startFetchLocked(ctx, now)
		}
		c.mu.Unlock()

		select {
		case <-done:
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %w", ErrKeySetUnavailable, ctx.Err())
		}
		fetched = true
	}
}

func (c *keyCache) mayFetchLocked(now time.Time) bool {
	return c.lastAttempt.IsZero() || now.Sub(c.lastAttempt) >= MinRefreshInterval
}

func (c *keyCache) missLocked(kid string) error {
	if c.keys == nil {
		if c.lastErr != nil {
			return fmt.Errorf("%w: %w", ErrKeySetUnavailable, c.lastErr)
		}
		return ErrKeySetUnavailable
	}
	return fmt.Errorf("%w: kid %q", ErrUnknownKey, kid)
}

// startFetchLocked launches the one in-flight fetch. It runs detached from the
// caller's cancellation (keeping its values, e.g. trace context) under its own
// timeout, so one impatient caller cannot abort the fetch every other waiter
// is sharing.
func (c *keyCache) startFetchLocked(ctx context.Context, now time.Time) chan struct{} {
	done := make(chan struct{})
	c.inflight = done
	c.lastAttempt = now
	uri := c.jwksURI
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	go func() {
		defer cancel()
		discovered := uri != ""
		var err error
		if !discovered {
			uri, err = c.src.discover(fctx)
		}
		var keys map[string][]*jwk
		var ttl time.Duration
		if err == nil {
			keys, ttl, err = c.src.fetchKeys(fctx, uri)
		}
		c.mu.Lock()
		if !discovered && uri != "" {
			c.jwksURI = uri // discovery succeeded; keep it even if the JWKS fetch failed
		}
		if err == nil {
			c.keys, c.expiresAt, c.lastErr = keys, c.now().Add(ttl), nil
		} else {
			c.lastErr = err
		}
		c.inflight = nil
		c.mu.Unlock()
		close(done)
	}()
	return done
}

// urlPolicy enforces HTTPS for the issuer and its jwks_uri, except for hosts
// explicitly allowed to use plain HTTP (tests, local development).
type urlPolicy struct {
	insecureHosts []string
}

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
