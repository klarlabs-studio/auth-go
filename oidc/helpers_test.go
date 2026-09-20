package oidc_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/oidc"
)

// Keys are generated once per test binary: RSA generation dominates runtime
// under -race otherwise.
var (
	rsaKeyA  = sync.OnceValue(func() *rsa.PrivateKey { return mustRSA(2048) })
	rsaKeyB  = sync.OnceValue(func() *rsa.PrivateKey { return mustRSA(2048) })
	ecKey    = sync.OnceValues(func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) })
	ecKey384 = sync.OnceValues(func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) })
	ecKey521 = sync.OnceValues(func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P521(), rand.Reader) })
)

func mustRSA(bits int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return k
}

func mustEC(t *testing.T, f func() (*ecdsa.PrivateKey, error)) *ecdsa.PrivateKey {
	t.Helper()
	k, err := f()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var b64 = base64.RawURLEncoding

func b64Int(n *big.Int) string { return b64.EncodeToString(n.Bytes()) }

func rsaJWK(kid string, pub *rsa.PublicKey, alg string) map[string]any {
	k := map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig",
		"n": b64Int(pub.N), "e": b64Int(big.NewInt(int64(pub.E))),
	}
	if alg != "" {
		k["alg"] = alg
	}
	return k
}

func ecJWK(kid string, pub *ecdsa.PublicKey) map[string]any {
	b, err := pub.Bytes() // 0x04 || X || Y, fixed width
	if err != nil {
		panic(err)
	}
	size := (len(b) - 1) / 2
	return map[string]any{
		"kty": "EC", "kid": kid, "crv": pub.Curve.Params().Name,
		"x": b64.EncodeToString(b[1 : 1+size]), "y": b64.EncodeToString(b[1+size:]),
	}
}

func jwksJSON(keys ...map[string]any) []byte {
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		panic(err)
	}
	return b
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// signJWS signs header.payload with key under alg and returns the compact
// serialization. key is *rsa.PrivateKey, *ecdsa.PrivateKey, or []byte (HS*).
func signJWS(t *testing.T, alg string, key any, header, payload []byte) string {
	t.Helper()
	input := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	hashes := map[byte]crypto.Hash{'2': crypto.SHA256, '3': crypto.SHA384, '5': crypto.SHA512}
	if alg == "none" {
		return input + "."
	}
	hash := hashes[alg[2]]
	h := hash.New()
	h.Write([]byte(input))
	digest := h.Sum(nil)

	var sig []byte
	var err error
	switch alg[:2] {
	case "RS":
		sig, err = rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), hash, digest)
	case "PS":
		sig, err = rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), hash, digest,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES":
		priv := key.(*ecdsa.PrivateKey)
		size := (priv.Curve.Params().BitSize + 7) / 8
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, priv, digest)
		if err == nil {
			sig = make([]byte, 2*size)
			r.FillBytes(sig[:size])
			s.FillBytes(sig[size:])
		}
	case "HS":
		m := hmac.New(hash.New, key.([]byte))
		m.Write([]byte(input))
		sig = m.Sum(nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64.EncodeToString(sig)
}

// fakeClock is a settable clock shared by the tokens and the Verifier.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *fakeClock { return &fakeClock{now: time.Unix(1_800_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeIssuer serves an OIDC discovery document and a JWKS, with knobs to
// rotate keys, fail, and count requests.
type fakeIssuer struct {
	srv *httptest.Server

	mu              sync.Mutex
	jwks            []byte
	jwksStatus      int
	cacheControl    string
	discoveryIssuer string // overrides the issuer in the discovery document
	jwksURI         string // overrides jwks_uri
	discoveryBody   []byte // overrides the whole discovery document
	discoveryHits   int
	jwksHits        int
	gate            chan struct{} // when set, the JWKS handler waits on it
}

func newFakeIssuer(t *testing.T, useTLS bool, keys ...map[string]any) *fakeIssuer {
	t.Helper()
	fi := &fakeIssuer{jwks: jwksJSON(keys...), jwksStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", fi.serveDiscovery)
	mux.HandleFunc("GET /jwks", fi.serveJWKS)
	mux.HandleFunc("GET /moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/jwks", http.StatusFound)
	})
	if useTLS {
		fi.srv = httptest.NewTLSServer(mux)
	} else {
		fi.srv = httptest.NewServer(mux)
	}
	t.Cleanup(fi.srv.Close)
	return fi
}

func (fi *fakeIssuer) URL() string { return fi.srv.URL }

func (fi *fakeIssuer) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	fi.mu.Lock()
	fi.discoveryHits++
	iss, uri, body := fi.discoveryIssuer, fi.jwksURI, fi.discoveryBody
	fi.mu.Unlock()
	if body != nil {
		_, _ = w.Write(body)
		return
	}
	if iss == "" {
		iss = fi.srv.URL
	}
	if uri == "" {
		uri = fi.srv.URL + "/jwks"
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(mustJSON(map[string]any{"issuer": iss, "jwks_uri": uri}))
}

func (fi *fakeIssuer) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	fi.mu.Lock()
	fi.jwksHits++
	body, status, cc, gate := fi.jwks, fi.jwksStatus, fi.cacheControl, fi.gate
	fi.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if cc != "" {
		w.Header().Set("Cache-Control", cc)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (fi *fakeIssuer) setKeys(keys ...map[string]any) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.jwks = jwksJSON(keys...)
}

func (fi *fakeIssuer) set(f func(fi *fakeIssuer)) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	f(fi)
}

func (fi *fakeIssuer) hits() (discovery, jwks int) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return fi.discoveryHits, fi.jwksHits
}

func (fi *fakeIssuer) jwksCount() int {
	_, n := fi.hits()
	return n
}

// newVerifier builds a Verifier for fi's plain-HTTP server on clock.
func newVerifier(t *testing.T, fi *fakeIssuer, clock *fakeClock, mut ...func(*oidc.Config)) *oidc.Verifier {
	t.Helper()
	cfg := oidc.Config{
		Issuer:                 fi.URL(),
		Audiences:              []string{"glossa"},
		AllowInsecureHTTPHosts: []string{"127.0.0.1"},
		Now:                    clock.Now,
	}
	for _, m := range mut {
		m(&cfg)
	}
	v, err := oidc.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// claims returns a valid claim set for fi at clock's time.
func claims(fi *fakeIssuer, clock *fakeClock) map[string]any {
	now := clock.Now().Unix()
	return map[string]any{
		"iss": fi.URL(),
		"aud": "glossa",
		"sub": "repo:acme/web:ref:refs/heads/main",
		"jti": "5f6c1e2a",
		"iat": now - 10,
		"nbf": now - 10,
		"exp": now + 300,
	}
}

func header(alg, kid string) []byte {
	return mustJSON(map[string]any{"alg": alg, "kid": kid, "typ": "JWT"})
}
