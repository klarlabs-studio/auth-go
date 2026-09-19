package oidc_test

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/oidc"
)

func TestNew_ValidatesConfig(t *testing.T) {
	ok := func(c *oidc.Config) {}
	cases := []struct {
		name    string
		mut     func(*oidc.Config)
		wantErr bool
	}{
		{"valid https", ok, false},
		{"missing issuer", func(c *oidc.Config) { c.Issuer = "" }, true},
		{"relative issuer", func(c *oidc.Config) { c.Issuer = "issuer.example" }, true},
		{"http issuer", func(c *oidc.Config) { c.Issuer = "http://issuer.example" }, true},
		{"http issuer, allowed host", func(c *oidc.Config) {
			c.Issuer = "http://127.0.0.1:8080"
			c.AllowInsecureHTTPHosts = []string{"127.0.0.1"}
		}, false},
		{"http issuer, other host allowed", func(c *oidc.Config) {
			c.Issuer = "http://issuer.example"
			c.AllowInsecureHTTPHosts = []string{"127.0.0.1"}
		}, true},
		{"ftp issuer", func(c *oidc.Config) { c.Issuer = "ftp://issuer.example" }, true},
		{"issuer with query", func(c *oidc.Config) { c.Issuer = "https://issuer.example?x=1" }, true},
		{"issuer with empty query", func(c *oidc.Config) { c.Issuer = "https://issuer.example?" }, true},
		{"issuer with fragment", func(c *oidc.Config) { c.Issuer = "https://issuer.example#f" }, true},
		{"issuer with userinfo", func(c *oidc.Config) { c.Issuer = "https://u:p@issuer.example" }, true},
		{"issuer with path", func(c *oidc.Config) { c.Issuer = "https://issuer.example/tenant" }, false},
		{"no audience", func(c *oidc.Config) { c.Audiences = nil }, true},
		{"empty audience", func(c *oidc.Config) { c.Audiences = []string{"glossa", ""} }, true},
		{"negative skew", func(c *oidc.Config) { c.ClockSkew = -time.Second }, true},
		{"negative max stale", func(c *oidc.Config) { c.MaxStale = -time.Hour }, true},
		{"max stale at the TTL floor", func(c *oidc.Config) { c.MaxStale = oidc.MinKeySetTTL }, true},
		{"max stale above the TTL floor", func(c *oidc.Config) { c.MaxStale = oidc.MinKeySetTTL + time.Second }, false},
		{"alg none", func(c *oidc.Config) { c.Algorithms = []string{"none"} }, true},
		{"alg HS256", func(c *oidc.Config) { c.Algorithms = []string{"RS256", "HS256"} }, true},
		{"alg lower-case", func(c *oidc.Config) { c.Algorithms = []string{"rs256"} }, true},
		{"all supported algs", func(c *oidc.Config) {
			c.Algorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := oidc.Config{Issuer: "https://issuer.example", Audiences: []string{"glossa"}}
			tc.mut(&cfg)
			_, err := oidc.New(cfg)
			if tc.wantErr && !errors.Is(err, oidc.ErrInvalidConfig) {
				t.Fatalf("want ErrInvalidConfig, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
		})
	}
}

func TestVerify_AcceptsEverySupportedAlgorithm(t *testing.T) {
	ec256, ec384, ec521 := mustEC(t, ecKey), mustEC(t, ecKey384), mustEC(t, ecKey521)
	fi := newFakeIssuer(t, false,
		rsaJWK("rsa", &rsaKeyA().PublicKey, ""),
		ecJWK("p256", &ec256.PublicKey),
		ecJWK("p384", &ec384.PublicKey),
		ecJWK("p521", &ec521.PublicKey),
	)
	clock := newClock()
	v := newVerifier(t, fi, clock, func(c *oidc.Config) {
		c.Algorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}
	})
	cases := []struct {
		alg, kid string
		key      any
	}{
		{"RS256", "rsa", rsaKeyA()},
		{"RS384", "rsa", rsaKeyA()},
		{"RS512", "rsa", rsaKeyA()},
		{"PS256", "rsa", rsaKeyA()},
		{"PS384", "rsa", rsaKeyA()},
		{"PS512", "rsa", rsaKeyA()},
		{"ES256", "p256", ec256},
		{"ES384", "p384", ec384},
		{"ES512", "p521", ec521},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			tok := signJWS(t, tc.alg, tc.key, header(tc.alg, tc.kid), mustJSON(claims(fi, clock)))
			got, err := v.Verify(context.Background(), tok)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got.Header.Algorithm != tc.alg || got.Header.KeyID != tc.kid || got.Header.Type != "JWT" {
				t.Fatalf("header = %+v", got.Header)
			}
		})
	}
	if n := fi.jwksCount(); n != 1 {
		t.Fatalf("key set fetched %d times, want 1 (cached)", n)
	}
}

func TestVerify_ReturnsTypedAndRawClaims(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, "RS256"))
	clock := newClock()
	v := newVerifier(t, fi, clock)
	c := claims(fi, clock)
	c["aud"] = []string{"other", "glossa"}
	c["repository_id"] = "123456789012"
	c["big"] = json.Number("9007199254740993") // 2^53+1: not representable as float64
	tok := signJWS(t, "RS256", rsaKeyA(), header("RS256", "a"), mustJSON(c))

	got, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	now := clock.Now()
	want := oidc.Claims{
		Issuer: fi.URL(), Subject: "repo:acme/web:ref:refs/heads/main", ID: "5f6c1e2a",
		Audience: []string{"other", "glossa"},
		Expiry:   now.Add(300 * time.Second), IssuedAt: now.Add(-10 * time.Second), NotBefore: now.Add(-10 * time.Second),
	}
	if got.Claims.Issuer != want.Issuer || got.Claims.Subject != want.Subject || got.Claims.ID != want.ID ||
		strings.Join(got.Claims.Audience, ",") != "other,glossa" ||
		!got.Claims.Expiry.Equal(want.Expiry) || !got.Claims.IssuedAt.Equal(want.IssuedAt) ||
		!got.Claims.NotBefore.Equal(want.NotBefore) {
		t.Fatalf("claims = %+v, want %+v", got.Claims, want)
	}
	if got.Raw["repository_id"] != "123456789012" {
		t.Fatalf("raw repository_id = %v", got.Raw["repository_id"])
	}
	if n, ok := got.Raw["big"].(json.Number); !ok || n.String() != "9007199254740993" {
		t.Fatalf("raw big = %#v, want exact json.Number", got.Raw["big"])
	}
}

// TestVerify_Claims covers time, issuer, audience and presence rules on
// correctly signed tokens.
func TestVerify_Claims(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	clock := newClock()
	now := clock.Now().Unix()
	cases := []struct {
		name    string
		mut     func(map[string]any)
		cfg     func(*oidc.Config)
		wantErr error
	}{
		{"valid", func(map[string]any) {}, nil, nil},
		{"expired beyond skew", func(c map[string]any) { c["exp"] = now - 61 }, nil, oidc.ErrExpired},
		{"expired at skew boundary", func(c map[string]any) { c["exp"] = now - 60 }, nil, oidc.ErrExpired},
		{"expired within skew", func(c map[string]any) { c["exp"] = now - 30 }, nil, nil},
		{"expired, zero-ish custom skew", func(c map[string]any) { c["exp"] = now - 2 },
			func(c *oidc.Config) { c.ClockSkew = time.Second }, oidc.ErrExpired},
		{"fractional exp", func(c map[string]any) { c["exp"] = float64(now) + 100.5 }, nil, nil},
		{"nbf in future", func(c map[string]any) { c["nbf"] = now + 120 }, nil, oidc.ErrNotYetValid},
		{"nbf within skew", func(c map[string]any) { c["nbf"] = now + 30 }, nil, nil},
		{"nbf absent", func(c map[string]any) { delete(c, "nbf") }, nil, nil},
		{"iat in future", func(c map[string]any) { c["iat"] = now + 120 }, nil, oidc.ErrNotYetValid},
		{"exp missing", func(c map[string]any) { delete(c, "exp") }, nil, oidc.ErrMissingClaim},
		{"iat missing", func(c map[string]any) { delete(c, "iat") }, nil, oidc.ErrMissingClaim},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://evil.example" }, nil, oidc.ErrIssuer},
		{"issuer trailing slash", func(c map[string]any) { c["iss"] = fi.URL() + "/" }, nil, oidc.ErrIssuer},
		{"issuer missing", func(c map[string]any) { delete(c, "iss") }, nil, oidc.ErrIssuer},
		{"wrong audience", func(c map[string]any) { c["aud"] = "https://github.com/acme" }, nil, oidc.ErrAudience},
		{"audience list without ours", func(c map[string]any) { c["aud"] = []string{"a", "b"} }, nil, oidc.ErrAudience},
		{"audience missing", func(c map[string]any) { delete(c, "aud") }, nil, oidc.ErrAudience},
		{"audience case differs", func(c map[string]any) { c["aud"] = "Glossa" }, nil, oidc.ErrAudience},
		{"second configured audience", func(c map[string]any) { c["aud"] = "glossa-staging" },
			func(c *oidc.Config) { c.Audiences = []string{"glossa", "glossa-staging"} }, nil},
		{"sub required, missing", func(c map[string]any) { delete(c, "sub") },
			func(c *oidc.Config) { c.RequireSubject = true }, oidc.ErrMissingClaim},
		{"sub not required, missing", func(c map[string]any) { delete(c, "sub") }, nil, nil},
		{"jti required, empty", func(c map[string]any) { c["jti"] = "" },
			func(c *oidc.Config) { c.RequireJTI = true }, oidc.ErrMissingClaim},
		{"exp as string", func(c map[string]any) { c["exp"] = "1800000300" }, nil, oidc.ErrMalformed},
		{"exp negative", func(c map[string]any) { c["exp"] = -5 }, nil, oidc.ErrMalformed},
		{"exp absurdly large", func(c map[string]any) { c["exp"] = 1e300 }, nil, oidc.ErrMalformed},
		{"aud as number", func(c map[string]any) { c["aud"] = 7 }, nil, oidc.ErrMalformed},
		{"aud list with number", func(c map[string]any) { c["aud"] = []any{"glossa", 7} }, nil, oidc.ErrMalformed},
		{"iss as array", func(c map[string]any) { c["iss"] = []string{fi.URL()} }, nil, oidc.ErrMalformed},
		{"sub as number", func(c map[string]any) { c["sub"] = 42 }, nil, oidc.ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var muts []func(*oidc.Config)
			if tc.cfg != nil {
				muts = append(muts, tc.cfg)
			}
			v := newVerifier(t, fi, clock, muts...)
			c := claims(fi, clock)
			tc.mut(c)
			tok := signJWS(t, "RS256", rsaKeyA(), header("RS256", "a"), mustJSON(c))
			_, err := v.Verify(context.Background(), tok)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

// TestVerify_RejectsAlgorithmConfusion covers the attacks where the header's
// alg is chosen to make the verifier misuse a key.
func TestVerify_RejectsAlgorithmConfusion(t *testing.T) {
	ec := mustEC(t, ecKey)
	rsaPub := &rsaKeyA().PublicKey
	fi := newFakeIssuer(t, false,
		rsaJWK("rsa", rsaPub, ""),
		rsaJWK("rsa-pinned", rsaPub, "RS256"),
		ecJWK("ec", &ec.PublicKey),
	)
	clock := newClock()
	v := newVerifier(t, fi, clock, func(c *oidc.Config) {
		c.Algorithms = []string{"RS256", "PS256", "ES256"}
	})
	payload := mustJSON(claims(fi, clock))
	// The PEM/DER encodings of the public key are what an attacker feeds an
	// HMAC verifier that treats "the key" as a byte string.
	der, err := x509.MarshalPKIXPublicKey(rsaPub)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		token   string
		wantErr error
	}{
		{"alg none, empty signature", signJWS(t, "none", nil, header("none", "rsa"), payload), oidc.ErrMalformed},
		{"alg none, junk signature", signJWS(t, "none", nil, header("none", "rsa"), payload) + "AAAA", oidc.ErrAlgorithm},
		{"alg None", signJWS(t, "none", nil, header("None", "rsa"), payload) + "AAAA", oidc.ErrAlgorithm},
		{"HS256 keyed with the public key", signJWS(t, "HS256", der, header("HS256", "rsa"), payload), oidc.ErrAlgorithm},
		{"allowed by issuer, not by us", signJWS(t, "RS512", rsaKeyA(), header("RS512", "rsa"), payload), oidc.ErrAlgorithm},
		{"ES256 header on an RSA key", signJWS(t, "ES256", ec, header("ES256", "rsa"), payload), oidc.ErrAlgorithm},
		{"RS256 header on an EC key", signJWS(t, "RS256", rsaKeyA(), header("RS256", "ec"), payload), oidc.ErrAlgorithm},
		{"PS256 on a key pinned to RS256", signJWS(t, "PS256", rsaKeyA(), header("PS256", "rsa-pinned"), payload), oidc.ErrAlgorithm},
		{"PS256 on an unpinned key", signJWS(t, "PS256", rsaKeyA(), header("PS256", "rsa"), payload), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(context.Background(), tc.token)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestVerify_RejectsBadSignatures(t *testing.T) {
	ec := mustEC(t, ecKey)
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""), ecJWK("ec", &ec.PublicKey))
	clock := newClock()
	v := newVerifier(t, fi, clock, func(c *oidc.Config) { c.Algorithms = []string{"RS256", "ES256"} })
	payload := mustJSON(claims(fi, clock))

	good := signJWS(t, "RS256", rsaKeyA(), header("RS256", "a"), payload)
	head, _, _ := strings.Cut(good, ".")
	forged := mustJSON(map[string]any{"iss": fi.URL(), "aud": "glossa", "exp": clock.Now().Unix() + 3600, "iat": clock.Now().Unix()})

	sigB64 := good[strings.LastIndexByte(good, '.')+1:]
	sig, _ := b64.DecodeString(sigB64)
	sig[10] ^= 0x01
	flipped := good[:strings.LastIndexByte(good, '.')+1] + b64.EncodeToString(sig)

	ecGood := signJWS(t, "ES256", ec, header("ES256", "ec"), payload)
	ecIn := ecGood[:strings.LastIndexByte(ecGood, '.')]
	ecSig, _ := b64.DecodeString(ecGood[len(ecIn)+1:])
	der, _ := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(ecSig[:32]), new(big.Int).SetBytes(ecSig[32:])})

	cases := []struct{ name, token string }{
		{"flipped bit", flipped},
		{"payload swapped", head + "." + b64.EncodeToString(forged) + "." + sigB64},
		{"signed by another key, same kid", signJWS(t, "RS256", rsaKeyB(), header("RS256", "a"), payload)},
		{"ES256 signature in DER", ecIn + "." + b64.EncodeToString(der)},
		{"ES256 signature truncated", ecIn + "." + b64.EncodeToString(ecSig[:63])},
		{"ES256 signature with trailing bytes", ecIn + "." + b64.EncodeToString(append(ecSig, 0))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), tc.token); !errors.Is(err, oidc.ErrSignature) {
				t.Fatalf("want ErrSignature, got %v", err)
			}
		})
	}
	if _, err := v.Verify(context.Background(), ecGood); err != nil {
		t.Fatalf("control ES256 token rejected: %v", err)
	}
}

func TestVerify_RejectsMalformedTokens(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	clock := newClock()
	v := newVerifier(t, fi, clock)
	payload := mustJSON(claims(fi, clock))
	sign := func(h, p []byte) string { return signJWS(t, "RS256", rsaKeyA(), h, p) }
	good := sign(header("RS256", "a"), payload)
	parts := strings.Split(good, ".")
	if _, err := v.Verify(context.Background(), good); err != nil {
		t.Fatalf("control token rejected: %v", err)
	}

	cases := []struct{ name, token string }{
		{"empty", ""},
		{"two segments", parts[0] + "." + parts[1]},
		{"four segments", good + ".AAAA"},
		{"empty signature", parts[0] + "." + parts[1] + "."},
		{"empty header", "." + parts[1] + "." + parts[2]},
		{"padded segment", parts[0] + "." + parts[1] + "." + parts[2] + "=="},
		{"std alphabet", parts[0] + "." + parts[1] + "." + strings.NewReplacer("-", "+", "_", "/").Replace(parts[2]) + "+/"},
		{"line break in segment", parts[0] + "." + parts[1][:10] + "\n" + parts[1][10:] + "." + parts[2]},
		{"carriage return in segment", parts[0] + "\r." + parts[1] + "." + parts[2]},
		{"space", " " + good},
		{"non-zero trailing bits", parts[0] + "." + parts[1] + "." + setTrailingBits(parts[2])},
		{"oversized", parts[0] + "." + strings.Repeat("A", oidc.MaxTokenBytes) + "." + parts[2]},
		{"header not JSON", b64.EncodeToString([]byte("RS256")) + "." + parts[1] + "." + parts[2]},
		{"header is array", sign([]byte(`["RS256"]`), payload)},
		{"duplicate alg in header", sign([]byte(`{"alg":"none","kid":"a","alg":"RS256"}`), payload)},
		{"crit header", sign([]byte(`{"alg":"RS256","kid":"a","crit":["exp"],"exp":1}`), payload)},
		{"kid missing", sign([]byte(`{"alg":"RS256"}`), payload)},
		{"kid empty", sign([]byte(`{"alg":"RS256","kid":""}`), payload)},
		{"kid not a string", sign([]byte(`{"alg":"RS256","kid":7}`), payload)},
		{"alg not a string", sign([]byte(`{"alg":["RS256"],"kid":"a"}`), payload)},
		{"typ not a string", sign([]byte(`{"alg":"RS256","kid":"a","typ":1}`), payload)},
		{"trailing data after header", sign([]byte(`{"alg":"RS256","kid":"a"}{}`), payload)},
		{"claims array", sign(header("RS256", "a"), []byte(`[1]`))},
		{"claims duplicate aud", sign(header("RS256", "a"), duplicateAud(payload))},
		{"claims nested duplicate", sign(header("RS256", "a"), nestedDuplicate(payload))},
		{"claims invalid UTF-8", sign(header("RS256", "a"), invalidUTF8(payload))},
		{"claims too deep", sign(header("RS256", "a"), deeplyNested(payload))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(context.Background(), tc.token); !errors.Is(err, oidc.ErrMalformed) {
				t.Fatalf("want ErrMalformed, got %v", err)
			}
		})
	}
}

// setTrailingBits changes the last character of an unpadded base64url string
// whose final quantum carries unused bits, so it decodes to the same bytes
// under a lenient decoder but is not the canonical encoding.
func setTrailingBits(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if len(s)%4 == 0 {
		panic("segment has no unused trailing bits")
	}
	last := strings.IndexByte(alphabet, s[len(s)-1])
	return s[:len(s)-1] + string(alphabet[last|1])
}

func duplicateAud(payload []byte) []byte {
	return append([]byte(`{"aud":"evil",`), payload[1:]...)
}

func nestedDuplicate(payload []byte) []byte {
	return append([]byte(`{"x":{"a":1,"a":2},`), payload[1:]...)
}

func invalidUTF8(payload []byte) []byte {
	return append([]byte("{\"name\":\"\xff\","), payload[1:]...)
}

func deeplyNested(payload []byte) []byte {
	return append([]byte(`{"x":`+strings.Repeat("[", 40)+strings.Repeat("]", 40)+","), payload[1:]...)
}

func TestVerify_UnknownKid(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	clock := newClock()
	v := newVerifier(t, fi, clock)
	tok := signJWS(t, "RS256", rsaKeyA(), header("RS256", "nope"), mustJSON(claims(fi, clock)))
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

func TestVerify_OverTLSWithCallerClient(t *testing.T) {
	fi := newFakeIssuer(t, true, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	clock := newClock()
	v, err := oidc.New(oidc.Config{
		Issuer:     fi.URL(),
		Audiences:  []string{"glossa"},
		HTTPClient: fi.srv.Client(), // trusts the test CA
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := signJWS(t, "RS256", rsaKeyA(), header("RS256", "a"), mustJSON(claims(fi, clock)))
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
