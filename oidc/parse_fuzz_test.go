package oidc

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// FuzzParseCompact: the parser never panics, fails only with ErrMalformed,
// and whatever it accepts is the one canonical serialization of what it
// decoded — so no two distinct strings parse to the same token.
func FuzzParseCompact(f *testing.F) {
	enc := base64.RawURLEncoding.EncodeToString
	h := enc([]byte(`{"alg":"RS256","kid":"a","typ":"JWT"}`))
	p := enc([]byte(`{"iss":"https://issuer.example","aud":["glossa"],"exp":1800000300,"iat":1800000000}`))
	for _, seed := range []string{
		h + "." + p + "." + enc([]byte("signature")),
		h + "." + p + ".",
		h + "." + p,
		h + "=." + p + ".AA",
		h + "." + p + ".AB",
		enc([]byte(`{"alg":"none","kid":"a","alg":"RS256"}`)) + "." + p + ".AA",
		enc([]byte(`{"alg":"RS256","kid":"a","crit":["b64"]}`)) + "." + p + ".AA",
		enc([]byte(`{"alg":"RS256","kid":"a"}`)) + "." + enc([]byte("{\"a\":\"\xff\"}")) + ".AA",
		enc([]byte(`{"alg":"RS256","kid":"a"}`)) + "." + enc([]byte(`{"a":[[[[[[{"b":1,"b":2}]]]]]]}`)) + ".AA",
		"..",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		jws, err := parseCompact(raw)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("error does not wrap ErrMalformed: %v", err)
			}
			return
		}
		parts := strings.Split(raw, ".")
		if jws.signingInput != parts[0]+"."+parts[1] {
			t.Fatalf("signing input %q is not the first two segments of %q", jws.signingInput, raw)
		}
		if enc(jws.payload) != parts[1] || enc(jws.signature) != parts[2] {
			t.Fatalf("accepted a non-canonical encoding: %q", raw)
		}
		if jws.header.Algorithm == "" || jws.header.KeyID == "" {
			t.Fatalf("accepted a header without alg or kid: %q", raw)
		}
		if _, _, err := decodeClaims(jws.payload); err != nil && !errors.Is(err, ErrMalformed) {
			t.Fatalf("decodeClaims error does not wrap ErrMalformed: %v", err)
		}
	})
}
