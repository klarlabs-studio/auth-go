package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/oidc"
)

func tokenFor(t *testing.T, fi *fakeIssuer, clock *fakeClock, kid string, key any) string {
	t.Helper()
	return signJWS(t, "RS256", key, header("RS256", kid), mustJSON(claims(fi, clock)))
}

func mustVerify(t *testing.T, v *oidc.Verifier, tok string) {
	t.Helper()
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func wantErr(t *testing.T, v *oidc.Verifier, tok string, want error) {
	t.Helper()
	if _, err := v.Verify(context.Background(), tok); !errors.Is(err, want) {
		t.Fatalf("want %v, got %v", want, err)
	}
}

func wantFetches(t *testing.T, fi *fakeIssuer, want int) {
	t.Helper()
	if got := fi.jwksCount(); got != want {
		t.Fatalf("JWKS fetched %d times, want %d", got, want)
	}
}

func TestKeySet_DiscoveredOnceAndCached(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	clock := newClock()
	v := newVerifier(t, fi, clock)
	for range 5 {
		mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
	}
	if d, j := fi.hits(); d != 1 || j != 1 {
		t.Fatalf("discovery=%d jwks=%d, want 1 and 1", d, j)
	}
}

// TestKeySet_RotationRefreshesOnUnknownKid: the issuer publishes a new key and
// drops the old one; the first token with the new kid triggers a refetch.
func TestKeySet_RotationRefreshesOnUnknownKid(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	clock := newClock()
	v := newVerifier(t, fi, clock)
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))

	fi.setKeys(rsaJWK("b", &rsaKeyB().PublicKey, ""))
	clock.Advance(oidc.MinRefreshInterval)
	mustVerify(t, v, tokenFor(t, fi, clock, "b", rsaKeyB()))
	wantFetches(t, fi, 2)

	// The rotated-out key is gone from the refreshed set.
	clock.Advance(oidc.MinRefreshInterval)
	wantErr(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()), oidc.ErrUnknownKey)
	if d, _ := fi.hits(); d != 1 {
		t.Fatalf("discovery fetched %d times, want 1 (jwks_uri is reused)", d)
	}
}

// TestKeySet_UnknownKidRefreshIsRateLimited: random kids cannot make the
// verifier hammer the issuer.
func TestKeySet_UnknownKidRefreshIsRateLimited(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	clock := newClock()
	v := newVerifier(t, fi, clock)
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
	wantFetches(t, fi, 1)

	for i := range 20 {
		clock.Advance(time.Second)
		wantErr(t, v, tokenFor(t, fi, clock, "unknown-"+string(rune('a'+i)), rsaKeyA()), oidc.ErrUnknownKey)
	}
	wantFetches(t, fi, 1) // 20 s after the last fetch: no refresh yet

	clock.Advance(10 * time.Second) // now 30 s after the last fetch
	wantErr(t, v, tokenFor(t, fi, clock, "unknown-x", rsaKeyA()), oidc.ErrUnknownKey)
	wantFetches(t, fi, 2)
	wantErr(t, v, tokenFor(t, fi, clock, "unknown-y", rsaKeyA()), oidc.ErrUnknownKey)
	wantFetches(t, fi, 2)

	// Known kids keep verifying throughout.
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
	wantFetches(t, fi, 2)
}

// TestKeySet_FailedRefreshKeepsLastGoodSet: once the TTL expires, a failing
// issuer does not take verification down with it.
func TestKeySet_FailedRefreshKeepsLastGoodSet(t *testing.T) {
	failures := []struct {
		name string
		set  func(fi *fakeIssuer)
	}{
		{"server error", func(fi *fakeIssuer) { fi.jwksStatus = http.StatusInternalServerError }},
		{"invalid JSON", func(fi *fakeIssuer) { fi.jwks = []byte(`{"keys":`) }},
		{"empty key set", func(fi *fakeIssuer) { fi.jwks = []byte(`{"keys":[]}`) }},
		{"oversized", func(fi *fakeIssuer) { fi.jwks = oversizedJWKS() }},
	}
	for _, f := range failures {
		t.Run(f.name, func(t *testing.T) {
			fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
			clock := newClock()
			v := newVerifier(t, fi, clock)
			mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))

			fi.set(f.set)
			clock.Advance(oidc.DefaultKeySetTTL + time.Minute)
			mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA())) // stale set still serves
			wantFetches(t, fi, 2)                                    // but a refetch was attempted
			mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA())) // and keeps serving while
			wantFetches(t, fi, 2)                                    // the retry is rate-limited

			// Unknown kids against a stale set are unknown, not "unavailable".
			clock.Advance(oidc.MinRefreshInterval)
			wantErr(t, v, tokenFor(t, fi, clock, "b", rsaKeyB()), oidc.ErrUnknownKey)
			wantFetches(t, fi, 3)

			// Recovery: the next permitted fetch picks up the new set.
			fi.set(func(fi *fakeIssuer) {
				fi.jwksStatus = http.StatusOK
				fi.jwks = jwksJSON(rsaJWK("a", &rsaKeyA().PublicKey, ""), rsaJWK("b", &rsaKeyB().PublicKey, ""))
			})
			clock.Advance(oidc.MinRefreshInterval)
			mustVerify(t, v, tokenFor(t, fi, clock, "b", rsaKeyB()))
		})
	}
}

// oversizedJWKS is a valid key set holding key "a", padded to exactly one
// byte over the limit, so only the size cap can reject it.
func oversizedJWKS() []byte {
	valid := jwksJSON(rsaJWK("a", &rsaKeyA().PublicKey, ""))
	prefix := `{"pad":"`
	suffix := `",` + string(valid[1:])
	return []byte(prefix + strings.Repeat("x", oidc.MaxDocumentBytes+1-len(prefix)-len(suffix)) + suffix)
}

// TestKeySet_Unavailable: with nothing cached, fetch failures surface as
// ErrKeySetUnavailable, and are themselves rate-limited.
func TestKeySet_Unavailable(t *testing.T) {
	cases := []struct {
		name string
		set  func(fi *fakeIssuer)
	}{
		{"jwks server error", func(fi *fakeIssuer) { fi.jwksStatus = http.StatusServiceUnavailable }},
		{"oversized jwks", func(fi *fakeIssuer) { fi.jwks = oversizedJWKS() }},
		{"discovery issuer mismatch", func(fi *fakeIssuer) { fi.discoveryIssuer = "https://evil.example" }},
		{"discovery issuer trailing slash", func(fi *fakeIssuer) { fi.discoveryIssuer = fi.srv.URL + "/" }},
		{"jwks_uri over plain http to a non-allowed host", func(fi *fakeIssuer) { fi.jwksURI = "http://keys.example/jwks" }},
		{"jwks_uri not absolute", func(fi *fakeIssuer) { fi.jwksURI = "/jwks" }},
		{"jwks_uri redirects", func(fi *fakeIssuer) { fi.jwksURI = fi.srv.URL + "/moved" }},
		{"jwks_uri 404", func(fi *fakeIssuer) { fi.jwksURI = fi.srv.URL + "/missing" }},
		{"no usable keys", func(fi *fakeIssuer) {
			fi.jwks = jwksJSON(
				map[string]any{"kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
				rsaJWK("enc", &rsaKeyA().PublicKey, ""),
			)
			fi.jwks = []byte(strings.Replace(string(fi.jwks), `"use":"sig"`, `"use":"enc"`, 1))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
			fi.set(tc.set)
			clock := newClock()
			v := newVerifier(t, fi, clock)
			tok := tokenFor(t, fi, clock, "a", rsaKeyA())
			wantErr(t, v, tok, oidc.ErrKeySetUnavailable)
			d1, j1 := fi.hits()
			wantErr(t, v, tok, oidc.ErrKeySetUnavailable) // within the refresh interval
			if d2, j2 := fi.hits(); d2 != d1 || j2 != j1 {
				t.Fatalf("refetched within MinRefreshInterval: discovery %d→%d, jwks %d→%d", d1, d2, j1, j2)
			}
		})
	}
}

func TestKeySet_DiscoveryDocumentChecks(t *testing.T) {
	// A discovery document with a duplicate member is refused, like a token.
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	fi.set(func(fi *fakeIssuer) {
		fi.discoveryBody = []byte(`{"issuer":"` + fi.URL() + `","jwks_uri":"` + fi.URL() + `/jwks","issuer":"x"}`)
	})
	clock := newClock()
	v := newVerifier(t, fi, clock)
	wantErr(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()), oidc.ErrKeySetUnavailable)
}

func TestKeySet_CacheControlBoundsTTL(t *testing.T) {
	cases := []struct {
		cacheControl string
		fresh, stale time.Duration // still cached after fresh; refetched after stale
	}{
		{"", oidc.DefaultKeySetTTL - time.Second, oidc.DefaultKeySetTTL},
		{"public, max-age=600", 599 * time.Second, 600 * time.Second},
		{"max-age=1", oidc.MinKeySetTTL - time.Second, oidc.MinKeySetTTL},        // clamped up
		{"max-age=31536000", oidc.MaxKeySetTTL - time.Second, oidc.MaxKeySetTTL}, // clamped down
		{"no-store", oidc.MinKeySetTTL - time.Second, oidc.MinKeySetTTL},
		{"max-age=bogus", oidc.DefaultKeySetTTL - time.Second, oidc.DefaultKeySetTTL},
	}
	for _, tc := range cases {
		t.Run(tc.cacheControl, func(t *testing.T) {
			fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
			fi.set(func(fi *fakeIssuer) { fi.cacheControl = tc.cacheControl })
			clock := newClock()
			v := newVerifier(t, fi, clock)
			start := clock.Now()
			mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))

			clock.Advance(tc.fresh)
			mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
			wantFetches(t, fi, 1)

			clock.Advance(start.Add(tc.stale).Sub(clock.Now()))
			mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
			wantFetches(t, fi, 2)
		})
	}
}

func TestKeySet_SkipsUnusableKeys(t *testing.T) {
	ec := mustEC(t, ecKey)
	offCurve := ecJWK("off", &ec.PublicKey)
	offCurve["y"] = offCurve["x"]
	short := ecJWK("short", &ec.PublicKey)
	short["x"] = b64.EncodeToString([]byte{1, 2, 3})
	weak := rsaJWK("weak", &rsaKeyA().PublicKey, "")
	weak["n"] = b64.EncodeToString(make([]byte, 128)) // not even 1024 bits
	evenE := rsaJWK("even-e", &rsaKeyA().PublicKey, "")
	evenE["e"] = "AQAA" // 65536
	noKid := rsaJWK("", &rsaKeyA().PublicKey, "")
	delete(noKid, "kid")
	verifyOnly := rsaJWK("ops-sign", &rsaKeyA().PublicKey, "")
	verifyOnly["key_ops"] = []string{"sign"}
	wrongAlg := rsaJWK("wrong-alg", &rsaKeyA().PublicKey, "ES256")
	badN := rsaJWK("bad-n", &rsaKeyA().PublicKey, "")
	badN["n"] = "not base64!"
	numericN := rsaJWK("numeric-n", &rsaKeyA().PublicKey, "")
	numericN["n"] = 12345

	fi := newFakeIssuer(t, false, offCurve, short, weak, evenE, noKid, verifyOnly, wrongAlg, badN, numericN,
		map[string]any{"kty": "EC", "kid": "p192", "crv": "P-192", "x": "AA", "y": "AA"},
		rsaJWK("good", &rsaKeyA().PublicKey, "RS256"),
	)
	clock := newClock()
	v := newVerifier(t, fi, clock, func(c *oidc.Config) { c.Algorithms = []string{"RS256", "ES256"} })
	mustVerify(t, v, tokenFor(t, fi, clock, "good", rsaKeyA()))

	for _, kid := range []string{"off", "short", "weak", "even-e", "ops-sign", "wrong-alg", "bad-n", "numeric-n", "p192"} {
		t.Run(kid, func(t *testing.T) {
			wantErr(t, v, tokenFor(t, fi, clock, kid, rsaKeyA()), oidc.ErrUnknownKey)
		})
	}
}

// TestKeySet_SingleFlight: concurrent verifications that all need a fetch
// share one request, and none fails because another is already fetching.
func TestKeySet_SingleFlight(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	gate := make(chan struct{})
	fi.set(func(fi *fakeIssuer) { fi.gate = gate })
	clock := newClock()
	v := newVerifier(t, fi, clock)
	tok := tokenFor(t, fi, clock, "a", rsaKeyA())

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Go(func() {
			_, err := v.Verify(context.Background(), tok)
			errs <- err
		})
	}
	// Let the goroutines pile up behind the in-flight fetch, then release it.
	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
	wantFetches(t, fi, 1)
}

// TestKeySet_CallerCancellationDoesNotAbortSharedFetch: one caller giving up
// neither fails the fetch nor poisons the cache for the next caller.
func TestKeySet_CallerCancellationDoesNotAbortSharedFetch(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	gate := make(chan struct{})
	fi.set(func(fi *fakeIssuer) { fi.gate = gate })
	clock := newClock()
	v := newVerifier(t, fi, clock)
	tok := tokenFor(t, fi, clock, "a", rsaKeyA())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := v.Verify(ctx, tok)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) || !errors.Is(err, oidc.ErrKeySetUnavailable) {
		t.Fatalf("want ErrKeySetUnavailable wrapping context.Canceled, got %v", err)
	}

	close(gate)
	mustVerify(t, v, tok) // joins or follows the same fetch; no second request
	wantFetches(t, fi, 1)
}

// TestKeySet_MaxStaleBoundsServingAFailedIssuer: the last good set keeps
// verifying while refetches fail, but only until MaxStale after its fetch;
// then verification fails closed until a refetch succeeds.
func TestKeySet_MaxStaleBoundsServingAFailedIssuer(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	clock := newClock()
	v := newVerifier(t, fi, clock, func(c *oidc.Config) { c.MaxStale = 2 * time.Hour })
	fetchedAt := clock.Now()
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))

	fi.set(func(fi *fakeIssuer) { fi.jwksStatus = http.StatusServiceUnavailable })

	// Stale (past the 1 h TTL) but within MaxStale: still verifies.
	clock.Advance(oidc.DefaultKeySetTTL + time.Minute)
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
	clock.Advance(fetchedAt.Add(2*time.Hour - time.Second).Sub(clock.Now()))
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
	n := fi.jwksCount()

	// At MaxStale the old set is no longer trusted, even while the refetch
	// is rate-limited (the last attempt was a second ago).
	clock.Advance(time.Second)
	wantErr(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()), oidc.ErrKeySetUnavailable)
	wantFetches(t, fi, n)
	// The next permitted refetch fails too: still unavailable.
	clock.Advance(oidc.MinRefreshInterval)
	wantErr(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()), oidc.ErrKeySetUnavailable)
	wantFetches(t, fi, n+1)
	wantErr(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()), oidc.ErrKeySetUnavailable)
	wantFetches(t, fi, n+1)

	// Recovery: the next permitted refetch that succeeds restores verification.
	fi.set(func(fi *fakeIssuer) { fi.jwksStatus = http.StatusOK })
	clock.Advance(oidc.MinRefreshInterval)
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
	wantFetches(t, fi, n+2)
}

// TestKeySet_MaxStaleDefault: without MaxStale, a failed issuer is tolerated
// for 24 h after the last successful fetch and no longer.
func TestKeySet_MaxStaleDefault(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	clock := newClock()
	v := newVerifier(t, fi, clock)
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
	fi.set(func(fi *fakeIssuer) { fi.jwksStatus = http.StatusInternalServerError })

	clock.Advance(oidc.DefaultMaxStale - time.Second)
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
	clock.Advance(oidc.MinRefreshInterval)
	wantErr(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()), oidc.ErrKeySetUnavailable)
}

// TestKeySet_MaxStaleCapsFreshness: a max-age longer than MaxStale does not
// let the set go unusable before it is refetched.
func TestKeySet_MaxStaleCapsFreshness(t *testing.T) {
	fi := newFakeIssuer(t, false, rsaJWK("a", &rsaKeyA().PublicKey, ""))
	fi.set(func(fi *fakeIssuer) { fi.cacheControl = "max-age=86400" })
	clock := newClock()
	v := newVerifier(t, fi, clock, func(c *oidc.Config) { c.MaxStale = 10 * time.Minute })
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))

	clock.Advance(10*time.Minute - time.Second)
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA()))
	wantFetches(t, fi, 1)
	clock.Advance(time.Second)
	mustVerify(t, v, tokenFor(t, fi, clock, "a", rsaKeyA())) // refetched, not failed
	wantFetches(t, fi, 2)
}
