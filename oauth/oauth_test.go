package oauth

import (
	"bytes"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

var testKey = bytes.Repeat([]byte{7}, 32)

// RFC 7636 Appendix B.
func TestPKCEChallengeRFCVector(t *testing.T) {
	got := PKCEChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %s", got)
	}
}

func TestNewLoginStateIsRandom(t *testing.T) {
	now := time.Now()
	a, err := NewLoginState("", now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewLoginState("", now)
	if a.State == b.State || a.Verifier == b.Verifier || a.State == a.Verifier {
		t.Fatal("login states repeat")
	}
	if len(a.Verifier) < 43 || len(a.Verifier) > 128 {
		t.Errorf("verifier length %d outside RFC 7636's 43..128", len(a.Verifier))
	}
}

func TestStateSealerRoundTrip(t *testing.T) {
	s, err := NewStateSealer(testKey, 0)
	if err != nil {
		t.Fatal(err)
	}
	if s.TTL() != DefaultStateTTL {
		t.Errorf("ttl %v", s.TTL())
	}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	st, _ := NewLoginState("link", now)
	sealed, err := s.Seal(st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, st.Verifier) || strings.Contains(sealed, st.State) {
		t.Fatal("sealed cookie shows the verifier or state in clear")
	}
	got, err := s.Open(sealed, st.State, now.Add(time.Minute))
	if err != nil || got.Verifier != st.Verifier || got.Extra != "link" {
		t.Fatalf("open: %+v %v", got, err)
	}
}

func TestStateSealerRefuses(t *testing.T) {
	s, _ := NewStateSealer(testKey, 5*time.Minute)
	other, _ := NewStateSealer(bytes.Repeat([]byte{8}, 32), 5*time.Minute)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	st, _ := NewLoginState("", now)
	sealed, _ := s.Seal(st)
	foreign, _ := other.Seal(st)
	raw := []byte(sealed)
	flipped := append([]byte{}, raw...)
	flipped[len(flipped)/2] ^= 1
	cases := map[string]struct {
		sealed, state string
		at            time.Time
	}{
		"wrong state":     {sealed, "attacker-state", now},
		"empty state":     {sealed, "", now},
		"empty cookie":    {"", st.State, now},
		"tampered":        {string(flipped), st.State, now},
		"other key":       {foreign, st.State, now},
		"expired":         {sealed, st.State, now.Add(5 * time.Minute)},
		"from the future": {sealed, st.State, now.Add(-2 * time.Minute)},
		"not base64":      {"%%%", st.State, now},
		"oversized":       {strings.Repeat("A", 5000), st.State, now},
	}
	for name, c := range cases {
		if _, err := s.Open(c.sealed, c.state, c.at); !errors.Is(err, ErrState) {
			t.Errorf("%s: err %v, want ErrState", name, err)
		}
	}
}

func TestNewStateSealerConfig(t *testing.T) {
	if _, err := NewStateSealer(make([]byte, 16), 0); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("16-byte key: %v", err)
	}
	if _, err := NewStateSealer(testKey, -time.Second); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("negative ttl: %v", err)
	}
}

func TestCallbackError(t *testing.T) {
	if err := CallbackError(url.Values{"code": {"x"}}); err != nil {
		t.Errorf("no error: %v", err)
	}
	if err := CallbackError(url.Values{"error": {"access_denied"}}); !errors.Is(err, ErrDenied) {
		t.Errorf("denied: %v", err)
	}
	if err := CallbackError(url.Values{"error": {"redirect_uri_mismatch"}}); !errors.Is(err, ErrProvider) {
		t.Errorf("other: %v", err)
	}
}
