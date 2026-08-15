package webauthn_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/klarlabs-studio/auth-go/adapters/memory"
	"github.com/klarlabs-studio/auth-go/adapters/webauthn"
	"github.com/klarlabs-studio/auth-go/domain"
)

func newAuth(t *testing.T) (*webauthn.Authenticator, *memory.PasskeyRepo) {
	t.Helper()
	repo := memory.NewPasskeyRepo()
	a, err := webauthn.New(webauthn.Config{
		RPDisplayName: "Klarlabs",
		RPID:          "klarlabs.de",
		RPOrigins:     []string{"https://app.klarlabs.de"},
		StateKey:      bytes.Repeat([]byte{0x42}, webauthn.StateKeyMinBytes),
	}, repo)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return a, repo
}

func mustUser(t *testing.T, s string) domain.UserID {
	t.Helper()
	id, err := domain.NewUserID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// decodeStatePayload extracts the JSON session from an HMAC-sealed state blob
// without verifying the MAC (tests that need the payload shape).
func decodeStatePayload(t *testing.T, state []byte) []byte {
	t.Helper()
	parts := bytes.Split(state, []byte("."))
	if len(parts) != 2 {
		t.Fatalf("state not sealed: %q", state)
	}
	raw := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[0])))
	n, err := base64.RawURLEncoding.Decode(raw, parts[0])
	if err != nil {
		t.Fatalf("payload b64: %v", err)
	}
	return raw[:n]
}

func TestBeginRegistration_ValidOptions(t *testing.T) {
	a, _ := newAuth(t)
	options, state, err := a.BeginRegistration(context.Background(), mustUser(t, "u1"), "Felix")
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	var opts map[string]any
	if err := json.Unmarshal(options, &opts); err != nil {
		t.Fatalf("options invalid JSON: %v", err)
	}
	if _, ok := opts["publicKey"]; !ok {
		t.Fatalf("options missing publicKey: %s", options)
	}
	if len(state) == 0 {
		t.Fatal("empty state")
	}
}

func TestBeginLogin_NoPasskeys(t *testing.T) {
	a, _ := newAuth(t)
	if _, _, err := a.BeginLogin(context.Background(), mustUser(t, "nobody")); !errors.Is(err, webauthn.ErrNoPasskeys) {
		t.Fatalf("want ErrNoPasskeys, got %v", err)
	}
}

func TestBeginLogin_WithCredential(t *testing.T) {
	ctx := context.Background()
	a, repo := newAuth(t)
	u := mustUser(t, "u2")
	if err := repo.Add(ctx, domain.PasskeyCredential{
		ID: []byte{1, 2, 3, 4}, UserID: u, PublicKey: []byte{5, 6, 7, 8}, Name: "Key",
	}); err != nil {
		t.Fatal(err)
	}
	opts, _, err := a.BeginLogin(ctx, u)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(opts, &obj); err != nil {
		t.Fatalf("login options invalid JSON: %v", err)
	}
	if _, ok := obj["publicKey"]; !ok {
		t.Fatalf("login options missing publicKey: %s", opts)
	}
}

func TestInterfaceSatisfied(t *testing.T) {
	var _ domain.PasskeyAuthenticator = (*webauthn.Authenticator)(nil)
}

// publicKeyOf extracts the "publicKey" member from a marshaled ceremony
// options blob (CredentialCreation / CredentialAssertion both nest their
// options under "publicKey").
func publicKeyOf(t *testing.T, options []byte) map[string]any {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(options, &top); err != nil {
		t.Fatalf("options invalid JSON: %v", err)
	}
	pk, ok := top["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("options missing publicKey object: %s", options)
	}
	return pk
}

func addCred(t *testing.T, ctx context.Context, repo *memory.PasskeyRepo, u domain.UserID) {
	t.Helper()
	if err := repo.Add(ctx, domain.PasskeyCredential{
		ID: []byte{1, 2, 3, 4}, UserID: u, PublicKey: []byte{5, 6, 7, 8}, Name: "Key",
	}); err != nil {
		t.Fatal(err)
	}
}

// Login options must request user verification "required" so a presence-only
// authenticator cannot satisfy the passwordless factor (defaults to Required).
func TestBeginLogin_RequiresUserVerification(t *testing.T) {
	ctx := context.Background()
	a, repo := newAuth(t)
	u := mustUser(t, "u-uv")
	addCred(t, ctx, repo, u)

	opts, _, err := a.BeginLogin(ctx, u)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	pk := publicKeyOf(t, opts)
	if got := pk["userVerification"]; got != "required" {
		t.Fatalf("userVerification = %v, want required", got)
	}
}

// Registration options must carry authenticatorSelection.userVerification
// "required".
func TestBeginRegistration_RequiresUserVerification(t *testing.T) {
	a, _ := newAuth(t)
	opts, _, err := a.BeginRegistration(context.Background(), mustUser(t, "u-reg"), "Felix")
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	pk := publicKeyOf(t, opts)
	sel, ok := pk["authenticatorSelection"].(map[string]any)
	if !ok {
		t.Fatalf("options missing authenticatorSelection: %s", opts)
	}
	if got := sel["userVerification"]; got != "required" {
		t.Fatalf("userVerification = %v, want required", got)
	}
}

// A non-empty Config.UserVerification overrides the default.
func TestConfig_UserVerificationOverride(t *testing.T) {
	ctx := context.Background()
	repo := memory.NewPasskeyRepo()
	a, err := webauthn.New(webauthn.Config{
		RPDisplayName:    "Klarlabs",
		RPID:             "klarlabs.de",
		RPOrigins:        []string{"https://app.klarlabs.de"},
		StateKey:         bytes.Repeat([]byte{0x7}, webauthn.StateKeyMinBytes),
		UserVerification: protocol.VerificationDiscouraged,
	}, repo)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	u := mustUser(t, "u-disc")
	addCred(t, ctx, repo, u)

	opts, _, err := a.BeginLogin(ctx, u)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	pk := publicKeyOf(t, opts)
	if got := pk["userVerification"]; got != "discouraged" {
		t.Fatalf("userVerification = %v, want discouraged", got)
	}
}

// Enforcing Timeouts means the session blob carries a future Expires, so the
// challenge cannot be replayed indefinitely.
func TestBeginLogin_ChallengeExpirySet(t *testing.T) {
	ctx := context.Background()
	a, repo := newAuth(t)
	u := mustUser(t, "u-exp")
	addCred(t, ctx, repo, u)

	_, state, err := a.BeginLogin(ctx, u)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	var session struct {
		Expires time.Time `json:"expires"`
	}
	if err := json.Unmarshal(decodeStatePayload(t, state), &session); err != nil {
		t.Fatalf("state payload invalid JSON: %v", err)
	}
	if session.Expires.IsZero() {
		t.Fatal("session Expires is zero: challenge expiry not enforced")
	}
	if !session.Expires.After(time.Now()) {
		t.Fatalf("session Expires %v is not in the future", session.Expires)
	}
}

func TestNew_RequiresStateKey(t *testing.T) {
	repo := memory.NewPasskeyRepo()
	_, err := webauthn.New(webauthn.Config{
		RPDisplayName: "Klarlabs",
		RPID:          "klarlabs.de",
		RPOrigins:     []string{"https://app.klarlabs.de"},
		StateKey:      bytes.Repeat([]byte{1}, 16),
	}, repo)
	if !errors.Is(err, webauthn.ErrInvalidStateKey) {
		t.Fatalf("want ErrInvalidStateKey, got %v", err)
	}
}

func TestFinish_RejectsTamperedState(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	_, state, err := a.BeginRegistration(ctx, mustUser(t, "u-tamper"), "Felix")
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the payload segment so the MAC no longer matches.
	parts := bytes.Split(state, []byte("."))
	parts[0][0] ^= 0xff
	tampered := bytes.Join(parts, []byte("."))
	if _, err := a.FinishRegistration(ctx, tampered, []byte(`{}`)); !errors.Is(err, webauthn.ErrInvalidState) {
		t.Fatalf("want ErrInvalidState, got %v", err)
	}
	if _, err := a.FinishLogin(ctx, tampered, []byte(`{}`)); !errors.Is(err, webauthn.ErrInvalidState) {
		t.Fatalf("login: want ErrInvalidState, got %v", err)
	}
}

// ErrCredentialCloned is a distinct, matchable sentinel. (The FinishLogin path
// that returns it requires a real authenticator assertion with a regressed
// signature counter, which cannot be forged in a unit test without a live
// authenticator; the rejection logic itself is a straight-line CloneWarning
// check. This test guards the exported sentinel's identity.)
func TestErrCredentialCloned_IsSentinel(t *testing.T) {
	if webauthn.ErrCredentialCloned == nil {
		t.Fatal("ErrCredentialCloned is nil")
	}
	wrapped := errors.Join(errors.New("ctx"), webauthn.ErrCredentialCloned)
	if !errors.Is(wrapped, webauthn.ErrCredentialCloned) {
		t.Fatal("ErrCredentialCloned not matchable via errors.Is")
	}
}
