package webauthn

import (
	"encoding/json"
	"testing"

	authgo "github.com/klarlabs-studio/auth-go"
)

func newTestAuth(t *testing.T) (*Authenticator, *authgo.MemoryPasskeyStore) {
	t.Helper()
	store := authgo.NewMemoryPasskeyStore()
	a, err := New(Config{
		RPDisplayName: "Klarlabs",
		RPID:          "klarlabs.de",
		RPOrigins:     []string{"https://app.klarlabs.de"},
	}, store)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return a, store
}

func TestBeginRegistration_ProducesOptionsAndState(t *testing.T) {
	a, _ := newTestAuth(t)
	options, state, err := a.BeginRegistration("user-1", "Felix")
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	var optsObj, stateObj map[string]any
	if err := json.Unmarshal(options, &optsObj); err != nil {
		t.Fatalf("options not valid JSON: %v", err)
	}
	if err := json.Unmarshal(state, &stateObj); err != nil {
		t.Fatalf("state not valid JSON: %v", err)
	}
	if _, ok := optsObj["publicKey"]; !ok {
		t.Fatalf("options missing publicKey: %s", options)
	}
}

func TestBeginLogin_NoCredentials(t *testing.T) {
	a, _ := newTestAuth(t)
	if _, _, err := a.BeginLogin("user-with-no-passkeys"); err == nil {
		t.Fatal("want error for user without passkeys")
	}
}

func TestBeginLogin_WithStoredCredential(t *testing.T) {
	a, store := newTestAuth(t)
	// Seed a registration first so the user has a credential, then ensure
	// BeginLogin builds an assertion referencing it.
	options, state, err := a.BeginRegistration("user-2", "Felix")
	if err != nil {
		t.Fatal(err)
	}
	_ = options
	_ = state
	// Manually store a credential (registration finish needs a real browser).
	if err := store.Add(authgo.PasskeyCredential{
		ID:        []byte{1, 2, 3, 4},
		UserID:    "user-2",
		PublicKey: []byte{5, 6, 7, 8},
		SignCount: 0,
		Name:      "Test Key",
	}); err != nil {
		t.Fatal(err)
	}
	opts, _, err := a.BeginLogin("user-2")
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(opts, &obj); err != nil {
		t.Fatalf("login options not valid JSON: %v", err)
	}
	if _, ok := obj["publicKey"]; !ok {
		t.Fatalf("login options missing publicKey: %s", opts)
	}
}

func TestInterfaceSatisfied(t *testing.T) {
	var _ authgo.PasskeyAuthenticator = (*Authenticator)(nil)
}
