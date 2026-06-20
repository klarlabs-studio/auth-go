package webauthn_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

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
