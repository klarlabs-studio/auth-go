// Command human is a minimal, self-contained walkthrough of the human auth
// flows: users, sessions (issue / validate / rotate / revoke), password hashing,
// replay-safe TOTP, single-use magic links, and a WebAuthn registration begin
// (HMAC-sealed state). It wires the in-memory adapters so it runs with no
// external services — swap in adapters/sqlite or adapters/pgstore in production
// (and pass an aesgcm cipher to NewTOTPRepo).
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/klarlabs-studio/auth-go/adapters/memory"
	"github.com/klarlabs-studio/auth-go/adapters/webauthn"
	"github.com/klarlabs-studio/auth-go/domain"
)

func main() {
	ctx := context.Background()

	uid, err := domain.NewUserID("user-1")
	must(err)
	tid, err := domain.NewTenantID("tenant-1")
	must(err)
	emailVO, err := domain.NewEmail("user@example.com")
	must(err)

	// Users — persisted through the UserRepository port.
	users := memory.NewUserRepo()
	u, err := domain.NewUser(uid, tid, emailVO, time.Now(), time.Now())
	must(err)
	must(users.UpsertUser(ctx, u))
	got, err := users.GetUser(ctx, tid, uid)
	must(err)
	fmt.Printf("user: %s <%s> in tenant %s\n", got.ID(), got.Email(), got.TenantID())

	// Sessions — opaque token, configurable lifetime, rotation, revoke.
	// After Validate, sess.Token() is empty — revoke with the raw cookie value.
	sessions := domain.NewSessionService(memory.NewSessionRepo(), 24*time.Hour, nil)
	s, err := sessions.Issue(ctx, uid, tid)
	must(err)
	fmt.Printf("session issued: token=%s…\n", s.Token().String()[:12])

	sess, err := sessions.Validate(ctx, s.Token())
	must(err)
	fmt.Printf("session validates for user %s (Token empty after Validate: %v)\n",
		sess.UserID(), sess.Token().String() == "")

	// Rotate after authentication to defeat session fixation.
	fresh, err := sessions.Rotate(ctx, s.Token())
	must(err)
	fmt.Printf("session rotated: new token=%s…, old token now invalid\n", fresh.Token().String()[:12])
	if _, err := sessions.Validate(ctx, s.Token()); err != nil {
		fmt.Printf("old token rejected: %v\n", err)
	}
	must(sessions.Revoke(ctx, fresh.Token())) // logout this session (raw cookie)
	must(sessions.RevokeAll(ctx, uid))        // logout everywhere

	// Password — argon2id value object.
	hash, err := domain.HashPassword("correct horse battery staple", domain.DefaultArgon2idParams())
	must(err)
	must(hash.Verify("correct horse battery staple"))
	fmt.Println("password verified")

	// TOTP — enroll + replay-safe Verify via TOTPService.
	// Production (sqlite/pgstore): NewTOTPRepo(db, aesgcmCipher) encrypts at rest.
	totpRepo := memory.NewTOTPRepo()
	cfg := domain.DefaultTOTPConfig("Klarlabs")
	secret, err := domain.NewTOTPSecret()
	must(err)
	must(totpRepo.SetSecret(ctx, uid, secret))
	fmt.Printf("totp provisioning URI: %s\n", cfg.ProvisioningURI(secret, emailVO.String()))
	totp, err := domain.NewTOTPService(totpRepo, cfg, nil)
	must(err)
	code, err := cfg.Generate(secret, time.Now())
	must(err)
	must(totp.Verify(ctx, uid, code))
	if err := totp.Verify(ctx, uid, code); err != nil {
		fmt.Printf("totp replay rejected: %v\n", err)
	}

	// Magic link — single-use; Issue invalidates prior links for email+tenant.
	magic := domain.NewMagicLinkService(memory.NewMagicLinkRepo(), 15*time.Minute, nil)
	raw, err := magic.Issue(ctx, emailVO, tid) // email raw.String() to the user
	must(err)
	stale, err := magic.Issue(ctx, emailVO, tid) // re-issue invalidates `raw`
	must(err)
	if _, err := magic.Consume(ctx, raw); err != nil {
		fmt.Printf("prior magic link rejected after re-issue: %v\n", err)
	}
	link, err := magic.Consume(ctx, stale)
	must(err)
	fmt.Printf("magic link consumed for %s\n", link.Email())

	// Passkeys — StateKey (≥32 bytes) HMAC-signs ceremony state so a client
	// cannot swap the UserID even if state is round-tripped.
	stateKey := make([]byte, webauthn.StateKeyMinBytes)
	_, err = rand.Read(stateKey)
	must(err)
	wa, err := webauthn.New(webauthn.Config{
		RPDisplayName: "Klarlabs",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:8080"},
		StateKey:      stateKey,
	}, memory.NewPasskeyRepo())
	must(err)
	opts, state, err := wa.BeginRegistration(ctx, uid, "Demo User")
	must(err)
	fmt.Printf("passkey begin: options=%dB sealed-state=%dB\n", len(opts), len(state))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
