// Command human is a minimal, self-contained walkthrough of the human auth
// flows: users, sessions (issue / validate / rotate / revoke), password hashing,
// TOTP enrollment + verification, and single-use magic links. It wires the
// in-memory adapters so it runs with no external services — swap in
// adapters/sqlite or adapters/pgstore in production.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/klarlabs-studio/auth-go/adapters/memory"
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
	sessions := domain.NewSessionService(memory.NewSessionRepo(), 24*time.Hour, nil)
	s, err := sessions.Issue(ctx, uid, tid)
	must(err)
	fmt.Printf("session issued: token=%s…\n", s.Token().String()[:12])

	sess, err := sessions.Validate(ctx, s.Token())
	must(err)
	fmt.Printf("session validates for user %s\n", sess.UserID())

	// Rotate after authentication to defeat session fixation.
	fresh, err := sessions.Rotate(ctx, s.Token())
	must(err)
	fmt.Printf("session rotated: new token=%s…, old token now invalid\n", fresh.Token().String()[:12])
	if _, err := sessions.Validate(ctx, s.Token()); err != nil {
		fmt.Printf("old token rejected: %v\n", err)
	}
	must(sessions.RevokeAll(ctx, uid)) // logout everywhere

	// Password — argon2id value object.
	hash, err := domain.HashPassword("correct horse battery staple", domain.DefaultArgon2idParams())
	must(err)
	must(hash.Verify("correct horse battery staple"))
	fmt.Println("password verified")

	// TOTP — RFC 6238 + secret persistence port.
	totp := memory.NewTOTPRepo()
	cfg := domain.DefaultTOTPConfig("Klarlabs")
	secret, err := domain.NewTOTPSecret()
	must(err)
	must(totp.SetSecret(ctx, uid, secret)) // enroll
	fmt.Printf("totp provisioning URI: %s\n", cfg.ProvisioningURI(secret, emailVO.String()))
	stored, err := totp.GetSecret(ctx, uid)
	must(err)
	code, err := cfg.Generate(stored, time.Now())
	must(err)
	must(cfg.Validate(stored, code, time.Now()))
	fmt.Printf("totp code %s verified\n", code)

	// Magic link — single-use, TTL, only the hash stored.
	magic := domain.NewMagicLinkService(memory.NewMagicLinkRepo(), 15*time.Minute, nil)
	raw, err := magic.Issue(ctx, emailVO, tid) // email raw.String() to the user
	must(err)
	link, err := magic.Consume(ctx, raw)
	must(err)
	fmt.Printf("magic link consumed for %s\n", link.Email())
	if _, err := magic.Consume(ctx, raw); err != nil {
		fmt.Printf("magic link reuse rejected: %v\n", err)
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
