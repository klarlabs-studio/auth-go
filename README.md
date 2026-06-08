# auth-go

Klarlabs shared authentication library. Implements the auth methods mandated by
the Klarlabs product standard — **magic link**, **password + TOTP**, and
**passkeys** (WebAuthn, via adapter) — all converging on a single server-side
session with HttpOnly-cookie semantics.

```
go get github.com/klarlabs-studio/auth-go
```

## What's here

| Area | Type | Notes |
| --- | --- | --- |
| Sessions | `SessionManager`, `SessionStore` | opaque 256-bit token, TTL, revoke + logout-everywhere |
| Password | `HashPassword` / `VerifyPassword` | argon2id, PHC encoding, OWASP-2024 defaults, constant-time verify |
| TOTP | `TOTPConfig` | RFC 6238, secret gen, `otpauth://` provisioning URI, clock-skew window |
| Magic link | `MagicLinkManager`, `MagicLinkStore` | single-use, TTL, only SHA-256 hash stored |
| Passkeys | `PasskeyAuthenticator`, `PasskeyStore` | interfaces; WebAuthn adapter lives separately so the core stays dependency-light |

In-memory stores ship for tests and single-node dev; products back the
`SessionStore` / `MagicLinkStore` / `PasskeyStore` interfaces with Postgres or
Redis.

## Example

```go
sm := authgo.NewSessionManager(store, 24*time.Hour, nil)
s, _ := sm.Issue(userID, tenantID)   // set s.Token as an HttpOnly cookie
sess, err := sm.Validate(cookieToken) // on each request
sm.RevokeAll(userID)                  // logout everywhere

hash, _ := authgo.HashPassword(pw, authgo.DefaultArgon2idParams())
err = authgo.VerifyPassword(pw, hash)

cfg := authgo.DefaultTOTPConfig("Klarlabs")
secret, _ := authgo.NewTOTPSecret()
uri := cfg.ProvisioningURI(secret, email) // → QR code
err = cfg.Validate(secret, userCode, time.Now())

ml := authgo.NewMagicLinkManager(mlStore, 15*time.Minute, nil)
raw, _ := ml.Issue(email, tenantID)  // email the raw token; never stored
link, err := ml.Consume(raw)         // single-use
```

## Design

- **Dependency-light core**: only `golang.org/x/crypto` (argon2). TOTP is pure
  stdlib. Passkeys are an interface — import the WebAuthn adapter only if needed.
- **Injectable `Clock`** everywhere time matters — deterministic tests.
- **Store interfaces, not implementations** — the library owns the protocol,
  the product owns persistence and tenant scoping.

87.9% covered, race-tested, RFC 6238 vectors verified. MIT.
