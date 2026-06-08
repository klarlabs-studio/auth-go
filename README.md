# auth-go

Klarlabs shared authentication library. Implements the auth methods mandated by
the Klarlabs product standard — **magic link**, **password + TOTP**, and
**passkeys** (WebAuthn) — all converging on a single server-side session with
HttpOnly-cookie semantics.

```
go get github.com/klarlabs-studio/auth-go
```

## Architecture

Strict DDD / hexagonal. The domain is the center and imports nothing outward;
persistence and the WebAuthn ceremony engine are injected through ports.

```
domain/              the auth bounded context — entities, value objects,
                     domain services, repository + authenticator ports
  values.go          UserID · TenantID · Email · Token (validating constructors)
  password.go        PasswordHash value object (argon2id)
  totp.go            TOTPSecret value object + TOTPConfig (RFC 6238)
  session.go         Session aggregate + SessionRepository port
  magiclink.go       MagicLink aggregate + MagicLinkRepository port
  passkey.go         PasskeyCredential entity + Passkey{Repository,Authenticator}
  services.go        SessionService · MagicLinkService (domain services)

adapters/
  memory/            in-memory ports — tests + single-node dev
  pgstore/           Postgres ports (database/sql, no driver dep) + schema.sql
  webauthn/          PasskeyAuthenticator over go-webauthn (passkey adapter)
```

Value objects enforce their own invariants in constructors — no anemic models.
A product wires the repository ports to Postgres and gets every method.

## Methods

| Area | Where | Notes |
| --- | --- | --- |
| Sessions | `domain.SessionService` | opaque 256-bit token, TTL, revoke + logout-everywhere |
| Password | `domain.PasswordHash` | argon2id, PHC encoding, OWASP-2024 defaults, constant-time verify |
| TOTP | `domain.TOTPConfig` | RFC 6238, verified against the spec vector, clock-skew window, `otpauth://` URI |
| Magic link | `domain.MagicLinkService` | single-use, TTL, only the SHA-256 hash stored |
| Passkeys | `adapters/webauthn` | WebAuthn; kept an adapter so the core carries only `x/crypto` |

## Example

```go
repo := pgstore.NewSessionRepo(db) // or memory.NewSessionRepo()
sm := domain.NewSessionService(repo, 24*time.Hour, nil)

uid, _ := domain.NewUserID(userID)
tid, _ := domain.NewTenantID(tenantID)
s, _ := sm.Issue(uid, tid)          // set s.Token().String() as an HttpOnly cookie

tok, _ := domain.TokenFromString(cookie)
sess, err := sm.Validate(tok)       // each request
sm.RevokeAll(uid)                   // logout everywhere

h, _ := domain.HashPassword(pw, domain.DefaultArgon2idParams())
err = h.Verify(pw)

cfg := domain.DefaultTOTPConfig("Klarlabs")
secret, _ := domain.NewTOTPSecret()
uri := cfg.ProvisioningURI(secret, email)   // → QR code
err = cfg.Validate(secret, userCode, time.Now())

ml := domain.NewMagicLinkService(pgstore.NewMagicLinkRepo(db), 15*time.Minute, nil)
raw, _ := ml.Issue(emailVO, tid)    // email raw.String(); never stored
link, err := ml.Consume(raw)        // single-use
```

## Engineering bar

Per the Klarlabs default: TDD, gofmt, golangci-lint (gocritic + gosec), nox
security scan, coverctl coverage gate, strict DDD. CI is the shared
`klarlabs-studio/.github` reusable Go workflow. Postgres adapter tests are
integration-gated on `TEST_DATABASE_URL`. MIT.
