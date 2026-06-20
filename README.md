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
  workload.go        WorkerID · Scope · APIKey aggregate + WorkloadStore port
  services.go        SessionService · MagicLinkService · WorkloadKeyService

adapters/
  memory/            in-memory ports — tests + single-node dev
  pgstore/           Postgres ports (database/sql, no driver dep) + schema.sql
  webauthn/          PasskeyAuthenticator over go-webauthn (passkey adapter)

middleware/
  basicauth.go       BasicAuthMiddleware — inbound HTTP adapter; Basic → session
                     handshake (stdlib net/http, depends only on the domain)
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
| Workload keys | `domain.WorkloadKeyService` | scoped API keys for agent workers — 256-bit token (stdlib only), only the SHA-256 hash stored, `resource:action` scopes with `tools:*` wildcards, issue/validate/authorize/revoke/rotate |
| Basic auth | `middleware.BasicAuthMiddleware` | bootstrap-then-session handshake; `Basic` once, session cookie after — fits browser SPAs |

## Example

```go
// Every store does I/O, so each service call takes a context.Context first — it
// carries cancellation, deadlines, and trace propagation through to the adapter
// (Postgres, SQLite, or in-memory). Pass the per-request ctx in real code.
ctx := context.Background()

repo := pgstore.NewSessionRepo(db) // or memory.NewSessionRepo() / sqlite.NewSessionRepo(db)
sm := domain.NewSessionService(repo, 24*time.Hour, nil)

uid, _ := domain.NewUserID(userID)
tid, _ := domain.NewTenantID(tenantID)
s, _ := sm.Issue(ctx, uid, tid)     // set s.Token().String() as an HttpOnly cookie

tok, _ := domain.TokenFromString(cookie)
sess, err := sm.Validate(ctx, tok)  // each request
sm.RevokeAll(ctx, uid)              // logout everywhere

h, _ := domain.HashPassword(pw, domain.DefaultArgon2idParams())
err = h.Verify(pw)

cfg := domain.DefaultTOTPConfig("Klarlabs")
secret, _ := domain.NewTOTPSecret()
uri := cfg.ProvisioningURI(secret, email)   // → QR code
err = cfg.Validate(secret, userCode, time.Now())

ml := domain.NewMagicLinkService(pgstore.NewMagicLinkRepo(db), 15*time.Minute, nil)
raw, _ := ml.Issue(ctx, emailVO, tid)  // email raw.String(); never stored
link, err := ml.Consume(ctx, raw)      // single-use

// Workload keys: scoped, time-boxed API keys for agent workers.
wk := domain.NewWorkloadKeyService(pgstore.NewWorkloadKeyRepo(db), nil)
worker, _ := domain.NewWorkerID("agent-7")
scope, _ := domain.NewScope("tools:*", "memory:read")
key, token, _ := wk.IssueKey(ctx, domain.KeyRequest{
    WorkerID: worker, Scope: scope, ExpiresAt: time.Now().Add(24 * time.Hour),
})                                   // hand token.String() to the worker once — never stored
err = wk.Authorize(ctx, token, "tools:write")     // validate + scope match (wildcard)
_, newToken, _ := wk.RotateKey(ctx, key.ID())     // new key live before old deleted — brief overlap, never a gap (not atomic across stores)
wk.RevokeAllKeys(ctx, worker)                     // kill-switch
_ = newToken

// Basic-auth handshake: Authorization: Basic once, session cookie after.
mw, _ := middleware.NewBasicAuthMiddleware(middleware.BasicAuthConfig{
    Verifier: middleware.AuthenticatorFunc(func(user, pass string) (domain.UserID, domain.TenantID, error) {
        // look up the user, verify with PasswordHash.Verify, return the identity
        return uid, tid, nil // or middleware.ErrInvalidCredentials
    }),
    Sessions:   sm,
    Realm:      "rollops",
    CookieName: "rollops_ui",
})
http.Handle("/ui/", mw.Middleware(uiHandler))
// downstream: sess, _ := middleware.SessionFromContext(r.Context())
```

## Engineering bar

Per the Klarlabs default: TDD, gofmt, golangci-lint (gocritic + gosec), nox
security scan, coverctl coverage gate, strict DDD. CI is the shared
`klarlabs-studio/.github` reusable Go workflow. Postgres adapter tests are
integration-gated on `TEST_DATABASE_URL`. MIT.
