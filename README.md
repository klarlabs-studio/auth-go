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
  user.go            User aggregate + UserRepository port
  password.go        PasswordHash value object (argon2id)
  totp.go            TOTPSecret + TOTPConfig (RFC 6238) + TOTPRepository port
  session.go         Session aggregate + SessionRepository port
  magiclink.go       MagicLink aggregate + MagicLinkRepository port
  passkey.go         PasskeyCredential entity + Passkey{Repository,Authenticator}
  workload.go        WorkerID · Scope · APIKey aggregate + WorkloadStore + AtomicRotator
  services.go        SessionService · MagicLinkService · WorkloadKeyService

adapters/
  memory/            in-memory ports — tests + single-node dev
  pgstore/           Postgres ports (database/sql, no driver dep) + schema.sql
  sqlite/            SQLite ports (database/sql + modernc.org/sqlite, cgo-free)
                     + schema.sql; embedded, self-migrating via Open
  webauthn/          PasskeyAuthenticator over go-webauthn (passkey adapter)

middleware/
  basicauth.go       BasicAuthMiddleware — inbound HTTP adapter; Basic → session
                     handshake (stdlib net/http, depends only on the domain)

oidc/                OIDC ID-token Verifier for third-party issuers (stdlib only):
                     discovery, cached JWKS, strict JWS; GitHub Actions profile

oauth/               relying-party browser sign-in (stdlib only): authorization
                     code + PKCE (S256) + state sealed in an AES-GCM cookie;
                     GitHub profile (verified primary e-mail from /user/emails)

example/
  human/             runnable human auth walkthrough (go run ./example/human)
  workload/          runnable workload identity walkthrough (go run ./example/workload)
```

Value objects enforce their own invariants in constructors — no anemic models.
A product wires the repository ports to its store of choice — Postgres, SQLite,
or in-memory — and gets every method. Every port method takes a
`context.Context` first, so storage I/O honors cancellation, deadlines, and
trace propagation.

## Methods

| Area | Where | Notes |
| --- | --- | --- |
| Users | `domain.UserRepository` | minimal User aggregate (id, tenant, email); GetUser / UpsertUser through the port |
| Sessions | `domain.SessionService` | opaque 256-bit token, TTL, rotate (anti-fixation), revoke + logout-everywhere |
| Password | `domain.PasswordHash` | argon2id, PHC encoding, OWASP-2024 defaults, constant-time verify |
| TOTP | `domain.TOTPConfig` + `TOTPRepository` | RFC 6238, verified against the spec vector, clock-skew window, `otpauth://` URI; per-user secret persisted through the port |
| Magic link | `domain.MagicLinkService` | single-use, TTL, only the SHA-256 hash stored; Issue invalidates prior links for email+tenant |
| Passkeys | `adapters/webauthn` | WebAuthn; HMAC-signed ceremony state (`StateKey`); kept an adapter so the core carries only `x/crypto` |
| Workload keys | `domain.WorkloadKeyService` | scoped API keys for agent workers — 256-bit token (stdlib only), only the SHA-256 hash stored, `resource:action` scopes with `tools:*` wildcards, issue/validate/authorize/revoke; rotate atomic on all first-party adapters (`AtomicRotator`) |
| Basic auth | `middleware.BasicAuthMiddleware` | bootstrap-then-session handshake; `Basic` once, session cookie after — fits browser SPAs |
| Sign in with GitHub | `oauth.GitHub` + `oauth.StateSealer` | authorization code flow with state and PKCE; identity = immutable numeric user ID + verified primary e-mail; unverified primary refused |
| OIDC ID tokens | `oidc.Verifier` | verify ID tokens from an external issuer (GitHub Actions, cloud workload identity): discovery, cached JWKS with rotation, RS/PS/ES only; `oidc.GitHubActions` profile |

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
emailVO, _ := domain.NewEmail(email)
s, _ := sm.Issue(ctx, uid, tid)     // set s.Token().String() as an HttpOnly cookie

tok, _ := domain.TokenFromString(cookie)
sess, err := sm.Validate(ctx, tok)  // each request
fresh, _ := sm.Rotate(ctx, tok)     // re-issue after auth — old token invalidated (anti-fixation)
_ = fresh
sm.RevokeAll(ctx, uid)              // logout everywhere

// Users — persisted through the UserRepository port.
users := pgstore.NewUserRepo(db)
u, _ := domain.NewUser(uid, tid, emailVO, time.Now(), time.Now())
_ = users.UpsertUser(ctx, u)

h, _ := domain.HashPassword(pw, domain.DefaultArgon2idParams())
err = h.Verify(pw)

cfg := domain.DefaultTOTPConfig("Klarlabs")
secret, _ := domain.NewTOTPSecret()
uri := cfg.ProvisioningURI(secret, email)   // → QR code
cipher, _ := aesgcm.New(totpKey)            // 32-byte deployment key
_ = pgstore.NewTOTPRepo(db, cipher).SetSecret(ctx, uid, secret) // enroll; encrypted at rest
err = cfg.Validate(secret, userCode, time.Now())

ml := domain.NewMagicLinkService(pgstore.NewMagicLinkRepo(db), 15*time.Minute, nil)
raw, _ := ml.Issue(ctx, emailVO, tid)  // email raw.String(); prior links for email+tenant invalidated
link, err := ml.Peek(ctx, raw)         // is it good? does NOT spend it
link, err = ml.Consume(ctx, raw)       // single-use; spend it when they commit

// Workload keys: scoped, time-boxed API keys for agent workers.
wk := domain.NewWorkloadKeyService(pgstore.NewWorkloadKeyRepo(db), nil)
worker, _ := domain.NewWorkerID("agent-7")
scope, _ := domain.NewScope("tools:*", "memory:read")
key, token, _ := wk.IssueKey(ctx, domain.KeyRequest{
    WorkerID: worker, Scope: scope, ExpiresAt: time.Now().Add(24 * time.Hour),
})                                   // hand token.String() to the worker once — never stored
err = wk.Authorize(ctx, token, "tools:write")     // validate + scope match (wildcard)
_, newToken, _ := wk.RotateKey(ctx, key.ID())     // atomic on memory/sqlite/pgstore (AtomicRotator)
wk.RevokeAllKeys(ctx, worker)                     // kill-switch
_ = newToken

// Basic-auth handshake: Authorization: Basic once, session cookie after.
mw, _ := middleware.NewBasicAuthMiddleware(middleware.BasicAuthConfig{
    Verifier: middleware.AuthenticatorFunc(func(ctx context.Context, user, pass string) (domain.UserID, domain.TenantID, error) {
        // look up the user, verify with PasswordHash.Verify, return the identity
        return uid, tid, nil // or middleware.ErrInvalidCredentials
    }),
    Sessions:   sm,
    Realm:      "rollops",
    CookieName: "rollops_ui",
})
http.Handle("/ui/", mw.Middleware(uiHandler))
// downstream: sess, _ := middleware.SessionFromContext(r.Context())
// logout: mw.Logout(w, r)  // revokes from cookie; do not Revoke(sess.Token()) after Validate
```

## OIDC ID tokens (workload federation)

`oidc` verifies ID tokens minted by someone else — typically a CI job proving
who it is without a stored secret. It is not a login flow: the product
verifies the token, then maps a claim it trusts to its own authorisation.

```go
v, err := oidc.New(oidc.GitHubActions("glossa")) // issuer, RS256, sub + jti required
tok, err := v.Verify(ctx, rawIDToken)            // signature, iss, aud, exp/iat/nbf (±60 s)
gh, err := oidc.ParseGitHubActionsClaims(tok)
// Authorise on the immutable numeric IDs, never on names:
conn, err := store.GitConnectionByRepositoryID(ctx, gh.RepositoryID)
// then narrow if needed: gh.Ref, gh.EventName, gh.JobWorkflowRef, gh.RunnerEnvironment
```

The job side requests the token with that audience (`core.getIDToken("glossa")`,
or `ACTIONS_ID_TOKEN_REQUEST_URL&audience=glossa`). Any other issuer works the
same way through `oidc.Config{Issuer, Audiences, Algorithms, ...}`.

- **Keys.** `jwks_uri` comes from `{issuer}/.well-known/openid-configuration`,
  whose `issuer` must match exactly. HTTPS only (`AllowInsecureHTTPHosts` for
  tests), redirects are not followed, responses are capped at 1 MiB.
- **Cache.** Fetched on first use and kept for `Cache-Control: max-age`, clamped
  to [5 min, 24 h] (1 h without one). An unknown `kid` refetches — key rotation
  — single-flight and at most once per 30 s, so random kids cannot hammer the
  issuer. A failed refetch keeps the last good set serving — but only until
  `MaxStale` (default 24 h) after its fetch, so an attacker who keeps the JWKS
  endpoint unreachable cannot keep a revoked key trusted indefinitely. Past
  that, verification fails with `ErrKeySetUnavailable` until a refetch
  succeeds.
- **Parsing.** Canonical unpadded base64url only (no padding, whitespace or
  non-zero trailing bits), no duplicate JSON members, valid UTF-8, `kid`
  required, `crit` refused, and keys never taken from the token (`jku`, `jwk`,
  `x5u`, `x5c` are ignored).
- **Algorithms.** An allow-list (default `RS256`) that must also match the key's
  `kty`, curve and pinned `alg`. `none` and `HS*` cannot be configured, which
  rules out the public-key-as-HMAC-secret confusion.
- **Errors.** `ErrMalformed`, `ErrAlgorithm`, `ErrUnknownKey`, `ErrSignature`,
  `ErrIssuer`, `ErrAudience`, `ErrExpired`, `ErrNotYetValid`, `ErrMissingClaim`,
  `ErrKeySetUnavailable` — match with `errors.Is`; all mean "not authenticated".
- **Replay.** An ID token is a bearer credential until `exp`. Exchange it for a
  short-lived token of your own, and track `jti` if a replay inside that window
  matters.

## Sign in with GitHub (browser login)

`oauth` is the relying-party half of a browser sign-in. It ends in a verified
identity; the product then finds or creates its user and issues a session with
`SessionService` as for any other method.

```go
gh, _ := oauth.NewGitHub(oauth.GitHubConfig{
    ClientID: id, ClientSecret: secret,                    // an OAuth App; secret from env, never the DB
    RedirectURL: "https://app.example/auth/github/callback", // registered on the app, exactly
})
sealer, _ := oauth.NewStateSealer(stateKey, 0)            // 32-byte key; 10-minute TTL

// GET /auth/github: start
st, authURL, _ := gh.Begin("", time.Now())
cookie, _ := sealer.Seal(st)  // HttpOnly, Secure, SameSite=Lax, Max-Age=sealer.TTL(), Path=/auth/github
http.Redirect(w, r, authURL, http.StatusFound)

// GET /auth/github/callback: finish
if err := oauth.CallbackError(r.URL.Query()); err != nil { /* declined */ }
st, err := sealer.Open(cookieValue, r.URL.Query().Get("state"), time.Now()) // ErrState on CSRF/replay/expiry
id, err := gh.Complete(ctx, st, r.URL.Query().Get("code")) // ErrExchange, ErrUnverifiedEmail, ErrProvider
// key the account on id.UserID (immutable), never id.Login; id.Email is GitHub-verified
```

- **CSRF and code injection.** `state` is 256 random bits, compared in
  constant time against the sealed cookie, which expires; the PKCE verifier
  (S256) means a code intercepted on its way back cannot be exchanged
  without the browser's cookie. Clear the cookie after the callback.
- **Identity.** `Complete` reads `/user` and `/user/emails` and returns the
  primary address only if GitHub marks it verified (`ErrUnverifiedEmail`
  otherwise — a secondary verified address is not substituted). Match
  returning users on `UserID`; logins are renamed and re-registered.
- **Account linking.** Never merge an existing account into a GitHub sign-in
  because the e-mail matches: link a second method only from inside the
  signed-in account.
- **Token handling.** The access token is used for the two reads and
  dropped; it is not returned or logged. Requests are HTTPS-only, refuse
  redirects (the client secret is never replayed elsewhere), and cap
  responses at 1 MiB. Provider error descriptions are not echoed.

## Security posture

What the library guarantees, and where the deployment must meet it halfway:

- **Secrets at rest.** Session tokens, magic links, and workload keys are stored
  as SHA-256 hashes; passwords as argon2id. The TOTP shared secret is the one
  recoverable credential — `sqlite`/`pgstore` `NewTOTPRepo(db, cipher)` requires
  an `aesgcm` (or other) `SecretCipher` so it is encrypted at rest. Use
  `NewPlaintextTOTPRepo` only for tests or legacy migration.
- **Session cookie vs Session.Token().** `Issue` / `Rotate` return a Session
  whose `Token()` is the raw cookie value. After `Validate`, `Token()` is empty
  — the raw bearer is not recoverable from storage. Revoke with the cookie
  string (or `BasicAuthMiddleware.Logout`), never `Revoke(sess.Token())` from a
  validated session.
- **TOTP replay.** Use `TOTPService` (requires an `AtomicTOTPConsumer` repo —
  all first-party adapters). `TOTPConfig.Validate` remains available and is
  intentionally replay-prone within the skew window.
- **Magic links.** `Issue` invalidates prior unconsumed links for the same
  email+tenant so only the newly emailed token remains redeemable.
- **Tenant isolation.** `UserRepository.GetUser` is tenant-scoped: a `UserID`
  belonging to another tenant reads as `ErrNotFound` even though IDs are globally
  unique. This is defense in depth *alongside*, not instead of, database
  Row-Level Security — enable RLS on the Postgres tables (`tenant_id` derived
  server-side, never from the client).
- **CSRF.** The session cookie defaults to `SameSite=Lax` + `HttpOnly` +
  `Secure`. `Lax` blocks cross-site state-changing requests but is not a complete
  defense; pair state-changing endpoints with an app-layer anti-CSRF token or an
  `Origin`/`Sec-Fetch-Site` check. Use `SameSite=Strict` where no cross-site
  authenticated navigation is needed.
- **Brute-force lockout.** Per-account lockout means an attacker who knows an
  email can lock that account on purpose; the lock expires (`Window`) so the
  victim self-recovers. Also throttle on a network identity (client IP) at the
  edge so one source can't drive another account's counter. Prefer
  `LockoutKeyFromEmail` so `authgo_login_attempts` does not store plaintext
  email.
- **Input bounds.** Value-object constructors cap length (email 254, id/worker
  255, token 4096, password 1024, lockout key 255) so an unbounded
  attacker-controlled field can't be hashed or stored.
- **Passkey ceremony state.** WebAuthn ceremony state is HMAC-SHA256-signed with
  a required `Config.StateKey` (≥32 bytes), so a client cannot swap the UserID.
  Still treat the blob as a secret single-use challenge; prefer server-side
  storage. See `adapters/webauthn` package docs.

## Engineering bar

Per the Klarlabs default: TDD, gofmt, golangci-lint (gocritic + gosec), nox
security scan, coverctl coverage gate, strict DDD. CI is the shared
`klarlabs-studio/.github` reusable Go workflow. Postgres adapter tests are
integration-gated on `TEST_DATABASE_URL`. MIT.
