# Changelog

All notable changes to auth-go are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (pre-1.0:
breaking changes bump the minor version).

## [Unreleased]

## [0.7.2] - 2026-08-29

### Fixed

- `pgstore.LoginAttemptRepo.RecordFailureAtomically` failed on every call with
  SQLSTATE 42804, so **account lockout was inert for every Postgres consumer**.
  `CASE WHEN … THEN $4 ELSE NULL END` has two untyped branches, so Postgres
  resolved the expression as `text` and refused to assign it to a `timestamptz`
  column. The `$4::timestamptz` casts are the fix.

  The failure was total and silent: the table was created, no row was ever
  written, and a failure count that never rises looks exactly like an account
  nobody is attacking. `LockoutService` reported no lock because the store never
  recorded one.

  `memory` and `sqlite` had tests for this method and passed — sqlite is
  dynamically typed, so the same SQL is valid there. The only adapter that could
  fail was the only adapter without a test, and CI ran no Postgres at all, so
  every pgstore test skipped while the package still printed `ok`.

### Added

- A `pgstore` CI job with a Postgres service, and a step that fails if those
  tests skip. A skipped test and a passing test are indistinguishable in a
  normal summary, which is how the above survived.

## [0.7.1] - 2026-08-29

### Added

- `MagicLinkService.Peek` — validate a link without spending it. Returns the
  same `ErrNotFound` / `ErrExpired` / `ErrConsumed` conditions as `Consume` but
  never marks the link, so a caller can answer "is this link good?" before
  acting on it.

  Single-use links are routinely *opened* before they are *accepted*. Any
  consumer that shows the recipient something first — an authenticator QR to
  scan, "you have been invited to Acme, continue?", a password field — runs code
  on page load, and if that code consumes, then a reload, a browser prerender,
  or opening the link on a phone instead of a laptop destroys it. The
  recipient's most natural recovery action is the one that makes recovery
  impossible.

  With only `Issue` and `Consume`, every such consumer builds the same
  compensating table: remember which links were opened and serve repeats from
  that record. That is duplicated per consumer, security-relevant, and easy to
  get subtly wrong.

  `Peek` does not weaken single-use — it reports, it never marks. Spend the link
  with `Consume` at the moment the recipient commits. Note that a successful
  `Peek` is **not** authentication: two people holding the same link both peek
  successfully. Authenticate with `Consume`.

## [0.7.0] - 2026-08-15

Security and DX hardening from the post-0.6.0 review, plus polish.

### Changed (breaking)

- **`Session.Token()` after Validate is empty**: hydrated sessions no longer
  put the at-rest hash in `Token()`. The raw cookie value is only present on
  the Issue/Rotate success path. `Revoke(sess.Token())` after Validate now
  returns `ErrInvalidToken` instead of silently hashing-the-hash. Use the
  request cookie (or `middleware.BasicAuthMiddleware.Logout`) to revoke.
- **`NewTOTPService` requires `AtomicTOTPConsumer`**: repositories that cannot
  consume time steps fail at construction with `ErrTOTPNoReplayProtection`
  instead of verifying with silent replay. First-party adapters already
  implement the capability; use `TOTPConfig.Validate` for intentional
  stateless checks.
- **`Authenticator.Authenticate` takes `context.Context`**: credential I/O
  honors request cancellation/deadlines/trace.
- **WebAuthn `Config.StateKey` is required** (≥32 bytes): ceremony state is
  HMAC-SHA256-signed so a client-tampered UserID is rejected
  (`ErrInvalidState`).
- **`sqlite`/`pgstore` `NewTOTPRepo(db, cipher)` requires a cipher**: secrets
  are encrypted at rest by default. Use `NewPlaintextTOTPRepo` only for tests
  or legacy migration. `WithCipher` option removed.
- **`MagicLinkRepository.InvalidateOutstanding`**: `Issue` invalidates prior
  unconsumed links for the same email+tenant so only the newly emailed token
  is live.

### Added

- `AtomicSessionRotator` port; memory/sqlite/pgstore session repos implement
  it so `SessionService.Rotate` swaps in one atomic step.
- `AtomicMagicLinkIssuer` port; Issue invalidate+save is atomic on
  memory/sqlite/pgstore.
- Memory `WorkloadKeyRepo` implements `AtomicRotator` (mutex swap).
- `LockoutKeyFromEmail` helper (SHA-256 hex) so lockout keys need not store
  plaintext email.
- Password plaintext length bound (1024) and `Argon2idParams.Validate`;
  `WorkerID` / lockout key length caps (255).
- `middleware.BasicAuthMiddleware.Logout` — revoke from cookie + clear.
- gosec enabled in `.golangci.yml`.
- Examples updated for `TOTPService`, magic-link re-issue, and WebAuthn
  `StateKey`.

### Fixed

- Basic auth `Realm` rejects `"` / `\` / controls that break
  `WWW-Authenticate`.

## [0.6.0] - 2026-07-05

A security-hardening release closing every finding from a full deep review. The
cryptographic primitives were already sound; each change here closes a
**stateful** gap — non-atomic ports, plaintext-at-rest, and ceremony hardening.

### Changed (breaking)

- **`UserRepository.GetUser` is now tenant-scoped**: `GetUser(ctx, id)` →
  `GetUser(ctx, tenantID, id)`. A `UserID` belonging to another tenant now reads
  as `ErrNotFound` even though IDs are globally unique — defense in depth
  alongside database Row-Level Security, and the only such control for the
  in-memory adapter. Thread the tenant through every call site. (#18)

### Added

- Optional **encryption-at-rest for the TOTP secret** — the one recoverable
  credential (RFC 6238 needs the raw secret). New `domain.SecretCipher` AEAD
  port, a ready `aesgcm` AES-256-GCM implementation, and a non-breaking
  `WithCipher` option on the sqlite/pgstore `TOTPRepo`. Without it, behavior is
  unchanged. (#19)
- `TOTPService` for replay-safe TOTP verification, plus the optional
  `AtomicTOTPConsumer` port and the `authgo_totp_used_steps` table. (#17)
- Value-object length bounds (email 254, user/tenant id 255, token 4096). (#18)
- Security-posture documentation: CSRF/SameSite, per-account lockout DoS, tenant
  RLS, and secrets-at-rest guidance (README + godoc). (#18)

### Fixed

- **Session tokens are hashed at rest** — sessions were the lone bearer secret
  stored and looked up by raw token; they now persist a SHA-256 hash. (#13)
- **WebAuthn ceremony hardening** — `FinishLogin` rejects a cloned authenticator
  (`ErrCredentialCloned`), enforces challenge expiry, and defaults
  user-verification to *required*. (#14)
- **Magic-link single-use made atomic** — redemption is now a conditional
  `UPDATE … WHERE consumed = 0`; a concurrent race yields `ErrConsumed`. (#15)
- **Lockout increment made atomic** — `RecordFailure` no longer loses increments
  under concurrency; adapters record-and-lock in one UPSERT via the optional
  `AtomicLoginAttemptStore`. (#16)
- **TOTP codes are single-use** — a valid code was replayable for its whole
  ±skew window (RFC 6238 §5.2); a replay now returns `ErrTOTPReused`. The
  stateless `TOTPConfig.Validate` is retained and documented as replay-prone.
  (#17)
- Memory `PasskeyRepo` no longer aliases the caller's `ID`/`PublicKey` byte
  slices — `Add`/`ListByUser` clone them. (#18)

## [0.5.0] - 2026-06-20

### Added

- `User` entity and `UserRepository` port with in-memory, SQLite, and Postgres
  adapters.
- `SessionService.Rotate` for session re-issuance (session-fixation mitigation).
- `TOTPRepository` port and adapters for enrolled-secret persistence.
- Atomic workload-key rotation on the SQL adapters (`AtomicRotator`).

## [0.4.0] - 2026-06-20

### Added

- Scoped API keys for agent workers: the `WorkloadKey` domain, in-memory and
  Postgres `WorkloadStore` adapters, and schema.
- SQLite storage adapter.

### Changed

- Threaded `context.Context` through all services and ports.
- Converged sqlite/pgstore on a single ctx-aware `DB` interface.
- Dedicated 16-byte `KeyID` generator; dropped the unused `UpdateKey` port.

### Fixed

- Reject malformed workload scope segments.
- Constant-time token verification in `WorkloadKeyService.ValidateKey`.

## [0.3.0] - 2026-06-09

### Added

- Account-lockout policy and `LoginAttemptStore` port.
- Basic-auth handshake middleware (Basic credential → server-side session).

## [0.2.0] - 2026-06-08

### Changed

- Packaging and CI hardening on top of the initial release.

## [0.1.0] - 2026-06-08

### Added

- Initial release: the auth bounded context with strict DDD layout — magic
  links, password + TOTP, passkeys (WebAuthn), and server-side sessions.

[Unreleased]: https://github.com/klarlabs-studio/auth-go/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/klarlabs-studio/auth-go/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/klarlabs-studio/auth-go/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/klarlabs-studio/auth-go/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/klarlabs-studio/auth-go/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/klarlabs-studio/auth-go/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/klarlabs-studio/auth-go/releases/tag/v0.1.0
