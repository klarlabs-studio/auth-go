package domain

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"
)

// Clock returns the current time. Injected for deterministic tests.
type Clock func() time.Time

// SystemClock is the default wall-clock.
func SystemClock() time.Time { return time.Now() }

func orSystemClock(c Clock) Clock {
	if c == nil {
		return SystemClock
	}
	return c
}

// SessionService is a domain service issuing and validating sessions over a
// SessionRepository. It owns the entropy and expiry invariants.
type SessionService struct {
	repo SessionRepository
	ttl  time.Duration
	now  Clock
}

// NewSessionService builds the service. ttl is the session lifetime.
func NewSessionService(repo SessionRepository, ttl time.Duration, clock Clock) *SessionService {
	return &SessionService{repo: repo, ttl: ttl, now: orSystemClock(clock)}
}

// Issue creates and persists a fresh session for a user/tenant.
func (s *SessionService) Issue(userID UserID, tenantID TenantID) (Session, error) {
	if userID.IsZero() {
		return Session{}, ErrInvalidUserID
	}
	if tenantID.IsZero() {
		return Session{}, ErrInvalidTenantID
	}
	tok, err := NewToken()
	if err != nil {
		return Session{}, err
	}
	t := s.now()
	sess := Session{
		token:     tok,
		userID:    userID,
		tenantID:  tenantID,
		createdAt: t,
		expiresAt: t.Add(s.ttl),
	}
	if err := s.repo.Save(sess); err != nil {
		return Session{}, err
	}
	return sess, nil
}

// Validate returns the session for a token, deleting and rejecting it if
// expired. Returns ErrNotFound / ErrExpired otherwise.
func (s *SessionService) Validate(token Token) (Session, error) {
	sess, err := s.repo.FindByToken(token)
	if err != nil {
		return Session{}, err
	}
	if sess.Expired(s.now()) {
		_ = s.repo.Delete(token)
		return Session{}, ErrExpired
	}
	return sess, nil
}

// Revoke deletes one session (logout).
func (s *SessionService) Revoke(token Token) error { return s.repo.Delete(token) }

// RevokeAll deletes every session for a user (logout-everywhere).
func (s *SessionService) RevokeAll(userID UserID) error { return s.repo.DeleteByUser(userID) }

// MagicLinkService is a domain service issuing and consuming magic links.
type MagicLinkService struct {
	repo MagicLinkRepository
	ttl  time.Duration
	now  Clock
}

// NewMagicLinkService builds the service. ttl is the link lifetime (standard: 15m).
func NewMagicLinkService(repo MagicLinkRepository, ttl time.Duration, clock Clock) *MagicLinkService {
	return &MagicLinkService{repo: repo, ttl: ttl, now: orSystemClock(clock)}
}

// Issue creates a link and returns the RAW token to embed in the emailed URL.
// The raw token is never persisted — only its hash.
func (s *MagicLinkService) Issue(email Email, tenantID TenantID) (Token, error) {
	if tenantID.IsZero() {
		return Token{}, ErrInvalidTenantID
	}
	raw, err := NewToken()
	if err != nil {
		return Token{}, err
	}
	t := s.now()
	link := MagicLink{
		hash:      HashToken(raw),
		email:     email,
		tenantID:  tenantID,
		expiresAt: t.Add(s.ttl),
	}
	if err := s.repo.Save(link); err != nil {
		return Token{}, err
	}
	return raw, nil
}

// Consume validates a raw token and, on success, marks it consumed and returns
// the link. Returns ErrNotFound / ErrExpired / ErrConsumed otherwise.
func (s *MagicLinkService) Consume(raw Token) (MagicLink, error) {
	link, err := s.repo.FindByHash(HashToken(raw))
	if err != nil {
		return MagicLink{}, err
	}
	if link.consumed {
		return MagicLink{}, ErrConsumed
	}
	if link.Expired(s.now()) {
		return MagicLink{}, ErrExpired
	}
	if err := s.repo.MarkConsumed(link.hash); err != nil {
		return MagicLink{}, err
	}
	link.consumed = true
	return link, nil
}

// KeyClaims is the validated, read-only result of authenticating a workload
// token: the worker the key belongs to and the capabilities it grants.
type KeyClaims struct {
	WorkerID WorkerID
	Scope    Scope
}

// KeyRequest is the input to WorkloadKeyService.IssueKey — the worker, the
// granted scope, and the absolute expiry instant.
type KeyRequest struct {
	WorkerID  WorkerID
	Scope     Scope
	ExpiresAt time.Time
}

// WorkloadKeyService is a domain service issuing, validating, authorizing,
// rotating, and revoking scoped API keys for agent workers over a
// WorkloadStore. It owns the entropy, hashing, and expiry invariants. The raw
// token is returned exactly once (at issue/rotate); only its hash is persisted.
type WorkloadKeyService struct {
	store WorkloadStore
	now   Clock
	newID func() (KeyID, error)
}

// NewWorkloadKeyService builds the service. A nil clock uses the wall clock.
func NewWorkloadKeyService(store WorkloadStore, clock Clock) *WorkloadKeyService {
	return &WorkloadKeyService{store: store, now: orSystemClock(clock), newID: randomKeyID}
}

// randomKeyID returns an opaque, high-entropy key identifier. It is not a
// credential — it is safe to log and surface for revocation/rotation.
func randomKeyID() (KeyID, error) {
	tok, err := NewWorkloadToken()
	if err != nil {
		return "", err
	}
	return KeyID("wk_" + tok.String()), nil
}

// IssueKey generates a fresh token, persists only its hash, and returns the new
// APIKey plus the RAW token — which the caller must surface to the worker
// immediately, as it is never recoverable again.
func (s *WorkloadKeyService) IssueKey(ctx context.Context, req KeyRequest) (APIKey, WorkloadToken, error) {
	key, raw, err := s.issue(req)
	if err != nil {
		return APIKey{}, WorkloadToken{}, err
	}
	if err := s.store.CreateKey(ctx, key); err != nil {
		return APIKey{}, WorkloadToken{}, err
	}
	return key, raw, nil
}

// issue builds (but does not persist) a fresh APIKey from a request, enforcing
// the request invariants. Shared by IssueKey and RotateKey.
func (s *WorkloadKeyService) issue(req KeyRequest) (APIKey, WorkloadToken, error) {
	if req.WorkerID.IsZero() {
		return APIKey{}, WorkloadToken{}, ErrInvalidWorkerID
	}
	if req.Scope.IsZero() {
		return APIKey{}, WorkloadToken{}, ErrInvalidScope
	}
	now := s.now()
	// Expiry must be strictly in the future; an at-or-before-now expiry would
	// issue a dead-on-arrival key.
	if !req.ExpiresAt.After(now) {
		return APIKey{}, WorkloadToken{}, ErrInvalidExpiry
	}
	raw, err := NewWorkloadToken()
	if err != nil {
		return APIKey{}, WorkloadToken{}, err
	}
	id, err := s.newID()
	if err != nil {
		return APIKey{}, WorkloadToken{}, err
	}
	key := APIKey{
		id:        id,
		hash:      HashWorkloadToken(raw),
		workerID:  req.WorkerID,
		scope:     req.Scope,
		expiresAt: req.ExpiresAt,
		createdAt: now,
	}
	return key, raw, nil
}

// ValidateKey hashes an inbound token, looks the key up, and enforces expiry,
// returning the worker + scope claims. Returns ErrKeyNotFound for an unknown
// token and ErrKeyExpired for an expired one. The lookup is keyed on the
// SHA-256 of the token, so the row is already selected by token hash; the
// constant-time re-comparison below is belt-and-suspenders consistency with the
// rest of the library (password.go/totp.go), not the primary security boundary.
func (s *WorkloadKeyService) ValidateKey(ctx context.Context, token WorkloadToken) (KeyClaims, error) {
	want := HashWorkloadToken(token)
	key, err := s.store.GetKeyByHash(ctx, want)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return KeyClaims{}, ErrKeyNotFound
		}
		return KeyClaims{}, err
	}
	// Re-verify the stored hash against the inbound token's hash in constant
	// time; a mismatch (e.g. a corrupted or substituted row) is treated as an
	// unknown key.
	if subtle.ConstantTimeCompare([]byte(key.Hash()), []byte(want)) != 1 {
		return KeyClaims{}, ErrKeyNotFound
	}
	if key.Expired(s.now()) {
		return KeyClaims{}, ErrKeyExpired
	}
	return KeyClaims{WorkerID: key.workerID, Scope: key.scope}, nil
}

// Authorize validates a token and checks its scope against a concrete
// "resource:action" permission. Returns ErrInvalidScope for a malformed
// permission, ErrScopeDenied when the key's scope does not cover it, and the
// validation errors (ErrKeyNotFound / ErrKeyExpired) otherwise.
func (s *WorkloadKeyService) Authorize(ctx context.Context, token WorkloadToken, permission string) error {
	perm, err := NewPermission(permission)
	if err != nil {
		return err
	}
	claims, err := s.ValidateKey(ctx, token)
	if err != nil {
		return err
	}
	if !claims.Scope.Allows(perm) {
		return ErrScopeDenied
	}
	return nil
}

// RevokeKey deletes one key by ID. Returns ErrKeyNotFound if absent.
func (s *WorkloadKeyService) RevokeKey(ctx context.Context, id KeyID) error {
	if err := s.store.DeleteKey(ctx, id); err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrKeyNotFound
		}
		return err
	}
	return nil
}

// RevokeAllKeys deletes every key for a worker (kill-switch).
func (s *WorkloadKeyService) RevokeAllKeys(ctx context.Context, workerID WorkerID) error {
	keys, err := s.store.ListKeysByWorker(ctx, workerID)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := s.store.DeleteKey(ctx, k.id); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}

// ListKeys returns every key for a worker. Keys carry only their hash, never
// the raw token, so they are safe to return for inventory/management UIs.
func (s *WorkloadKeyService) ListKeys(ctx context.Context, workerID WorkerID) ([]APIKey, error) {
	return s.store.ListKeysByWorker(ctx, workerID)
}

// RotateKey issues a replacement key — same worker, scope, and expiry — and
// invalidates the old one, returning the new APIKey and its RAW token.
//
// This is NOT transactional across stores. It creates the new key first, then
// deletes the old one, so the two keys briefly OVERLAP (both valid) — there is
// never a gap with no usable key. If deleting the old key fails, the new key is
// rolled back on a best-effort basis (its delete is attempted and its error
// ignored) and the original delete error is surfaced. Over a non-transactional
// store these steps are not atomic; a crash between create and delete can leave
// both keys live until the old one expires or is revoked.
func (s *WorkloadKeyService) RotateKey(ctx context.Context, id KeyID) (APIKey, WorkloadToken, error) {
	old, err := s.store.GetKey(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return APIKey{}, WorkloadToken{}, ErrKeyNotFound
		}
		return APIKey{}, WorkloadToken{}, err
	}
	newKey, raw, err := s.issue(KeyRequest{
		WorkerID:  old.workerID,
		Scope:     old.scope,
		ExpiresAt: old.expiresAt,
	})
	if err != nil {
		return APIKey{}, WorkloadToken{}, err
	}
	if err := s.store.CreateKey(ctx, newKey); err != nil {
		return APIKey{}, WorkloadToken{}, err
	}
	if err := s.store.DeleteKey(ctx, old.id); err != nil {
		// Roll back the new key so we don't leave two live keys after a failed
		// rotation; best-effort cleanup, original error is surfaced.
		_ = s.store.DeleteKey(ctx, newKey.id)
		return APIKey{}, WorkloadToken{}, err
	}
	return newKey, raw, nil
}
