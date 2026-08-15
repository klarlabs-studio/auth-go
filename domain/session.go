package domain

import (
	"context"
	"time"
)

// Session is an aggregate: an authenticated server-side session. The opaque
// Token rides in an HttpOnly cookie; everything else stays server-side.
//
// Construct sessions through SessionService.Issue, never by hand — the service
// enforces the entropy and expiry invariants.
//
// Token() returns the raw cookie value only on the Issue/Rotate success path.
// After Validate (or any FindByToken hydrate), the raw bearer is not recoverable
// from the Session — only its at-rest hash is. Revoke and Rotate take the raw
// cookie from the request, not sess.Token() from a validated Session.
type Session struct {
	token     Token  // raw bearer; set only on Issue/Rotate; zero after hydrate
	tokenHash string // SHA-256 hex at-rest key; always set for a live session
	userID    UserID
	tenantID  TenantID
	createdAt time.Time
	expiresAt time.Time
}

// Token returns the raw session cookie value when available (immediately after
// Issue or Rotate). After Validate / repository hydrate the raw value is not
// present — Token() is the zero Token. Callers must revoke or rotate with the
// cookie string from the request, not with sess.Token() from a validated
// Session (that pattern hashed-the-hash and silently failed to delete).
func (s Session) Token() Token { return s.token }

// UserID returns the owning user.
func (s Session) UserID() UserID { return s.userID }

// TenantID returns the owning tenant.
func (s Session) TenantID() TenantID { return s.tenantID }

// CreatedAt returns the issue time.
func (s Session) CreatedAt() time.Time { return s.createdAt }

// ExpiresAt returns the expiry.
func (s Session) ExpiresAt() time.Time { return s.expiresAt }

// Expired reports whether the session has expired as of now.
func (s Session) Expired(now time.Time) bool { return !now.Before(s.expiresAt) }

// IsZero reports whether the session is the zero value.
func (s Session) IsZero() bool { return s.tokenHash == "" && s.token.v == "" }

// SessionSnapshot is the flat, exportable shape of a Session for persistence.
// Repository adapters convert between Session and SessionSnapshot; the
// aggregate's fields stay unexported so invariants cannot be bypassed.
type SessionSnapshot struct {
	Token     string // at-rest SHA-256 hash of the bearer token, never the raw value
	UserID    string
	TenantID  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Snapshot exports the session for storage. Token holds the SHA-256 hash of the
// bearer token, never the raw value — the raw token lives only in the cookie, so
// a read of the session store (backup, replica, injection) yields hashes, not
// usable cookies. Matches the magic-link and workload-key hash-at-rest pattern;
// lookups hash the incoming cookie token the same way (see SessionService).
func (s Session) Snapshot() SessionSnapshot {
	hash := s.tokenHash
	if hash == "" && s.token.v != "" {
		hash = HashToken(s.token)
	}
	return SessionSnapshot{
		Token:     hash,
		UserID:    s.userID.v,
		TenantID:  s.tenantID.v,
		CreatedAt: s.createdAt,
		ExpiresAt: s.expiresAt,
	}
}

// SessionFromSnapshot rehydrates a Session from storage without re-validating
// entropy (the token already existed). Used only by repository adapters.
//
// The snapshot's Token field is the at-rest hash. The raw cookie value is not
// recoverable; Token() on the result is zero. See Session.Token.
func SessionFromSnapshot(s SessionSnapshot) Session {
	return Session{
		tokenHash: s.Token,
		userID:    UserID{v: s.UserID},
		tenantID:  TenantID{v: s.TenantID},
		createdAt: s.CreatedAt,
		expiresAt: s.ExpiresAt,
	}
}

// SessionRepository is the persistence port for sessions. Implementations must
// be safe for concurrent use. Every method takes a context.Context first so
// storage I/O honors cancellation, deadlines, and trace propagation.
//
// FindByToken and Delete key on the at-rest hash (SessionService wraps the raw
// cookie with sessionKey before calling). Save persists Session.Snapshot().
type SessionRepository interface {
	Save(ctx context.Context, s Session) error
	FindByToken(ctx context.Context, token Token) (Session, error)
	Delete(ctx context.Context, token Token) error
	DeleteByUser(ctx context.Context, userID UserID) error
}

// AtomicSessionRotator is an optional SessionRepository capability: replace an
// old session with a new one in a single atomic step. SessionService.Rotate
// prefers it when available so a crash cannot leave two live tokens (or lose
// both). The sqlite and pgstore adapters implement it; memory does too (under
// its mutex). Without it Rotate falls back to create-then-delete with a brief
// overlap window, matching WorkloadKeyService.RotateKey.
type AtomicSessionRotator interface {
	// RotateAtomically deletes the session keyed by oldKey (the at-rest hash,
	// matching FindByToken/Delete) and inserts newSess in one atomic operation.
	// Returns ErrNotFound if oldKey is absent.
	RotateAtomically(ctx context.Context, oldKey Token, newSess Session) error
}
