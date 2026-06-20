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
type Session struct {
	token     Token
	userID    UserID
	tenantID  TenantID
	createdAt time.Time
	expiresAt time.Time
}

// Token returns the session token (cookie value).
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
func (s Session) IsZero() bool { return s.token.v == "" }

// SessionSnapshot is the flat, exportable shape of a Session for persistence.
// Repository adapters convert between Session and SessionSnapshot; the
// aggregate's fields stay unexported so invariants cannot be bypassed.
type SessionSnapshot struct {
	Token     string
	UserID    string
	TenantID  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Snapshot exports the session for storage.
func (s Session) Snapshot() SessionSnapshot {
	return SessionSnapshot{
		Token:     s.token.v,
		UserID:    s.userID.v,
		TenantID:  s.tenantID.v,
		CreatedAt: s.createdAt,
		ExpiresAt: s.expiresAt,
	}
}

// SessionFromSnapshot rehydrates a Session from storage without re-validating
// entropy (the token already existed). Used only by repository adapters.
func SessionFromSnapshot(s SessionSnapshot) Session {
	return Session{
		token:     Token{v: s.Token},
		userID:    UserID{v: s.UserID},
		tenantID:  TenantID{v: s.TenantID},
		createdAt: s.CreatedAt,
		expiresAt: s.ExpiresAt,
	}
}

// SessionRepository is the persistence port for sessions. Implementations must
// be safe for concurrent use. Every method takes a context.Context first so
// storage I/O honors cancellation, deadlines, and trace propagation.
type SessionRepository interface {
	Save(ctx context.Context, s Session) error
	FindByToken(ctx context.Context, token Token) (Session, error)
	Delete(ctx context.Context, token Token) error
	DeleteByUser(ctx context.Context, userID UserID) error
}
