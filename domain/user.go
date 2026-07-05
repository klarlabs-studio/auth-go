package domain

import (
	"context"
	"time"
)

// User is an aggregate: the human principal an authentication flow resolves to.
// It is intentionally minimal — auth-go answers "who are you?", not "what may
// you do?" — so a User carries only its identity (ID), the tenant it belongs to,
// its login email, and persistence bookkeeping timestamps. Roles, profile data,
// and application attributes live in the consuming product, not here.
//
// Construct through NewUser, which enforces the value-object invariants, never
// by hand. Adapters rehydrate from storage through UserFromSnapshot.
type User struct {
	id        UserID
	tenantID  TenantID
	email     Email
	createdAt time.Time
	updatedAt time.Time
}

// NewUser validates and constructs a User. id, tenantID, and email are required
// value objects (already validated by their own constructors); the caller passes
// the issue/update instants so the clock stays injectable and tests stay
// deterministic. A zero createdAt/updatedAt is permitted — adapters may stamp
// them — but the three identity fields must be non-zero.
func NewUser(id UserID, tenantID TenantID, email Email, createdAt, updatedAt time.Time) (User, error) {
	if id.IsZero() {
		return User{}, ErrInvalidUserID
	}
	if tenantID.IsZero() {
		return User{}, ErrInvalidTenantID
	}
	if email.String() == "" {
		return User{}, ErrInvalidEmail
	}
	return User{
		id:        id,
		tenantID:  tenantID,
		email:     email,
		createdAt: createdAt,
		updatedAt: updatedAt,
	}, nil
}

// ID returns the user identifier.
func (u User) ID() UserID { return u.id }

// TenantID returns the owning tenant.
func (u User) TenantID() TenantID { return u.tenantID }

// Email returns the login email.
func (u User) Email() Email { return u.email }

// CreatedAt returns the creation instant.
func (u User) CreatedAt() time.Time { return u.createdAt }

// UpdatedAt returns the last-update instant.
func (u User) UpdatedAt() time.Time { return u.updatedAt }

// IsZero reports whether the User is the zero value.
func (u User) IsZero() bool { return u.id.IsZero() }

// UserSnapshot is the flat, exportable shape of a User for persistence.
// Adapters convert between User and UserSnapshot; the aggregate's fields stay
// unexported so invariants cannot be bypassed.
type UserSnapshot struct {
	ID        string
	TenantID  string
	Email     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Snapshot exports the user for storage.
func (u User) Snapshot() UserSnapshot {
	return UserSnapshot{
		ID:        u.id.v,
		TenantID:  u.tenantID.v,
		Email:     u.email.v,
		CreatedAt: u.createdAt,
		UpdatedAt: u.updatedAt,
	}
}

// UserFromSnapshot rehydrates a User from storage without re-validating the
// value objects (they already existed). Used only by repository adapters.
func UserFromSnapshot(s UserSnapshot) User {
	return User{
		id:        UserID{v: s.ID},
		tenantID:  TenantID{v: s.TenantID},
		email:     Email{v: s.Email},
		createdAt: s.CreatedAt,
		updatedAt: s.UpdatedAt,
	}
}

// UserRepository is the persistence port for users. It is the spec's Store
// GetUser/UpsertUser pair, modeled as a focused port in line with the rest of
// the domain. Implementations must be safe for concurrent use. Every method
// takes a context.Context first so storage I/O honors cancellation, deadlines,
// and trace propagation.
type UserRepository interface {
	// GetUser returns the user with id within tenantID, or ErrNotFound. The
	// lookup is scoped to the tenant so a UserID belonging to another tenant is
	// never resolved across the boundary even though IDs are globally unique —
	// defense in depth alongside (not a replacement for) database Row-Level
	// Security. A user that exists under a different tenant reads as ErrNotFound.
	GetUser(ctx context.Context, tenantID TenantID, id UserID) (User, error)
	// UpsertUser inserts or updates a user, keyed on its ID. The tenant is taken
	// from the User aggregate, which carries its own validated TenantID.
	UpsertUser(ctx context.Context, u User) error
}
