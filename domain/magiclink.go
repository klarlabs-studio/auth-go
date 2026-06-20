package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// MagicLink is an aggregate: a single-use, time-boxed email login token. Only
// the SHA-256 hash of the raw token is persisted; the raw token lives solely
// in the emailed URL. Construct through MagicLinkService.Issue.
type MagicLink struct {
	hash      string
	email     Email
	tenantID  TenantID
	expiresAt time.Time
	consumed  bool
}

// Hash returns the storage key (hex SHA-256 of the raw token).
func (m MagicLink) Hash() string { return m.hash }

// Email returns the recipient.
func (m MagicLink) Email() Email { return m.email }

// TenantID returns the owning tenant.
func (m MagicLink) TenantID() TenantID { return m.tenantID }

// ExpiresAt returns the expiry.
func (m MagicLink) ExpiresAt() time.Time { return m.expiresAt }

// Consumed reports whether the link was already used.
func (m MagicLink) Consumed() bool { return m.consumed }

// Expired reports whether the link has expired as of now.
func (m MagicLink) Expired(now time.Time) bool { return !now.Before(m.expiresAt) }

// HashToken returns the hex SHA-256 of a raw token — the storage key. Exposed
// so services and adapters agree on the keying without duplicating it.
func HashToken(raw Token) string {
	return hashString(raw.v)
}

// hashString returns the hex SHA-256 of s. Shared by the token-hashing helpers
// so the keying is defined in exactly one place.
func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// MagicLinkSnapshot is the flat, exportable shape for persistence.
type MagicLinkSnapshot struct {
	Hash      string
	Email     string
	TenantID  string
	ExpiresAt time.Time
	Consumed  bool
}

// Snapshot exports the link for storage.
func (m MagicLink) Snapshot() MagicLinkSnapshot {
	return MagicLinkSnapshot{
		Hash:      m.hash,
		Email:     m.email.v,
		TenantID:  m.tenantID.v,
		ExpiresAt: m.expiresAt,
		Consumed:  m.consumed,
	}
}

// MagicLinkFromSnapshot rehydrates a link from storage. Adapter-only.
func MagicLinkFromSnapshot(s MagicLinkSnapshot) MagicLink {
	return MagicLink{
		hash:      s.Hash,
		email:     Email{v: s.Email},
		tenantID:  TenantID{v: s.TenantID},
		expiresAt: s.ExpiresAt,
		consumed:  s.Consumed,
	}
}

// MagicLinkRepository is the persistence port for magic links. Every method
// takes a context.Context first so storage I/O honors cancellation, deadlines,
// and trace propagation.
type MagicLinkRepository interface {
	Save(ctx context.Context, m MagicLink) error
	FindByHash(ctx context.Context, hash string) (MagicLink, error)
	MarkConsumed(ctx context.Context, hash string) error
}
