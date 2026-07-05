// Package domain is the auth bounded context. It holds the entities, value
// objects, domain services, and repository ports for Klarlabs authentication.
//
// The domain never imports infrastructure. Persistence and the WebAuthn
// ceremony engine are injected through the ports defined here; adapters under
// ../adapters implement them. Value objects enforce their own invariants in
// validating constructors — there are no anemic models.
package domain

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// Length bounds for the value objects. Every constructor caps its input so a
// single over-long field can't be used to force outsized allocations, hashing,
// or storage — an unauthenticated caller controls the email and (via a cookie)
// the token, so the bound is a cheap denial-of-service floor, not a business
// rule. The caps are deliberately generous: real identifiers, addresses, and
// tokens sit far below them.
const (
	maxUserIDLen   = 255  // product-chosen key (UUID/ULID/external id)
	maxTenantIDLen = 255  // product-chosen key
	maxEmailLen    = 254  // RFC 5321 §4.5.3.1.3 maximum path length
	maxTokenLen    = 4096 // >> a 43-char base64 token; a browser cookie cap
)

// UserID identifies a user within a tenant. Opaque, non-empty.
type UserID struct{ v string }

// NewUserID validates and constructs a UserID.
func NewUserID(s string) (UserID, error) {
	if strings.TrimSpace(s) == "" || len(s) > maxUserIDLen {
		return UserID{}, ErrInvalidUserID
	}
	return UserID{v: s}, nil
}

// String returns the raw identifier.
func (u UserID) String() string { return u.v }

// IsZero reports whether the UserID is unset.
func (u UserID) IsZero() bool { return u.v == "" }

// TenantID identifies a tenant (organization or individual). Opaque, non-empty.
type TenantID struct{ v string }

// NewTenantID validates and constructs a TenantID.
func NewTenantID(s string) (TenantID, error) {
	if strings.TrimSpace(s) == "" || len(s) > maxTenantIDLen {
		return TenantID{}, ErrInvalidTenantID
	}
	return TenantID{v: s}, nil
}

// String returns the raw identifier.
func (t TenantID) String() string { return t.v }

// IsZero reports whether the TenantID is unset.
func (t TenantID) IsZero() bool { return t.v == "" }

// Email is a validated email address value object.
type Email struct{ v string }

// NewEmail validates (minimally) and normalizes an email to lower case.
func NewEmail(s string) (Email, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	at := strings.IndexByte(s, '@')
	// require a local part, an '@', a dot in the domain part, and a length within
	// the RFC 5321 maximum (rejects an over-long address before it is stored).
	if at <= 0 || at == len(s)-1 || len(s) > maxEmailLen || !strings.Contains(s[at+1:], ".") {
		return Email{}, ErrInvalidEmail
	}
	return Email{v: s}, nil
}

// String returns the normalized address.
func (e Email) String() string { return e.v }

// Token is an opaque, high-entropy credential — a session token or the raw
// half of a magic link. Construct random tokens with NewToken.
type Token struct{ v string }

// tokenBytes is the entropy of a Token (256-bit).
const tokenBytes = 32

// NewToken returns a cryptographically random URL-safe Token.
func NewToken() (Token, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return Token{}, err
	}
	return Token{v: base64.RawURLEncoding.EncodeToString(b)}, nil
}

// TokenFromString wraps an existing token string (e.g. from a cookie). It
// rejects the empty string and any value past maxTokenLen — the raw token is
// attacker-controlled (it arrives in a cookie or URL), so an unbounded value
// would otherwise be hashed and looked up verbatim.
func TokenFromString(s string) (Token, error) {
	if s == "" || len(s) > maxTokenLen {
		return Token{}, ErrInvalidToken
	}
	return Token{v: s}, nil
}

// String returns the raw token.
func (t Token) String() string { return t.v }
