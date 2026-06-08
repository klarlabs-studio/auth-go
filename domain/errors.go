package domain

import "errors"

// Domain errors. Adapters and services wrap or return these; callers match
// with errors.Is.
var (
	// Persistence-shape errors (returned by repository ports).
	ErrNotFound = errors.New("authgo: not found")

	// Lifecycle errors.
	ErrExpired  = errors.New("authgo: expired")
	ErrConsumed = errors.New("authgo: already consumed")

	// Credential errors.
	ErrPasswordMismatch = errors.New("authgo: password mismatch")
	ErrInvalidTOTP      = errors.New("authgo: invalid TOTP code")

	// Value-object validation errors.
	ErrInvalidUserID   = errors.New("authgo: invalid user id")
	ErrInvalidTenantID = errors.New("authgo: invalid tenant id")
	ErrInvalidEmail    = errors.New("authgo: invalid email")
	ErrInvalidToken    = errors.New("authgo: invalid token")
	ErrInvalidSecret   = errors.New("authgo: invalid TOTP secret")
	ErrInvalidHash     = errors.New("authgo: invalid password hash")
)
