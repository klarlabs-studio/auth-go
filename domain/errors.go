package domain

import "errors"

// Domain errors. Adapters and services wrap or return these; callers match
// with errors.Is.
var (
	// Persistence-shape errors (returned by repository ports).
	ErrNotFound = errors.New("authgo: not found")
	ErrConflict = errors.New("authgo: already exists")

	// Lifecycle errors.
	ErrExpired  = errors.New("authgo: expired")
	ErrConsumed = errors.New("authgo: already consumed")

	// Credential errors.
	ErrPasswordMismatch = errors.New("authgo: password mismatch")
	ErrInvalidTOTP      = errors.New("authgo: invalid TOTP code")

	// Lockout errors.
	ErrAccountLocked     = errors.New("authgo: account locked")
	ErrInvalidLockoutCfg = errors.New("authgo: invalid lockout policy")
	ErrInvalidLockoutKey = errors.New("authgo: invalid lockout key")

	// Value-object validation errors.
	ErrInvalidUserID   = errors.New("authgo: invalid user id")
	ErrInvalidTenantID = errors.New("authgo: invalid tenant id")
	ErrInvalidEmail    = errors.New("authgo: invalid email")
	ErrInvalidToken    = errors.New("authgo: invalid token")
	ErrInvalidSecret   = errors.New("authgo: invalid TOTP secret")
	ErrInvalidHash     = errors.New("authgo: invalid password hash")

	// Workload (scoped agent API key) errors.
	ErrInvalidWorkerID = errors.New("authgo: invalid worker id")
	ErrInvalidScope    = errors.New("authgo: invalid scope")
	ErrInvalidExpiry   = errors.New("authgo: invalid key expiry")
	ErrInvalidKeyToken = errors.New("authgo: invalid key token")
	ErrKeyNotFound     = errors.New("authgo: key not found")
	ErrKeyExpired      = errors.New("authgo: key expired")
	ErrScopeDenied     = errors.New("authgo: scope denied")
)
