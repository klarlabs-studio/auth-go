package oidc

import "errors"

// Verification errors. Verify wraps exactly one of these with detail; callers
// match with errors.Is and must treat every one of them as "not authenticated".
var (
	// ErrMalformed: the token is not a well-formed compact JWS carrying a JSON
	// claims object — wrong segment count, non-canonical base64url, invalid
	// JSON or UTF-8, duplicate member names, a wrongly typed claim, a missing
	// kid, or a "crit" header this verifier cannot honour.
	ErrMalformed = errors.New("oidc: malformed token")
	// ErrAlgorithm: the header's alg is not in the verifier's allow-list, or
	// the key the kid names cannot be used with it (RS↔ES confusion).
	ErrAlgorithm = errors.New("oidc: algorithm not allowed")
	// ErrUnknownKey: no key in the issuer's key set has the token's kid, even
	// after a refresh (or a refresh was rate-limited).
	ErrUnknownKey = errors.New("oidc: unknown signing key")
	// ErrSignature: the signature does not verify under the issuer's key.
	ErrSignature = errors.New("oidc: invalid signature")
	// ErrIssuer: the iss claim is not exactly the configured issuer.
	ErrIssuer = errors.New("oidc: issuer mismatch")
	// ErrAudience: the aud claim contains none of the configured audiences.
	ErrAudience = errors.New("oidc: audience mismatch")
	// ErrExpired: exp is in the past (beyond the clock skew).
	ErrExpired = errors.New("oidc: token expired")
	// ErrNotYetValid: nbf or iat is in the future (beyond the clock skew).
	ErrNotYetValid = errors.New("oidc: token not yet valid")
	// ErrMissingClaim: a claim the verifier or a profile requires is absent.
	ErrMissingClaim = errors.New("oidc: required claim missing")
	// ErrKeySetUnavailable: the issuer's discovery document or key set could
	// not be fetched or parsed and no previously fetched key set is cached.
	ErrKeySetUnavailable = errors.New("oidc: key set unavailable")

	// ErrInvalidConfig is returned by New for an unusable Config.
	ErrInvalidConfig = errors.New("oidc: invalid config")
)
