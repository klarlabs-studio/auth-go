package authgo

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrPasswordMismatch is returned when a password does not match its hash.
var ErrPasswordMismatch = errors.New("authgo: password mismatch")

// Argon2idParams are the cost parameters for argon2id hashing. Defaults follow
// the OWASP Password Storage Cheat Sheet (2024).
type Argon2idParams struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2idParams returns OWASP-recommended argon2id parameters.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Memory:      19 * 1024, // 19 MiB
		Iterations:  2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// HashPassword hashes a plaintext password with argon2id, returning the
// standard PHC-string encoding ($argon2id$v=19$m=...,t=...,p=...$salt$hash).
func HashPassword(password string, p Argon2idParams) (string, error) {
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key),
	), nil
}

// VerifyPassword checks a plaintext password against a PHC-encoded hash in
// constant time. Returns ErrPasswordMismatch on a non-match.
func VerifyPassword(password, encoded string) error {
	params, salt, hash, err := decodePHC(encoded)
	if err != nil {
		return err
	}
	other := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(hash)))
	if subtle.ConstantTimeCompare(hash, other) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

func decodePHC(encoded string) (Argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2idParams{}, nil, nil, errors.New("authgo: invalid password hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Argon2idParams{}, nil, nil, errors.New("authgo: unsupported argon2 version")
	}
	var p Argon2idParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Argon2idParams{}, nil, nil, errors.New("authgo: invalid argon2 params")
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, errors.New("authgo: invalid salt encoding")
	}
	hash, err := b64.DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, errors.New("authgo: invalid hash encoding")
	}
	return p, salt, hash, nil
}
