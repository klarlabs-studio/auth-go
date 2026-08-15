package domain

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// maxPasswordLen bounds plaintext accepted by HashPassword / Verify. An
// unauthenticated login path feeds attacker-controlled bytes into argon2id; an
// unbounded body is a cheap CPU/memory DoS. Real passwords sit far below this.
const maxPasswordLen = 1024

// Argon2idParams are the cost parameters for argon2id hashing.
type Argon2idParams struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2idParams returns OWASP-2024-recommended argon2id parameters.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Memory:      19 * 1024, // 19 MiB
		Iterations:  2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Validate reports ErrInvalidArgon2Params when any cost field is zero. Zero
// Memory/Parallelism would panic inside x/crypto/argon2; rejecting early keeps
// the failure a domain error.
func (p Argon2idParams) Validate() error {
	if p.Memory == 0 || p.Iterations == 0 || p.Parallelism == 0 || p.SaltLength == 0 || p.KeyLength == 0 {
		return ErrInvalidArgon2Params
	}
	return nil
}

// PasswordHash is a value object: a PHC-encoded argon2id hash that knows how
// to verify a plaintext against itself. A product stores its String().
type PasswordHash struct{ encoded string }

// HashPassword constructs a PasswordHash from a plaintext using argon2id.
// Empty and over-long plaintexts return ErrInvalidPassword; invalid cost
// parameters return ErrInvalidArgon2Params.
func HashPassword(plaintext string, p Argon2idParams) (PasswordHash, error) {
	if err := checkPasswordPlaintext(plaintext); err != nil {
		return PasswordHash{}, err
	}
	if err := p.Validate(); err != nil {
		return PasswordHash{}, err
	}
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return PasswordHash{}, err
	}
	key := argon2.IDKey([]byte(plaintext), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	b64 := base64.RawStdEncoding
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key),
	)
	return PasswordHash{encoded: encoded}, nil
}

// PasswordHashFromString rehydrates a stored hash, validating its format.
func PasswordHashFromString(encoded string) (PasswordHash, error) {
	if _, _, _, err := decodePHC(encoded); err != nil {
		return PasswordHash{}, err
	}
	return PasswordHash{encoded: encoded}, nil
}

// String returns the PHC encoding for storage.
func (h PasswordHash) String() string { return h.encoded }

// Verify checks a plaintext against the hash in constant time. Returns
// ErrPasswordMismatch on a non-match, ErrInvalidPassword for an empty or
// over-long plaintext (same bound as HashPassword), and ErrInvalidHash if the
// stored encoding is corrupt.
func (h PasswordHash) Verify(plaintext string) error {
	if err := checkPasswordPlaintext(plaintext); err != nil {
		return err
	}
	params, salt, hash, err := decodePHC(h.encoded)
	if err != nil {
		return err
	}
	other := argon2.IDKey([]byte(plaintext), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(hash)))
	if subtle.ConstantTimeCompare(hash, other) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

func checkPasswordPlaintext(plaintext string) error {
	if plaintext == "" || len(plaintext) > maxPasswordLen {
		return ErrInvalidPassword
	}
	return nil
}

func decodePHC(encoded string) (Argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}
	var p Argon2idParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}
	hash, err := b64.DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, ErrInvalidHash
	}
	return p, salt, hash, nil
}
