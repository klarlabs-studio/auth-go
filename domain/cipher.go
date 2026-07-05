package domain

// SecretCipher optionally protects a recoverable secret at rest. Most auth-go
// credentials are stored one-way — sessions, magic links, and workload keys as
// SHA-256 hashes, passwords as argon2id — and never need this. The TOTP shared
// secret is the exception: RFC 6238 verification recomputes the code from the
// raw secret, so the adapter must persist it in a form it can read back. A
// SecretCipher lets a deployment keep even that secret encrypted at rest without
// relying on a database-level column-encryption feature.
//
// Implementations MUST be safe for concurrent use and SHOULD use authenticated
// encryption (AEAD) so a tampered ciphertext fails Decrypt rather than yielding
// a wrong secret. Package aesgcm provides a ready AES-256-GCM implementation.
type SecretCipher interface {
	// Encrypt returns the ciphertext for plaintext. It MUST be randomized — a
	// fresh nonce per call — so equal secrets don't produce equal ciphertext.
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	// Decrypt reverses Encrypt, returning an error for any ciphertext it did not
	// produce (wrong key, truncation, or tampering).
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
}
