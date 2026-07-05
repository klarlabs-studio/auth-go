// Package aesgcm is a ready AES-256-GCM implementation of domain.SecretCipher,
// for encrypting a recoverable secret (the TOTP shared secret) at rest.
//
// Ciphertext layout is nonce || GCM(ciphertext+tag): a fresh 12-byte random
// nonce is generated per Encrypt and prepended, so equal plaintexts never
// produce equal ciphertext and Decrypt is self-contained. GCM is authenticated,
// so any tampering, truncation, or wrong-key decrypt fails rather than
// returning a wrong secret.
//
// The 32-byte key is the deployment's secret; source it from a KMS, a sealed
// secret, or an env var — never commit it, and rotate by re-encrypting stored
// secrets under the new key.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// KeySize is the required key length: AES-256 takes a 32-byte key.
const KeySize = 32

// ErrInvalidKey is returned by New for a key that is not KeySize bytes.
var ErrInvalidKey = errors.New("aesgcm: key must be 32 bytes")

// ErrMalformedCiphertext is returned by Decrypt for input too short to carry a
// nonce and tag, or that fails authentication.
var ErrMalformedCiphertext = errors.New("aesgcm: malformed or tampered ciphertext")

// Cipher is an AES-256-GCM domain.SecretCipher. Construct it with New; it is
// safe for concurrent use (the underlying cipher.AEAD is).
type Cipher struct {
	aead cipher.AEAD
}

// New builds a Cipher from a 32-byte key, returning ErrInvalidKey otherwise.
func New(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesgcm: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aesgcm: new gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt seals plaintext under a fresh random nonce, returning nonce||sealed.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("aesgcm: nonce: %w", err)
	}
	// Seal appends the ciphertext+tag to nonce, so the returned slice is
	// nonce||ciphertext and Decrypt can recover the nonce from the prefix.
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. It returns ErrMalformedCiphertext for input shorter
// than a nonce or that fails GCM authentication (wrong key, truncation, or
// tampering).
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, ErrMalformedCiphertext
	}
	nonce, sealed := ciphertext[:ns], ciphertext[ns:]
	plaintext, err := c.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, ErrMalformedCiphertext
	}
	return plaintext, nil
}
