package aesgcm_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/klarlabs-studio/auth-go/aesgcm"
	"github.com/klarlabs-studio/auth-go/domain"
)

// compile-time proof the cipher satisfies the domain port.
var _ domain.SecretCipher = (*aesgcm.Cipher)(nil)

func newKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, aesgcm.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestCipher_RoundTrip(t *testing.T) {
	c, err := aesgcm.New(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("JBSWY3DPEHPK3PXP") // a base32 TOTP secret
	ct, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(ct, plaintext) {
		t.Fatal("ciphertext leaks the plaintext")
	}
	got, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: %q vs %q", got, plaintext)
	}
}

func TestCipher_NonceIsRandomized(t *testing.T) {
	c, err := aesgcm.New(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("same secret")
	a, _ := c.Encrypt(pt)
	b, _ := c.Encrypt(pt)
	if bytes.Equal(a, b) {
		t.Fatal("equal plaintexts produced equal ciphertext — nonce not randomized")
	}
}

func TestCipher_RejectsTamperAndWrongKey(t *testing.T) {
	c, err := aesgcm.New(newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := c.Encrypt([]byte("secret"))

	// Flipping any byte must fail authentication.
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := c.Decrypt(tampered); !errors.Is(err, aesgcm.ErrMalformedCiphertext) {
		t.Fatalf("tamper: want ErrMalformedCiphertext, got %v", err)
	}

	// Truncated input (shorter than a nonce) is rejected.
	if _, err := c.Decrypt([]byte{0x00}); !errors.Is(err, aesgcm.ErrMalformedCiphertext) {
		t.Fatalf("truncated: want ErrMalformedCiphertext, got %v", err)
	}

	// A different key cannot open the ciphertext.
	other, _ := aesgcm.New(newKey(t))
	if _, err := other.Decrypt(ct); !errors.Is(err, aesgcm.ErrMalformedCiphertext) {
		t.Fatalf("wrong key: want ErrMalformedCiphertext, got %v", err)
	}
}

func TestNew_RejectsBadKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := aesgcm.New(make([]byte, n)); !errors.Is(err, aesgcm.ErrInvalidKey) {
			t.Fatalf("key len %d: want ErrInvalidKey, got %v", n, err)
		}
	}
}
