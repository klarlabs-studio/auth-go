package domain

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 mandates HMAC-SHA1 for TOTP; authenticator apps require it.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	defaultPeriod = 30
	defaultDigits = 6
	defaultSkew   = 1
	secretBytes   = 20 // 160-bit, RFC 4226
)

// TOTPSecret is a value object: a base32 shared secret that can generate and
// validate RFC 6238 time-based one-time passwords.
type TOTPSecret struct{ v string }

// NewTOTPSecret generates a random TOTP secret.
func NewTOTPSecret() (TOTPSecret, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return TOTPSecret{}, err
	}
	enc := strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	return TOTPSecret{v: enc}, nil
}

// TOTPSecretFromString rehydrates a stored secret, validating it decodes.
func TOTPSecretFromString(s string) (TOTPSecret, error) {
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(s)); err != nil || s == "" {
		return TOTPSecret{}, ErrInvalidSecret
	}
	return TOTPSecret{v: strings.ToUpper(s)}, nil
}

// String returns the base32 secret for storage.
func (s TOTPSecret) String() string { return s.v }

// TOTPConfig parameterizes the OTP algorithm (RFC 6238 defaults).
type TOTPConfig struct {
	Period uint   // seconds per step (default 30)
	Digits int    // code length (default 6)
	Skew   uint   // allowed +/- steps for clock drift (default 1)
	Issuer string // shown in authenticator apps
}

// DefaultTOTPConfig returns standard 30s / 6-digit / ±1-step settings.
func DefaultTOTPConfig(issuer string) TOTPConfig {
	return TOTPConfig{Period: defaultPeriod, Digits: defaultDigits, Skew: defaultSkew, Issuer: issuer}
}

func (c TOTPConfig) period() uint {
	if c.Period == 0 {
		return defaultPeriod
	}
	return c.Period
}

func (c TOTPConfig) digits() int {
	if c.Digits == 0 {
		return defaultDigits
	}
	return c.Digits
}

// ProvisioningURI builds an otpauth:// URI for QR provisioning.
func (c TOTPConfig) ProvisioningURI(secret TOTPSecret, account string) string {
	label := url.PathEscape(c.Issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret.v)
	q.Set("issuer", c.Issuer)
	q.Set("period", fmt.Sprint(c.period()))
	q.Set("digits", fmt.Sprint(c.digits()))
	q.Set("algorithm", "SHA1")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Generate returns the code for a secret at time t.
func (c TOTPConfig) Generate(secret TOTPSecret, t time.Time) (string, error) {
	counter := uint64(t.Unix()) / uint64(c.period())
	return c.hotp(secret, counter)
}

// Validate checks a code against the secret at time t, allowing ±Skew steps.
func (c TOTPConfig) Validate(secret TOTPSecret, code string, t time.Time) error {
	counter := int64(uint64(t.Unix()) / uint64(c.period()))
	skew := int64(c.Skew)
	for i := -skew; i <= skew; i++ {
		want, err := c.hotp(secret, uint64(counter+i))
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return nil
		}
	}
	return ErrInvalidTOTP
}

func (c TOTPConfig) hotp(secret TOTPSecret, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret.v)
	if err != nil {
		return "", ErrInvalidSecret
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	h := hmac.New(sha1.New, key)
	h.Write(buf)
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < c.digits(); i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", c.digits(), value%mod), nil
}
