package authgo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ErrInvalidTOTP is returned when a TOTP code does not validate.
var ErrInvalidTOTP = errors.New("authgo: invalid TOTP code")

// TOTPConfig configures time-based one-time passwords (RFC 6238).
type TOTPConfig struct {
	Period uint   // seconds per step (default 30)
	Digits int    // code length (default 6)
	Skew   uint   // allowed +/- steps for clock drift (default 1)
	Issuer string // shown in authenticator apps
}

// DefaultTOTPConfig returns standard 30s / 6-digit / ±1-step settings.
func DefaultTOTPConfig(issuer string) TOTPConfig {
	return TOTPConfig{Period: 30, Digits: 6, Skew: 1, Issuer: issuer}
}

// NewTOTPSecret returns a base32 (no padding) secret suitable for TOTP.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20) // 160-bit, RFC 4226 recommended
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}

// ProvisioningURI builds an otpauth:// URI for QR provisioning.
func (c TOTPConfig) ProvisioningURI(secret, account string) string {
	label := url.PathEscape(c.Issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", c.Issuer)
	q.Set("period", fmt.Sprint(c.period()))
	q.Set("digits", fmt.Sprint(c.digits()))
	q.Set("algorithm", "SHA1")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func (c TOTPConfig) period() uint {
	if c.Period == 0 {
		return 30
	}
	return c.Period
}

func (c TOTPConfig) digits() int {
	if c.Digits == 0 {
		return 6
	}
	return c.Digits
}

// Generate returns the TOTP code for a secret at time t.
func (c TOTPConfig) Generate(secret string, t time.Time) (string, error) {
	counter := uint64(t.Unix()) / uint64(c.period())
	return c.hotp(secret, counter)
}

// Validate checks code against the secret at time t, allowing ±Skew steps.
func (c TOTPConfig) Validate(secret, code string, t time.Time) error {
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

func (c TOTPConfig) hotp(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", errors.New("authgo: invalid TOTP secret")
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
