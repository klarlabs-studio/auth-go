package domain

import (
	"context"
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

// IsZero reports whether the secret is unset.
func (s TOTPSecret) IsZero() bool { return s.v == "" }

// TOTPRepository is the persistence port for a user's enrolled TOTP secret —
// the per-user shared secret behind RFC 6238 codes. It closes the spec's "TOTP,
// passkey credential methods..." Store gap so callers do not have to own secret
// storage themselves: enroll on SetSecret, load on GetSecret to validate a code,
// and DeleteSecret to disenroll.
//
// The base32 secret is a credential: adapters store TOTPSecret.String() verbatim
// and SHOULD protect the column the way they protect any shared secret (e.g.
// column encryption or a protected schema). Implementations must be safe for
// concurrent use. Every method takes a context.Context first so storage I/O
// honors cancellation, deadlines, and trace propagation.
type TOTPRepository interface {
	// GetSecret returns the user's enrolled secret or ErrNotFound.
	GetSecret(ctx context.Context, userID UserID) (TOTPSecret, error)
	// SetSecret enrolls (or replaces) the user's secret.
	SetSecret(ctx context.Context, userID UserID, secret TOTPSecret) error
	// DeleteSecret removes the user's secret (disenroll). Removing an absent
	// secret returns ErrNotFound.
	DeleteSecret(ctx context.Context, userID UserID) error
}

// AtomicTOTPConsumer is a TOTPRepository capability enabling single-use codes:
// it records the last successfully consumed time step per user and reports
// whether a step is fresh. Without it a valid code is replayable within its
// ±Skew window (RFC 6238 §5.2). NewTOTPService requires the repository to
// implement it — the memory/sqlite/pgstore adapters all do. For a one-shot
// check without persistence use TOTPConfig.Validate (documented as replay-prone).
type AtomicTOTPConsumer interface {
	// ConsumeStep atomically records step as userID's last-consumed step and
	// returns true if it was fresh (strictly greater than the previous), false on
	// a replay (step <= the last consumed).
	ConsumeStep(ctx context.Context, userID UserID, step int64) (bool, error)
}

// TOTPService verifies a user's TOTP codes with replay protection. It loads the
// enrolled secret, validates the code, and atomically consumes the matched time
// step so a code can't be reused within its ±Skew window (RFC 6238 §5.2).
type TOTPService struct {
	repo     TOTPRepository
	consumer AtomicTOTPConsumer
	cfg      TOTPConfig
	now      Clock
}

// NewTOTPService builds the service. repo must implement AtomicTOTPConsumer
// (all first-party adapters do); otherwise it returns ErrTOTPNoReplayProtection
// so replay-safe verification cannot be silently skipped. A nil clock uses the
// wall clock.
func NewTOTPService(repo TOTPRepository, cfg TOTPConfig, clock Clock) (*TOTPService, error) {
	consumer, ok := repo.(AtomicTOTPConsumer)
	if !ok {
		return nil, ErrTOTPNoReplayProtection
	}
	return &TOTPService{repo: repo, consumer: consumer, cfg: cfg, now: orSystemClock(clock)}, nil
}

// Verify checks code against userID's enrolled secret. It returns ErrNotFound if
// the user has no secret, ErrInvalidTOTP if the code doesn't match any step in
// the window, and ErrTOTPReused if the code is valid but its step was already
// consumed. On success the matched step is consumed so the same code cannot be
// used again.
func (s *TOTPService) Verify(ctx context.Context, userID UserID, code string) error {
	secret, err := s.repo.GetSecret(ctx, userID)
	if err != nil {
		return err
	}
	step, err := s.cfg.validateStep(secret, code, s.now())
	if err != nil {
		return err
	}
	fresh, err := s.consumer.ConsumeStep(ctx, userID, step)
	if err != nil {
		return err
	}
	if !fresh {
		return ErrTOTPReused
	}
	return nil
}

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
// It is stateless — a code stays valid for its whole ±Skew window. For
// replay-safe verification (RFC 6238 §5.2) use TOTPService, which consumes the
// matched step so a code can't be reused.
func (c TOTPConfig) Validate(secret TOTPSecret, code string, t time.Time) error {
	_, err := c.validateStep(secret, code, t)
	return err
}

// validateStep is Validate but returns the matched time step, so the step can be
// recorded as consumed to prevent replay.
func (c TOTPConfig) validateStep(secret TOTPSecret, code string, t time.Time) (int64, error) {
	counter := int64(uint64(t.Unix()) / uint64(c.period()))
	skew := int64(c.Skew)
	for i := -skew; i <= skew; i++ {
		want, err := c.hotp(secret, uint64(counter+i))
		if err != nil {
			return 0, err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return counter + i, nil
		}
	}
	return 0, ErrInvalidTOTP
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
