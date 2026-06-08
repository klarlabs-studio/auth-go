package domain

import "time"

// Clock returns the current time. Injected for deterministic tests.
type Clock func() time.Time

// SystemClock is the default wall-clock.
func SystemClock() time.Time { return time.Now() }

func orSystemClock(c Clock) Clock {
	if c == nil {
		return SystemClock
	}
	return c
}

// SessionService is a domain service issuing and validating sessions over a
// SessionRepository. It owns the entropy and expiry invariants.
type SessionService struct {
	repo SessionRepository
	ttl  time.Duration
	now  Clock
}

// NewSessionService builds the service. ttl is the session lifetime.
func NewSessionService(repo SessionRepository, ttl time.Duration, clock Clock) *SessionService {
	return &SessionService{repo: repo, ttl: ttl, now: orSystemClock(clock)}
}

// Issue creates and persists a fresh session for a user/tenant.
func (s *SessionService) Issue(userID UserID, tenantID TenantID) (Session, error) {
	if userID.IsZero() {
		return Session{}, ErrInvalidUserID
	}
	if tenantID.IsZero() {
		return Session{}, ErrInvalidTenantID
	}
	tok, err := NewToken()
	if err != nil {
		return Session{}, err
	}
	t := s.now()
	sess := Session{
		token:     tok,
		userID:    userID,
		tenantID:  tenantID,
		createdAt: t,
		expiresAt: t.Add(s.ttl),
	}
	if err := s.repo.Save(sess); err != nil {
		return Session{}, err
	}
	return sess, nil
}

// Validate returns the session for a token, deleting and rejecting it if
// expired. Returns ErrNotFound / ErrExpired otherwise.
func (s *SessionService) Validate(token Token) (Session, error) {
	sess, err := s.repo.FindByToken(token)
	if err != nil {
		return Session{}, err
	}
	if sess.Expired(s.now()) {
		_ = s.repo.Delete(token)
		return Session{}, ErrExpired
	}
	return sess, nil
}

// Revoke deletes one session (logout).
func (s *SessionService) Revoke(token Token) error { return s.repo.Delete(token) }

// RevokeAll deletes every session for a user (logout-everywhere).
func (s *SessionService) RevokeAll(userID UserID) error { return s.repo.DeleteByUser(userID) }

// MagicLinkService is a domain service issuing and consuming magic links.
type MagicLinkService struct {
	repo MagicLinkRepository
	ttl  time.Duration
	now  Clock
}

// NewMagicLinkService builds the service. ttl is the link lifetime (standard: 15m).
func NewMagicLinkService(repo MagicLinkRepository, ttl time.Duration, clock Clock) *MagicLinkService {
	return &MagicLinkService{repo: repo, ttl: ttl, now: orSystemClock(clock)}
}

// Issue creates a link and returns the RAW token to embed in the emailed URL.
// The raw token is never persisted — only its hash.
func (s *MagicLinkService) Issue(email Email, tenantID TenantID) (Token, error) {
	if tenantID.IsZero() {
		return Token{}, ErrInvalidTenantID
	}
	raw, err := NewToken()
	if err != nil {
		return Token{}, err
	}
	t := s.now()
	link := MagicLink{
		hash:      HashToken(raw),
		email:     email,
		tenantID:  tenantID,
		expiresAt: t.Add(s.ttl),
	}
	if err := s.repo.Save(link); err != nil {
		return Token{}, err
	}
	return raw, nil
}

// Consume validates a raw token and, on success, marks it consumed and returns
// the link. Returns ErrNotFound / ErrExpired / ErrConsumed otherwise.
func (s *MagicLinkService) Consume(raw Token) (MagicLink, error) {
	link, err := s.repo.FindByHash(HashToken(raw))
	if err != nil {
		return MagicLink{}, err
	}
	if link.consumed {
		return MagicLink{}, ErrConsumed
	}
	if link.Expired(s.now()) {
		return MagicLink{}, ErrExpired
	}
	if err := s.repo.MarkConsumed(link.hash); err != nil {
		return MagicLink{}, err
	}
	link.consumed = true
	return link, nil
}
