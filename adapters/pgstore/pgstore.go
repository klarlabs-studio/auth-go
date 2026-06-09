// Package pgstore provides Postgres implementations of the auth domain
// repository ports, built on the stdlib database/sql. It carries no driver
// dependency — the consuming product registers its own (pgx/stdlib, lib/pq).
//
// Apply schema.sql before use. Tables are tenant-aware; pair with Row-Level
// Security per the Klarlabs product standard.
package pgstore

import (
	"database/sql"
	"errors"

	"github.com/klarlabs-studio/auth-go/domain"
)

// DB is the subset of *sql.DB the adapters need; satisfied by *sql.DB and
// *sql.Tx, so repositories compose into a product's transactions.
type DB interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

// SessionRepo is a Postgres domain.SessionRepository.
type SessionRepo struct{ db DB }

// NewSessionRepo builds a session repository over db.
func NewSessionRepo(db DB) *SessionRepo { return &SessionRepo{db: db} }

// Save upserts a session.
func (r *SessionRepo) Save(s domain.Session) error {
	snap := s.Snapshot()
	_, err := r.db.Exec(
		`INSERT INTO authgo_sessions (token, user_id, tenant_id, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (token) DO UPDATE SET
		   user_id = EXCLUDED.user_id, tenant_id = EXCLUDED.tenant_id,
		   created_at = EXCLUDED.created_at, expires_at = EXCLUDED.expires_at`,
		snap.Token, snap.UserID, snap.TenantID, snap.CreatedAt, snap.ExpiresAt,
	)
	return err
}

// FindByToken loads a session or returns domain.ErrNotFound.
func (r *SessionRepo) FindByToken(token domain.Token) (domain.Session, error) {
	var snap domain.SessionSnapshot
	err := r.db.QueryRow(
		`SELECT token, user_id, tenant_id, created_at, expires_at
		 FROM authgo_sessions WHERE token = $1`, token.String(),
	).Scan(&snap.Token, &snap.UserID, &snap.TenantID, &snap.CreatedAt, &snap.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Session{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Session{}, err
	}
	return domain.SessionFromSnapshot(snap), nil
}

// Delete removes one session.
func (r *SessionRepo) Delete(token domain.Token) error {
	_, err := r.db.Exec(`DELETE FROM authgo_sessions WHERE token = $1`, token.String())
	return err
}

// DeleteByUser removes every session for a user.
func (r *SessionRepo) DeleteByUser(userID domain.UserID) error {
	_, err := r.db.Exec(`DELETE FROM authgo_sessions WHERE user_id = $1`, userID.String())
	return err
}

// MagicLinkRepo is a Postgres domain.MagicLinkRepository.
type MagicLinkRepo struct{ db DB }

// NewMagicLinkRepo builds a magic-link repository over db.
func NewMagicLinkRepo(db DB) *MagicLinkRepo { return &MagicLinkRepo{db: db} }

// Save inserts a magic link.
func (r *MagicLinkRepo) Save(m domain.MagicLink) error {
	snap := m.Snapshot()
	_, err := r.db.Exec(
		`INSERT INTO authgo_magic_links (hash, email, tenant_id, expires_at, consumed)
		 VALUES ($1, $2, $3, $4, $5)`,
		snap.Hash, snap.Email, snap.TenantID, snap.ExpiresAt, snap.Consumed,
	)
	return err
}

// FindByHash loads a link or returns domain.ErrNotFound.
func (r *MagicLinkRepo) FindByHash(hash string) (domain.MagicLink, error) {
	var snap domain.MagicLinkSnapshot
	err := r.db.QueryRow(
		`SELECT hash, email, tenant_id, expires_at, consumed
		 FROM authgo_magic_links WHERE hash = $1`, hash,
	).Scan(&snap.Hash, &snap.Email, &snap.TenantID, &snap.ExpiresAt, &snap.Consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.MagicLink{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.MagicLink{}, err
	}
	return domain.MagicLinkFromSnapshot(snap), nil
}

// MarkConsumed flags a link as used.
func (r *MagicLinkRepo) MarkConsumed(hash string) error {
	res, err := r.db.Exec(`UPDATE authgo_magic_links SET consumed = TRUE WHERE hash = $1`, hash)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// PasskeyRepo is a Postgres domain.PasskeyRepository.
type PasskeyRepo struct{ db DB }

// NewPasskeyRepo builds a passkey repository over db.
func NewPasskeyRepo(db DB) *PasskeyRepo { return &PasskeyRepo{db: db} }

// Add inserts a credential.
func (r *PasskeyRepo) Add(c domain.PasskeyCredential) error {
	_, err := r.db.Exec(
		`INSERT INTO authgo_passkeys (id, user_id, public_key, sign_count, name)
		 VALUES ($1, $2, $3, $4, $5)`,
		c.ID, c.UserID.String(), c.PublicKey, int64(c.SignCount), c.Name,
	)
	return err
}

// ListByUser returns a user's credentials.
func (r *PasskeyRepo) ListByUser(userID domain.UserID) ([]domain.PasskeyCredential, error) {
	rows, err := r.db.Query(
		`SELECT id, user_id, public_key, sign_count, name
		 FROM authgo_passkeys WHERE user_id = $1`, userID.String(),
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []domain.PasskeyCredential
	for rows.Next() {
		var (
			id, pub   []byte
			uid, name string
			count     int64
		)
		if err := rows.Scan(&id, &uid, &pub, &count, &name); err != nil {
			return nil, err
		}
		u, err := domain.NewUserID(uid)
		if err != nil {
			return nil, err
		}
		out = append(out, domain.PasskeyCredential{
			ID: id, UserID: u, PublicKey: pub, SignCount: uint32(count), Name: name,
		})
	}
	return out, rows.Err()
}

// UpdateSignCount advances a credential's sign count.
func (r *PasskeyRepo) UpdateSignCount(id []byte, count uint32) error {
	res, err := r.db.Exec(
		`UPDATE authgo_passkeys SET sign_count = $1 WHERE id = $2`, int64(count), id,
	)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// Delete removes a credential.
func (r *PasskeyRepo) Delete(id []byte) error {
	_, err := r.db.Exec(`DELETE FROM authgo_passkeys WHERE id = $1`, id)
	return err
}

// requireOneRow maps a zero-row UPDATE to domain.ErrNotFound.
func requireOneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// LoginAttemptRepo is a Postgres domain.LoginAttemptStore. Callers SHOULD pass
// a hashed key (e.g. hex SHA-256 of the email) so plaintext PII is never
// persisted — this adapter stores the key verbatim.
type LoginAttemptRepo struct{ db DB }

// NewLoginAttemptRepo builds a login-attempt store over db.
func NewLoginAttemptRepo(db DB) *LoginAttemptRepo { return &LoginAttemptRepo{db: db} }

// Get loads a key's state or returns domain.ErrNotFound.
func (r *LoginAttemptRepo) Get(key string) (domain.LoginAttemptSnapshot, error) {
	var snap domain.LoginAttemptSnapshot
	var until sql.NullTime
	err := r.db.QueryRow(
		`SELECT key, failure_count, locked_until
		   FROM authgo_login_attempts WHERE key = $1`, key,
	).Scan(&snap.Key, &snap.FailureCount, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.LoginAttemptSnapshot{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.LoginAttemptSnapshot{}, err
	}
	if until.Valid {
		snap.LockedUntil = until.Time
	}
	return snap, nil
}

// Save upserts a key's state.
func (r *LoginAttemptRepo) Save(s domain.LoginAttemptSnapshot) error {
	var until sql.NullTime
	if !s.LockedUntil.IsZero() {
		until = sql.NullTime{Time: s.LockedUntil, Valid: true}
	}
	_, err := r.db.Exec(
		`INSERT INTO authgo_login_attempts (key, failure_count, locked_until, updated_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (key) DO UPDATE SET
		   failure_count = EXCLUDED.failure_count,
		   locked_until  = EXCLUDED.locked_until,
		   updated_at    = now()`,
		s.Key, s.FailureCount, until,
	)
	return err
}

// Delete removes a key's state.
func (r *LoginAttemptRepo) Delete(key string) error {
	_, err := r.db.Exec(`DELETE FROM authgo_login_attempts WHERE key = $1`, key)
	return err
}

// Port assertions.
var (
	_ domain.SessionRepository   = (*SessionRepo)(nil)
	_ domain.MagicLinkRepository = (*MagicLinkRepo)(nil)
	_ domain.PasskeyRepository   = (*PasskeyRepo)(nil)
	_ domain.LoginAttemptStore   = (*LoginAttemptRepo)(nil)
)
