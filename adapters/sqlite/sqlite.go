package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/klarlabs-studio/auth-go/domain"
)

// DB is the context-aware subset of *sql.DB the adapters need; satisfied by
// *sql.DB and *sql.Tx, so repositories compose into a product's transactions.
// It mirrors pgstore.DB, so the two adapters share one storage contract.
type DB interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// UserRepo is a SQLite domain.UserRepository.
type UserRepo struct{ db DB }

// NewUserRepo builds a user repository over db.
func NewUserRepo(db DB) *UserRepo { return &UserRepo{db: db} }

// GetUser loads the user with id within tenantID, or domain.ErrNotFound. The
// tenant is part of the predicate, so a user under another tenant reads as
// ErrNotFound.
func (r *UserRepo) GetUser(ctx context.Context, tenantID domain.TenantID, id domain.UserID) (domain.User, error) {
	var (
		snap                 domain.UserSnapshot
		createdAt, updatedAt string
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, email, created_at, updated_at
		 FROM authgo_users WHERE id = ? AND tenant_id = ?`, id.String(), tenantID.String(),
	).Scan(&snap.ID, &snap.TenantID, &snap.Email, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.User{}, err
	}
	if snap.CreatedAt, err = decodeTime(createdAt); err != nil {
		return domain.User{}, err
	}
	if snap.UpdatedAt, err = decodeTime(updatedAt); err != nil {
		return domain.User{}, err
	}
	return domain.UserFromSnapshot(snap), nil
}

// UpsertUser inserts or updates a user, keyed on its ID.
func (r *UserRepo) UpsertUser(ctx context.Context, u domain.User) error {
	snap := u.Snapshot()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO authgo_users (id, tenant_id, email, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (id) DO UPDATE SET
		   tenant_id = excluded.tenant_id, email = excluded.email,
		   created_at = excluded.created_at, updated_at = excluded.updated_at`,
		snap.ID, snap.TenantID, snap.Email, encodeTime(snap.CreatedAt), encodeTime(snap.UpdatedAt),
	)
	return err
}

// SessionRepo is a SQLite domain.SessionRepository.
type SessionRepo struct{ db DB }

// NewSessionRepo builds a session repository over db.
func NewSessionRepo(db DB) *SessionRepo { return &SessionRepo{db: db} }

// Save upserts a session.
func (r *SessionRepo) Save(ctx context.Context, s domain.Session) error {
	snap := s.Snapshot()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO authgo_sessions (token, user_id, tenant_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT (token) DO UPDATE SET
		   user_id = excluded.user_id, tenant_id = excluded.tenant_id,
		   created_at = excluded.created_at, expires_at = excluded.expires_at`,
		snap.Token, snap.UserID, snap.TenantID, encodeTime(snap.CreatedAt), encodeTime(snap.ExpiresAt),
	)
	return err
}

// FindByToken loads a session or returns domain.ErrNotFound.
func (r *SessionRepo) FindByToken(ctx context.Context, token domain.Token) (domain.Session, error) {
	var (
		snap                 domain.SessionSnapshot
		createdAt, expiresAt string
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT token, user_id, tenant_id, created_at, expires_at
		 FROM authgo_sessions WHERE token = ?`, token.String(),
	).Scan(&snap.Token, &snap.UserID, &snap.TenantID, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Session{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Session{}, err
	}
	if snap.CreatedAt, err = decodeTime(createdAt); err != nil {
		return domain.Session{}, err
	}
	if snap.ExpiresAt, err = decodeTime(expiresAt); err != nil {
		return domain.Session{}, err
	}
	return domain.SessionFromSnapshot(snap), nil
}

// Delete removes one session.
func (r *SessionRepo) Delete(ctx context.Context, token domain.Token) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM authgo_sessions WHERE token = ?`, token.String())
	return err
}

// DeleteByUser removes every session for a user.
func (r *SessionRepo) DeleteByUser(ctx context.Context, userID domain.UserID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM authgo_sessions WHERE user_id = ?`, userID.String())
	return err
}

// RotateAtomically implements domain.AtomicSessionRotator: delete oldKey and
// insert newSess in a single transaction (or directly when already inside a Tx).
func (r *SessionRepo) RotateAtomically(ctx context.Context, oldKey domain.Token, newSess domain.Session) error {
	beginner, ok := r.db.(txBeginner)
	if !ok {
		return sessionRotateSwap(ctx, r.db, oldKey, newSess)
	}
	tx, err := beginner.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := sessionRotateSwap(ctx, tx, oldKey, newSess); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func sessionRotateSwap(ctx context.Context, db DB, oldKey domain.Token, newSess domain.Session) error {
	res, err := db.ExecContext(ctx, `DELETE FROM authgo_sessions WHERE token = ?`, oldKey.String())
	if err != nil {
		return err
	}
	if err := requireOneRow(res); err != nil {
		return err
	}
	snap := newSess.Snapshot()
	_, err = db.ExecContext(ctx,
		`INSERT INTO authgo_sessions (token, user_id, tenant_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		snap.Token, snap.UserID, snap.TenantID, encodeTime(snap.CreatedAt), encodeTime(snap.ExpiresAt),
	)
	return err
}

// MagicLinkRepo is a SQLite domain.MagicLinkRepository.
type MagicLinkRepo struct{ db DB }

// NewMagicLinkRepo builds a magic-link repository over db.
func NewMagicLinkRepo(db DB) *MagicLinkRepo { return &MagicLinkRepo{db: db} }

// Save inserts a magic link.
func (r *MagicLinkRepo) Save(ctx context.Context, m domain.MagicLink) error {
	snap := m.Snapshot()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO authgo_magic_links (hash, email, tenant_id, expires_at, consumed)
		 VALUES (?, ?, ?, ?, ?)`,
		snap.Hash, snap.Email, snap.TenantID, encodeTime(snap.ExpiresAt), boolToInt(snap.Consumed),
	)
	return err
}

// FindByHash loads a link or returns domain.ErrNotFound.
func (r *MagicLinkRepo) FindByHash(ctx context.Context, hash string) (domain.MagicLink, error) {
	var (
		snap      domain.MagicLinkSnapshot
		expiresAt string
		consumed  int64
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT hash, email, tenant_id, expires_at, consumed
		 FROM authgo_magic_links WHERE hash = ?`, hash,
	).Scan(&snap.Hash, &snap.Email, &snap.TenantID, &expiresAt, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.MagicLink{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.MagicLink{}, err
	}
	if snap.ExpiresAt, err = decodeTime(expiresAt); err != nil {
		return domain.MagicLink{}, err
	}
	snap.Consumed = consumed != 0
	return domain.MagicLinkFromSnapshot(snap), nil
}

// MarkConsumed flags a link as used.
func (r *MagicLinkRepo) MarkConsumed(ctx context.Context, hash string) (bool, error) {
	// Atomic single-use: only flip a link that is still unconsumed, and report
	// whether this statement was the one that flipped it.
	res, err := r.db.ExecContext(ctx, `UPDATE authgo_magic_links SET consumed = 1 WHERE hash = ? AND consumed = 0`, hash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// InvalidateOutstanding marks every unconsumed link for email+tenant consumed.
func (r *MagicLinkRepo) InvalidateOutstanding(ctx context.Context, email domain.Email, tenantID domain.TenantID) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE authgo_magic_links SET consumed = 1
		 WHERE email = ? AND tenant_id = ? AND consumed = 0`,
		email.String(), tenantID.String(),
	)
	return err
}

// IssueAtomically implements domain.AtomicMagicLinkIssuer: invalidate outstanding
// links and insert the new one in a single transaction (or directly inside a Tx).
func (r *MagicLinkRepo) IssueAtomically(ctx context.Context, link domain.MagicLink) error {
	beginner, ok := r.db.(txBeginner)
	if !ok {
		return magicIssueSwap(ctx, r.db, link)
	}
	tx, err := beginner.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := magicIssueSwap(ctx, tx, link); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func magicIssueSwap(ctx context.Context, db DB, link domain.MagicLink) error {
	snap := link.Snapshot()
	if _, err := db.ExecContext(ctx,
		`UPDATE authgo_magic_links SET consumed = 1
		 WHERE email = ? AND tenant_id = ? AND consumed = 0`,
		snap.Email, snap.TenantID,
	); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO authgo_magic_links (hash, email, tenant_id, expires_at, consumed)
		 VALUES (?, ?, ?, ?, ?)`,
		snap.Hash, snap.Email, snap.TenantID, encodeTime(snap.ExpiresAt), boolToInt(snap.Consumed),
	)
	return err
}

// TOTPRepo is a SQLite domain.TOTPRepository. Secrets are encrypted at rest
// when constructed with NewTOTPRepo (required SecretCipher). Use
// NewPlaintextTOTPRepo only for tests or one-off migrations of legacy rows.
type TOTPRepo struct {
	db     DB
	cipher domain.SecretCipher // nil = store the base32 secret verbatim (plaintext ctor only)
}

// NewTOTPRepo builds a TOTP secret repository that encrypts secrets at rest
// with cipher. cipher must be non-nil (use aesgcm.New from a deployment key).
func NewTOTPRepo(db DB, cipher domain.SecretCipher) *TOTPRepo {
	if cipher == nil {
		panic("sqlite: NewTOTPRepo requires a non-nil SecretCipher; use NewPlaintextTOTPRepo for tests")
	}
	return &TOTPRepo{db: db, cipher: cipher}
}

// NewPlaintextTOTPRepo stores the base32 secret verbatim. Prefer NewTOTPRepo
// with aesgcm in any durable deployment — plaintext is for tests and legacy
// migration only.
func NewPlaintextTOTPRepo(db DB) *TOTPRepo {
	return &TOTPRepo{db: db}
}

// encodeSecret renders a secret for storage: base64(ciphertext) when a cipher is
// configured, else the base32 secret verbatim.
func (r *TOTPRepo) encodeSecret(secret domain.TOTPSecret) (string, error) {
	if r.cipher == nil {
		return secret.String(), nil
	}
	ct, err := r.cipher.Encrypt([]byte(secret.String()))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// decodeSecret reverses encodeSecret for a stored column value.
func (r *TOTPRepo) decodeSecret(stored string) (domain.TOTPSecret, error) {
	if r.cipher == nil {
		return domain.TOTPSecretFromString(stored)
	}
	ct, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return domain.TOTPSecret{}, err
	}
	pt, err := r.cipher.Decrypt(ct)
	if err != nil {
		return domain.TOTPSecret{}, err
	}
	return domain.TOTPSecretFromString(string(pt))
}

// GetSecret loads a user's secret or returns domain.ErrNotFound.
func (r *TOTPRepo) GetSecret(ctx context.Context, userID domain.UserID) (domain.TOTPSecret, error) {
	var enc string
	err := r.db.QueryRowContext(ctx,
		`SELECT secret FROM authgo_totp_secrets WHERE user_id = ?`, userID.String(),
	).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.TOTPSecret{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.TOTPSecret{}, err
	}
	return r.decodeSecret(enc)
}

// SetSecret enrolls or replaces a user's secret.
func (r *TOTPRepo) SetSecret(ctx context.Context, userID domain.UserID, secret domain.TOTPSecret) error {
	stored, err := r.encodeSecret(secret)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		`INSERT INTO authgo_totp_secrets (user_id, secret) VALUES (?, ?)
		 ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret`,
		userID.String(), stored,
	)
	return err
}

// DeleteSecret removes a user's secret. Removing an absent secret returns
// domain.ErrNotFound.
func (r *TOTPRepo) DeleteSecret(ctx context.Context, userID domain.UserID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM authgo_totp_secrets WHERE user_id = ?`, userID.String())
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// ConsumeStep implements domain.AtomicTOTPConsumer: atomically record step as
// used, accepting it only if it advances past the last consumed step. A single
// conditional UPSERT, so concurrent verifications can't both consume one step.
func (r *TOTPRepo) ConsumeStep(ctx context.Context, userID domain.UserID, step int64) (bool, error) {
	res, err := r.db.ExecContext(ctx,
		`INSERT INTO authgo_totp_used_steps (user_id, last_step) VALUES (?, ?)
		 ON CONFLICT (user_id) DO UPDATE SET last_step = excluded.last_step
		   WHERE last_step < excluded.last_step`,
		userID.String(), step,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// PasskeyRepo is a SQLite domain.PasskeyRepository.
type PasskeyRepo struct{ db DB }

// NewPasskeyRepo builds a passkey repository over db.
func NewPasskeyRepo(db DB) *PasskeyRepo { return &PasskeyRepo{db: db} }

// Add inserts a credential.
func (r *PasskeyRepo) Add(ctx context.Context, c domain.PasskeyCredential) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO authgo_passkeys (id, user_id, public_key, sign_count, name)
		 VALUES (?, ?, ?, ?, ?)`,
		c.ID, c.UserID.String(), c.PublicKey, int64(c.SignCount), c.Name,
	)
	return err
}

// ListByUser returns a user's credentials.
func (r *PasskeyRepo) ListByUser(ctx context.Context, userID domain.UserID) ([]domain.PasskeyCredential, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, user_id, public_key, sign_count, name
		 FROM authgo_passkeys WHERE user_id = ?`, userID.String(),
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
		sc, err := uint32SignCount(count)
		if err != nil {
			return nil, err
		}
		out = append(out, domain.PasskeyCredential{
			ID: id, UserID: u, PublicKey: pub, SignCount: sc, Name: name,
		})
	}
	return out, rows.Err()
}

// UpdateSignCount advances a credential's sign count.
func (r *PasskeyRepo) UpdateSignCount(ctx context.Context, id []byte, count uint32) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE authgo_passkeys SET sign_count = ? WHERE id = ?`, int64(count), id,
	)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// Delete removes a credential.
func (r *PasskeyRepo) Delete(ctx context.Context, id []byte) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM authgo_passkeys WHERE id = ?`, id)
	return err
}

// LoginAttemptRepo is a SQLite domain.LoginAttemptStore. Callers SHOULD pass a
// hashed key (e.g. hex SHA-256 of the email) so plaintext PII is never
// persisted — this adapter stores the key verbatim.
type LoginAttemptRepo struct{ db DB }

// NewLoginAttemptRepo builds a login-attempt store over db.
func NewLoginAttemptRepo(db DB) *LoginAttemptRepo { return &LoginAttemptRepo{db: db} }

// Get loads a key's state or returns domain.ErrNotFound.
func (r *LoginAttemptRepo) Get(ctx context.Context, key string) (domain.LoginAttemptSnapshot, error) {
	var (
		snap  domain.LoginAttemptSnapshot
		until sql.NullString
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT key, failure_count, locked_until
		   FROM authgo_login_attempts WHERE key = ?`, key,
	).Scan(&snap.Key, &snap.FailureCount, &until)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.LoginAttemptSnapshot{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.LoginAttemptSnapshot{}, err
	}
	if until.Valid {
		if snap.LockedUntil, err = decodeTime(until.String); err != nil {
			return domain.LoginAttemptSnapshot{}, err
		}
	}
	return snap, nil
}

// Save upserts a key's state.
func (r *LoginAttemptRepo) Save(ctx context.Context, s domain.LoginAttemptSnapshot) error {
	var until any
	if !s.LockedUntil.IsZero() {
		until = encodeTime(s.LockedUntil)
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO authgo_login_attempts (key, failure_count, locked_until, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT (key) DO UPDATE SET
		   failure_count = excluded.failure_count,
		   locked_until  = excluded.locked_until,
		   updated_at    = excluded.updated_at`,
		s.Key, s.FailureCount, until, encodeTime(nowUTC()),
	)
	return err
}

// Delete removes a key's state.
func (r *LoginAttemptRepo) Delete(ctx context.Context, key string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM authgo_login_attempts WHERE key = ?`, key)
	return err
}

// RecordFailureAtomically implements domain.AtomicLoginAttemptStore in a single
// conditional UPSERT: failure_count + 1 is evaluated in SQL, so concurrent
// failures for one key can't lose increments the way a Get→Save pair can.
// locked_until is an RFC3339Nano string; the values compared here differ by the
// lock window, so lexical ordering matches chronological ordering.
func (r *LoginAttemptRepo) RecordFailureAtomically(ctx context.Context, key string, now time.Time, maxFailures int, window time.Duration) (domain.LoginAttemptSnapshot, bool, error) {
	nowS := encodeTime(now)
	lockS := encodeTime(now.Add(window))
	var (
		snap  domain.LoginAttemptSnapshot
		until sql.NullString
	)
	err := r.db.QueryRowContext(ctx,
		`INSERT INTO authgo_login_attempts (key, failure_count, locked_until, updated_at)
		 VALUES (?, 1, CASE WHEN 1 >= ? THEN ? ELSE NULL END, ?)
		 ON CONFLICT (key) DO UPDATE SET
		   failure_count = CASE
		     WHEN locked_until IS NOT NULL AND locked_until <= ? THEN 1
		     ELSE failure_count + 1 END,
		   locked_until = CASE
		     WHEN locked_until IS NOT NULL AND locked_until > ? THEN locked_until
		     WHEN (CASE WHEN locked_until IS NOT NULL AND locked_until <= ? THEN 1 ELSE failure_count + 1 END) >= ? THEN ?
		     ELSE NULL END,
		   updated_at = ?
		 RETURNING failure_count, locked_until`,
		key, maxFailures, lockS, nowS, nowS, nowS, nowS, maxFailures, lockS, nowS,
	).Scan(&snap.FailureCount, &until)
	if err != nil {
		return domain.LoginAttemptSnapshot{}, false, err
	}
	snap.Key = key
	if until.Valid {
		if snap.LockedUntil, err = decodeTime(until.String); err != nil {
			return domain.LoginAttemptSnapshot{}, false, err
		}
	}
	justLocked := !snap.LockedUntil.IsZero() && snap.FailureCount == maxFailures
	return snap, justLocked, nil
}

// WorkloadKeyRepo is a SQLite domain.WorkloadStore. Only the hex SHA-256 hash of
// each token is stored (the hash column is UNIQUE for the validation hot path);
// the raw token is never persisted. Scope is stored as a newline-joined list of
// canonical "resource:action" entries.
type WorkloadKeyRepo struct{ db DB }

// NewWorkloadKeyRepo builds a workload-key repository over db.
func NewWorkloadKeyRepo(db DB) *WorkloadKeyRepo { return &WorkloadKeyRepo{db: db} }

// CreateKey inserts a new key, mapping a unique-violation to domain.ErrConflict.
func (r *WorkloadKeyRepo) CreateKey(ctx context.Context, k domain.APIKey) error {
	snap := k.Snapshot()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO authgo_workload_keys (id, hash, worker_id, scope, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		snap.ID, snap.Hash, snap.WorkerID, encodeScope(snap.Scope), encodeTime(snap.ExpiresAt), encodeTime(snap.CreatedAt),
	)
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

// GetKeyByHash loads a key by token hash or returns domain.ErrNotFound.
func (r *WorkloadKeyRepo) GetKeyByHash(ctx context.Context, hash string) (domain.APIKey, error) {
	return r.scanOne(ctx, `WHERE hash = ?`, hash)
}

// GetKey loads a key by ID or returns domain.ErrNotFound.
func (r *WorkloadKeyRepo) GetKey(ctx context.Context, id domain.KeyID) (domain.APIKey, error) {
	return r.scanOne(ctx, `WHERE id = ?`, id.String())
}

// scanOne loads the single key matching where (a parameterized clause).
func (r *WorkloadKeyRepo) scanOne(ctx context.Context, where string, arg any) (domain.APIKey, error) {
	var (
		snap                 domain.APIKeySnapshot
		scope                string
		expiresAt, createdAt string
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT id, hash, worker_id, scope, expires_at, created_at
		   FROM authgo_workload_keys `+where, arg,
	).Scan(&snap.ID, &snap.Hash, &snap.WorkerID, &scope, &expiresAt, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.APIKey{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.APIKey{}, err
	}
	snap.Scope = decodeScope(scope)
	if snap.ExpiresAt, err = decodeTime(expiresAt); err != nil {
		return domain.APIKey{}, err
	}
	if snap.CreatedAt, err = decodeTime(createdAt); err != nil {
		return domain.APIKey{}, err
	}
	return domain.APIKeyFromSnapshot(snap), nil
}

// ListKeysByWorker returns every key for a worker.
func (r *WorkloadKeyRepo) ListKeysByWorker(ctx context.Context, workerID domain.WorkerID) ([]domain.APIKey, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, hash, worker_id, scope, expires_at, created_at
		   FROM authgo_workload_keys WHERE worker_id = ?`, workerID.String(),
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []domain.APIKey
	for rows.Next() {
		var (
			snap                 domain.APIKeySnapshot
			scope                string
			expiresAt, createdAt string
		)
		if err := rows.Scan(&snap.ID, &snap.Hash, &snap.WorkerID, &scope, &expiresAt, &createdAt); err != nil {
			return nil, err
		}
		snap.Scope = decodeScope(scope)
		if snap.ExpiresAt, err = decodeTime(expiresAt); err != nil {
			return nil, err
		}
		if snap.CreatedAt, err = decodeTime(createdAt); err != nil {
			return nil, err
		}
		out = append(out, domain.APIKeyFromSnapshot(snap))
	}
	return out, rows.Err()
}

// DeleteKey removes a key by ID. Deleting an absent key returns ErrNotFound.
func (r *WorkloadKeyRepo) DeleteKey(ctx context.Context, id domain.KeyID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM authgo_workload_keys WHERE id = ?`, id.String())
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// txBeginner is the subset of *sql.DB that can start a transaction. A repo built
// over a *sql.DB satisfies it; a repo built over a *sql.Tx (composed into a
// caller's transaction) does not — in which case the swap below already runs
// inside that outer transaction and is atomic without a nested one.
type txBeginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// RotateAtomically deletes oldID and inserts newKey in a single transaction,
// implementing domain.AtomicRotator. When the repo is backed by a *sql.DB it
// opens a transaction so the delete+insert apply atomically (no window where
// both keys are live and no crash can leave the old key dangling). When backed
// by a *sql.Tx already (composed into a caller's transaction) it runs the two
// statements directly — they are already atomic within that outer transaction.
func (r *WorkloadKeyRepo) RotateAtomically(ctx context.Context, oldID domain.KeyID, newKey domain.APIKey) error {
	beginner, ok := r.db.(txBeginner)
	if !ok {
		// Already inside a caller-owned *sql.Tx: the two statements below are
		// atomic within it, so run them directly.
		return rotateSwap(ctx, r.db, oldID, newKey)
	}
	tx, err := beginner.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := rotateSwap(ctx, tx, oldID, newKey); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// rotateSwap performs the delete-old + insert-new pair over the given executor
// (a *sql.DB, *sql.Tx, or this package's DB). The delete must affect exactly one
// row (ErrNotFound otherwise); a duplicate insert maps to ErrConflict.
func rotateSwap(ctx context.Context, db DB, oldID domain.KeyID, newKey domain.APIKey) error {
	res, err := db.ExecContext(ctx, `DELETE FROM authgo_workload_keys WHERE id = ?`, oldID.String())
	if err != nil {
		return err
	}
	if err := requireOneRow(res); err != nil {
		return err
	}
	snap := newKey.Snapshot()
	_, err = db.ExecContext(ctx,
		`INSERT INTO authgo_workload_keys (id, hash, worker_id, scope, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		snap.ID, snap.Hash, snap.WorkerID, encodeScope(snap.Scope), encodeTime(snap.ExpiresAt), encodeTime(snap.CreatedAt),
	)
	if isUniqueViolation(err) {
		return domain.ErrConflict
	}
	return err
}

// requireOneRow maps a zero-row write to domain.ErrNotFound.
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

// uint32SignCount converts a scanned INTEGER sign_count into the WebAuthn
// uint32 counter, rejecting values outside the type's range.
func uint32SignCount(count int64) (uint32, error) {
	if count < 0 || count > math.MaxUint32 {
		return 0, fmt.Errorf("sqlite: sign_count out of range: %d", count)
	}
	return uint32(count), nil
}

// boolToInt encodes a Go bool as SQLite's 0/1 integer boolean.
func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// scopeSep joins canonical scope entries on disk. The Scope value object rejects
// any segment containing a newline (see domain.validScopeSegment), so a newline
// is an unambiguous separator that cannot appear inside an entry.
const scopeSep = "\n"

// encodeScope joins canonical scope entries into the on-disk TEXT column.
func encodeScope(entries []string) string {
	return strings.Join(entries, scopeSep)
}

// decodeScope splits the on-disk scope TEXT back into entries, tolerating the
// empty string (no entries).
func decodeScope(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, scopeSep)
}

// isUniqueViolation reports whether err is a SQLite UNIQUE/PK constraint
// violation. The modernc.org/sqlite driver exposes the extended result code via
// a Code() method; 2067 (SQLITE_CONSTRAINT_UNIQUE) and 1555
// (SQLITE_CONSTRAINT_PRIMARYKEY) both map to a conflict. Detected structurally
// (no driver import) so the adapter stays driver-swappable.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var ce interface{ Code() int }
	if errors.As(err, &ce) {
		switch ce.Code() {
		case sqliteConstraintUnique, sqliteConstraintPrimaryKey:
			return true
		}
	}
	// Fallback: match on the driver's error text, which always names the
	// violated constraint. Keeps conflict detection working even if a future
	// driver revision changes how the code is surfaced.
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

const (
	sqliteConstraintPrimaryKey = 1555
	sqliteConstraintUnique     = 2067
)

// Port assertions.
var (
	_ domain.UserRepository        = (*UserRepo)(nil)
	_ domain.SessionRepository     = (*SessionRepo)(nil)
	_ domain.AtomicSessionRotator  = (*SessionRepo)(nil)
	_ domain.MagicLinkRepository   = (*MagicLinkRepo)(nil)
	_ domain.AtomicMagicLinkIssuer = (*MagicLinkRepo)(nil)
	_ domain.TOTPRepository        = (*TOTPRepo)(nil)
	_ domain.PasskeyRepository     = (*PasskeyRepo)(nil)
	_ domain.LoginAttemptStore     = (*LoginAttemptRepo)(nil)
	_ domain.WorkloadStore         = (*WorkloadKeyRepo)(nil)
	_ domain.AtomicRotator         = (*WorkloadKeyRepo)(nil)
)
