package domain

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// WorkerID identifies an agent worker — the principal a workload API key is
// issued to. Opaque, non-empty.
type WorkerID struct{ v string }

// NewWorkerID validates and constructs a WorkerID.
func NewWorkerID(s string) (WorkerID, error) {
	if strings.TrimSpace(s) == "" {
		return WorkerID{}, ErrInvalidWorkerID
	}
	return WorkerID{v: s}, nil
}

// String returns the raw identifier.
func (w WorkerID) String() string { return w.v }

// IsZero reports whether the WorkerID is unset.
func (w WorkerID) IsZero() bool { return w.v == "" }

// KeyID is the opaque, server-side identifier of an APIKey. It is safe to
// surface to operators (for revocation/rotation) — it is not a credential.
type KeyID string

// String returns the raw identifier.
func (k KeyID) String() string { return string(k) }

// Permission is a single validated "resource:action" capability query — what a
// caller is asking to do. Construct with NewPermission. Wildcards are not valid
// in a query (you authorize a concrete action), only in a granted Scope.
type Permission struct {
	resource string
	action   string
}

// NewPermission parses and validates a concrete "resource:action" string.
func NewPermission(s string) (Permission, error) {
	res, act, err := splitScopeEntry(s)
	if err != nil {
		return Permission{}, err
	}
	return Permission{resource: res, action: act}, nil
}

// Resource returns the resource half.
func (p Permission) Resource() string { return p.resource }

// Action returns the action half.
func (p Permission) Action() string { return p.action }

// String returns the canonical "resource:action" form.
func (p Permission) String() string { return p.resource + ":" + p.action }

// Scope is an immutable value object: the set of "resource:action" capabilities
// granted to a key. Entries support wildcards — "tools:*" matches every action
// on tools, "*:read" every read, "*:*" everything. Construct with NewScope,
// which normalizes (trim + lower-case) and de-duplicates entries.
type Scope struct {
	// entries holds canonical "resource:action" strings, sorted for a stable
	// snapshot. Stored as a string so Scope stays comparable and copy-safe.
	entries []string
}

// NewScope validates, normalizes, and de-duplicates the granted capabilities.
// At least one valid "resource:action" entry is required.
func NewScope(actions ...string) (Scope, error) {
	set := make(map[string]struct{}, len(actions))
	for _, a := range actions {
		res, act, err := splitScopeEntryAllowWildcard(a)
		if err != nil {
			return Scope{}, err
		}
		set[res+":"+act] = struct{}{}
	}
	if len(set) == 0 {
		return Scope{}, ErrInvalidScope
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return Scope{entries: out}, nil
}

// Actions returns the granted entries in canonical, sorted form. The returned
// slice is a copy — mutating it does not affect the Scope.
func (s Scope) Actions() []string {
	out := make([]string, len(s.entries))
	copy(out, s.entries)
	return out
}

// IsZero reports whether the Scope grants nothing.
func (s Scope) IsZero() bool { return len(s.entries) == 0 }

// Allows reports whether any granted entry covers the requested permission,
// honoring "*" wildcards in either the resource or action half of an entry.
func (s Scope) Allows(p Permission) bool {
	for _, e := range s.entries {
		res, act, ok := strings.Cut(e, ":")
		if !ok {
			continue
		}
		if (res == "*" || res == p.resource) && (act == "*" || act == p.action) {
			return true
		}
	}
	return false
}

// splitScopeEntry parses a concrete (no-wildcard) "resource:action" string.
func splitScopeEntry(s string) (resource, action string, err error) {
	resource, action, err = splitScopeEntryAllowWildcard(s)
	if err != nil {
		return "", "", err
	}
	if resource == "*" || action == "*" {
		return "", "", ErrInvalidScope
	}
	return resource, action, nil
}

// splitScopeEntryAllowWildcard parses a "resource:action" entry, permitting "*"
// in either half. Both halves must be non-empty and there must be exactly one
// colon. Normalizes by trimming surrounding space and lower-casing.
func splitScopeEntryAllowWildcard(s string) (resource, action string, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	res, act, ok := strings.Cut(s, ":")
	if !ok {
		return "", "", ErrInvalidScope
	}
	// reject a second colon (e.g. "a:b:c")
	if strings.Contains(act, ":") {
		return "", "", ErrInvalidScope
	}
	if res == "" || act == "" {
		return "", "", ErrInvalidScope
	}
	return res, act, nil
}

// WorkloadToken is the raw, high-entropy bearer credential handed to an agent
// worker exactly once at issue time. Only its SHA-256 hash is persisted (see
// HashToken); the raw value is never stored. 32 bytes of crypto/rand,
// hex-encoded (64 chars).
type WorkloadToken struct{ v string }

// workloadTokenBytes is the entropy of a WorkloadToken (256-bit).
const workloadTokenBytes = 32

// NewWorkloadToken returns a cryptographically random hex-encoded token.
func NewWorkloadToken() (WorkloadToken, error) {
	b := make([]byte, workloadTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return WorkloadToken{}, err
	}
	return WorkloadToken{v: hex.EncodeToString(b)}, nil
}

// WorkloadTokenFromString wraps an inbound token (e.g. from an Authorization
// header), validating its hex format and length.
func WorkloadTokenFromString(s string) (WorkloadToken, error) {
	if len(s) != workloadTokenBytes*2 {
		return WorkloadToken{}, ErrInvalidKeyToken
	}
	if _, err := hex.DecodeString(s); err != nil {
		return WorkloadToken{}, ErrInvalidKeyToken
	}
	return WorkloadToken{v: s}, nil
}

// String returns the raw token.
func (t WorkloadToken) String() string { return t.v }

// HashWorkloadToken returns the hex SHA-256 of a raw workload token — the
// storage key. Exposed so services and adapters agree on the keying without
// duplicating it, and so callers can confirm only the hash is persisted.
func HashWorkloadToken(raw WorkloadToken) string {
	return hashString(raw.v)
}

// APIKey is an aggregate: a scoped, time-boxed credential issued to an agent
// worker. Only the hex SHA-256 Hash of the raw token is persisted — the raw
// token is returned once by the service and never stored. Construct through
// WorkloadKeyService, never by hand.
type APIKey struct {
	id        KeyID
	hash      string
	workerID  WorkerID
	scope     Scope
	expiresAt time.Time
	createdAt time.Time
}

// ID returns the server-side key identifier.
func (k APIKey) ID() KeyID { return k.id }

// Hash returns the storage key (hex SHA-256 of the raw token).
func (k APIKey) Hash() string { return k.hash }

// WorkerID returns the owning worker.
func (k APIKey) WorkerID() WorkerID { return k.workerID }

// Scope returns the granted capabilities.
func (k APIKey) Scope() Scope { return k.scope }

// ExpiresAt returns the expiry.
func (k APIKey) ExpiresAt() time.Time { return k.expiresAt }

// CreatedAt returns the issue time.
func (k APIKey) CreatedAt() time.Time { return k.createdAt }

// Expired reports whether the key has expired as of now.
func (k APIKey) Expired(now time.Time) bool { return !now.Before(k.expiresAt) }

// IsZero reports whether the key is the zero value.
func (k APIKey) IsZero() bool { return k.id == "" }

// APIKeySnapshot is the flat, exportable shape of an APIKey for persistence.
// Adapters convert between APIKey and APIKeySnapshot; the aggregate's fields
// stay unexported so invariants cannot be bypassed. Scope is stored as its
// canonical entry list.
type APIKeySnapshot struct {
	ID        string
	Hash      string
	WorkerID  string
	Scope     []string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Snapshot exports the key for storage.
func (k APIKey) Snapshot() APIKeySnapshot {
	return APIKeySnapshot{
		ID:        string(k.id),
		Hash:      k.hash,
		WorkerID:  k.workerID.v,
		Scope:     k.scope.Actions(),
		ExpiresAt: k.expiresAt,
		CreatedAt: k.createdAt,
	}
}

// APIKeyFromSnapshot rehydrates a key from storage without re-validating
// entropy (the hash already existed). Adapter-only.
func APIKeyFromSnapshot(s APIKeySnapshot) APIKey {
	return APIKey{
		id:        KeyID(s.ID),
		hash:      s.Hash,
		workerID:  WorkerID{v: s.WorkerID},
		scope:     Scope{entries: append([]string(nil), s.Scope...)},
		expiresAt: s.ExpiresAt,
		createdAt: s.CreatedAt,
	}
}

// WorkloadStore is the persistence port for workload API keys. Implementations
// must be safe for concurrent use and must key on Hash for GetKeyByHash so the
// hot validation path is a single lookup. Every method takes a context.Context
// first so storage I/O honors cancellation, deadlines, and trace propagation.
type WorkloadStore interface {
	// CreateKey inserts a new key. Implementations SHOULD reject a duplicate ID
	// or Hash rather than silently overwrite.
	CreateKey(ctx context.Context, k APIKey) error
	// GetKeyByHash returns the key for a token hash or ErrNotFound.
	GetKeyByHash(ctx context.Context, hash string) (APIKey, error)
	// GetKey returns the key for an ID or ErrNotFound.
	GetKey(ctx context.Context, id KeyID) (APIKey, error)
	// ListKeysByWorker returns every key for a worker (any order).
	ListKeysByWorker(ctx context.Context, workerID WorkerID) ([]APIKey, error)
	// UpdateKey replaces an existing key by ID; ErrNotFound if absent.
	UpdateKey(ctx context.Context, k APIKey) error
	// DeleteKey removes a key by ID. Deleting an absent key returns ErrNotFound.
	DeleteKey(ctx context.Context, id KeyID) error
}
