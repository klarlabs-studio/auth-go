package domain_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/klarlabs-studio/auth-go/adapters/memory"
	"github.com/klarlabs-studio/auth-go/domain"
)

func mustWorkerID(t *testing.T, s string) domain.WorkerID {
	t.Helper()
	id, err := domain.NewWorkerID(s)
	if err != nil {
		t.Fatalf("NewWorkerID(%q): %v", s, err)
	}
	return id
}

func mustScope(t *testing.T, actions ...string) domain.Scope {
	t.Helper()
	sc, err := domain.NewScope(actions...)
	if err != nil {
		t.Fatalf("NewScope(%v): %v", actions, err)
	}
	return sc
}

// ── WorkerID ────────────────────────────────────────────────

func TestWorkerID_Validation(t *testing.T) {
	for _, bad := range []string{"", "  "} {
		if _, err := domain.NewWorkerID(bad); !errors.Is(err, domain.ErrInvalidWorkerID) {
			t.Fatalf("NewWorkerID(%q): want ErrInvalidWorkerID, got %v", bad, err)
		}
	}
	id := mustWorkerID(t, "agent-7")
	if id.String() != "agent-7" || id.IsZero() {
		t.Fatalf("unexpected: %+v", id)
	}
	if (domain.WorkerID{}).IsZero() != true {
		t.Fatal("zero WorkerID must be zero")
	}
}

// ── Scope: validation ───────────────────────────────────────

func TestScope_Validation(t *testing.T) {
	cases := []struct {
		name    string
		actions []string
		wantErr bool
	}{
		{"empty set", nil, true},
		{"single", []string{"tools:read"}, false},
		{"wildcard action", []string{"tools:*"}, false},
		{"multiple", []string{"tools:read", "memory:write"}, false},
		{"missing colon", []string{"toolsread"}, true},
		{"empty resource", []string{":read"}, true},
		{"empty action", []string{"tools:"}, true},
		{"blank entry", []string{"   "}, true},
		{"too many colons", []string{"a:b:c"}, true},
		{"full wildcard", []string{"*:*"}, false},
		{"resource wildcard", []string{"*:read"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := domain.NewScope(tc.actions...)
			if tc.wantErr && !errors.Is(err, domain.ErrInvalidScope) {
				t.Fatalf("want ErrInvalidScope, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
		})
	}
}

func TestScope_NormalizesAndDeduplicates(t *testing.T) {
	sc := mustScope(t, " tools:read ", "tools:read", "Memory:Write")
	got := sc.Actions()
	if len(got) != 2 {
		t.Fatalf("want 2 deduped/normalized actions, got %v", got)
	}
	// normalized lower-case, trimmed
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "tools:read") || !strings.Contains(joined, "memory:write") {
		t.Fatalf("normalization failed: %v", got)
	}
}

// ── Scope: matching (incl. wildcard) ────────────────────────

func TestScope_Allows(t *testing.T) {
	cases := []struct {
		name    string
		granted []string
		query   string
		want    bool
	}{
		{"exact", []string{"tools:read"}, "tools:read", true},
		{"exact miss action", []string{"tools:read"}, "tools:write", false},
		{"exact miss resource", []string{"tools:read"}, "memory:read", false},
		{"action wildcard hit", []string{"tools:*"}, "tools:read", true},
		{"action wildcard hit2", []string{"tools:*"}, "tools:write", true},
		{"action wildcard miss resource", []string{"tools:*"}, "memory:read", false},
		{"resource wildcard hit", []string{"*:read"}, "tools:read", true},
		{"resource wildcard miss action", []string{"*:read"}, "tools:write", false},
		{"full wildcard hit", []string{"*:*"}, "anything:goes", true},
		{"one of many", []string{"a:b", "tools:*"}, "tools:read", true},
		{"none of many", []string{"a:b", "c:d"}, "tools:read", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := mustScope(t, tc.granted...)
			q, err := domain.NewPermission(tc.query)
			if err != nil {
				t.Fatalf("NewPermission(%q): %v", tc.query, err)
			}
			if got := sc.Allows(q); got != tc.want {
				t.Fatalf("Allows(%q) over %v = %v, want %v", tc.query, tc.granted, got, tc.want)
			}
		})
	}
}

func TestPermission_Validation(t *testing.T) {
	for _, bad := range []string{"", "noColon", "a:b:c", ":x", "x:"} {
		if _, err := domain.NewPermission(bad); !errors.Is(err, domain.ErrInvalidScope) {
			t.Fatalf("NewPermission(%q): want ErrInvalidScope, got %v", bad, err)
		}
	}
}

// ── Token entropy / format ──────────────────────────────────

func TestNewWorkloadToken_EntropyAndFormat(t *testing.T) {
	a, err := domain.NewWorkloadToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := domain.NewWorkloadToken()
	if a.String() == b.String() {
		t.Fatal("tokens not random")
	}
	// 32 bytes hex-encoded → 64 hex chars
	if len(a.String()) != 64 {
		t.Fatalf("want 64 hex chars, got %d (%q)", len(a.String()), a.String())
	}
	for _, c := range a.String() {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("non-hex char %q in token", c)
		}
	}
	if _, err := domain.WorkloadTokenFromString(""); !errors.Is(err, domain.ErrInvalidKeyToken) {
		t.Fatalf("empty token: want ErrInvalidKeyToken, got %v", err)
	}
	if _, err := domain.WorkloadTokenFromString("not-hex-zz"); !errors.Is(err, domain.ErrInvalidKeyToken) {
		t.Fatalf("bad hex: want ErrInvalidKeyToken, got %v", err)
	}
}

// ── APIKey aggregate / snapshot ─────────────────────────────

func TestAPIKey_SnapshotRoundTrip(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	repo := memory.NewWorkloadKeyRepo()
	svc := domain.NewWorkloadKeyService(repo, fixedClock(&now))

	key, raw, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  mustWorkerID(t, "agent-1"),
		Scope:     mustScope(t, "tools:*"),
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	snap := key.Snapshot()
	if snap.Hash != domain.HashWorkloadToken(raw) {
		t.Fatal("snapshot hash is not the hash of the raw token")
	}
	rt := domain.APIKeyFromSnapshot(snap)
	if rt.ID() != key.ID() || rt.WorkerID().String() != "agent-1" {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", rt.Snapshot(), snap)
	}
	if !rt.Scope().Allows(mustPerm(t, "tools:read")) {
		t.Fatal("scope lost across snapshot")
	}
}

func mustPerm(t *testing.T, s string) domain.Permission {
	t.Helper()
	p, err := domain.NewPermission(s)
	if err != nil {
		t.Fatalf("NewPermission(%q): %v", s, err)
	}
	return p
}

// ── WorkloadKeyService: issue / validate ────────────────────

func TestWorkloadKeyService_IssueStoresHashOnly(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	repo := memory.NewWorkloadKeyRepo()
	svc := domain.NewWorkloadKeyService(repo, fixedClock(&now))

	key, raw, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  mustWorkerID(t, "agent-1"),
		Scope:     mustScope(t, "tools:read"),
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if raw.String() == "" {
		t.Fatal("raw token empty")
	}
	// The raw token must NEVER be a storage key.
	if _, err := repo.GetKeyByHash(ctx, raw.String()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatal("raw token used as storage key — must be hashed")
	}
	// The hash must be retrievable.
	stored, err := repo.GetKeyByHash(ctx, domain.HashWorkloadToken(raw))
	if err != nil {
		t.Fatalf("hash lookup: %v", err)
	}
	if stored.ID() != key.ID() {
		t.Fatalf("hash lookup wrong key: %v vs %v", stored.ID(), key.ID())
	}
	// Plaintext token must not appear anywhere in the snapshot.
	if stored.Snapshot().Hash == raw.String() {
		t.Fatal("plaintext token stored")
	}
}

func TestWorkloadKeyService_RejectsBadRequest(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	svc := domain.NewWorkloadKeyService(memory.NewWorkloadKeyRepo(), fixedClock(&now))

	// zero worker
	if _, _, err := svc.IssueKey(ctx, domain.KeyRequest{
		Scope:     mustScope(t, "tools:*"),
		ExpiresAt: now.Add(time.Hour),
	}); !errors.Is(err, domain.ErrInvalidWorkerID) {
		t.Fatalf("zero worker: want ErrInvalidWorkerID, got %v", err)
	}
	// empty scope
	if _, _, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  mustWorkerID(t, "a"),
		ExpiresAt: now.Add(time.Hour),
	}); !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("zero scope: want ErrInvalidScope, got %v", err)
	}
	// expiry in the past
	if _, _, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  mustWorkerID(t, "a"),
		Scope:     mustScope(t, "tools:*"),
		ExpiresAt: now.Add(-time.Hour),
	}); !errors.Is(err, domain.ErrInvalidExpiry) {
		t.Fatalf("past expiry: want ErrInvalidExpiry, got %v", err)
	}
}

func TestWorkloadKeyService_Validate(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	repo := memory.NewWorkloadKeyRepo()
	svc := domain.NewWorkloadKeyService(repo, fixedClock(&now))

	_, raw, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  mustWorkerID(t, "agent-1"),
		Scope:     mustScope(t, "tools:read", "memory:*"),
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	claims, err := svc.ValidateKey(ctx, raw)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.WorkerID.String() != "agent-1" {
		t.Fatalf("claims worker: %v", claims.WorkerID)
	}
	if !claims.Scope.Allows(mustPerm(t, "memory:write")) {
		t.Fatal("claims scope lost wildcard")
	}

	// Unknown token → ErrKeyNotFound.
	other, _ := domain.NewWorkloadToken()
	if _, err := svc.ValidateKey(ctx, other); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("unknown token: want ErrKeyNotFound, got %v", err)
	}

	// Expired token → ErrKeyExpired.
	now = now.Add(2 * time.Hour)
	if _, err := svc.ValidateKey(ctx, raw); !errors.Is(err, domain.ErrKeyExpired) {
		t.Fatalf("expired: want ErrKeyExpired, got %v", err)
	}
}

// mismatchStore returns, for any GetKeyByHash lookup, a key whose stored hash
// does NOT match the inbound token's hash — simulating a corrupted or attacker-
// substituted row. ValidateKey must reject it via the constant-time check.
type mismatchStore struct {
	domain.WorkloadStore
	key domain.APIKey
}

func (m *mismatchStore) GetKeyByHash(ctx context.Context, hash string) (domain.APIKey, error) {
	return m.key, nil
}

func TestWorkloadKeyService_ValidateRejectsHashMismatch(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	// Build a key whose stored hash is for some OTHER token.
	otherTok, _ := domain.NewWorkloadToken()
	storedKey := domain.APIKeyFromSnapshot(domain.APIKeySnapshot{
		ID:        "wk_x",
		Hash:      domain.HashWorkloadToken(otherTok),
		WorkerID:  "agent-1",
		Scope:     []string{"tools:*"},
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	})
	ms := &mismatchStore{WorkloadStore: memory.NewWorkloadKeyRepo(), key: storedKey}
	svc := domain.NewWorkloadKeyService(ms, fixedClock(&now))

	// Validate with a DIFFERENT token: the store returns storedKey regardless,
	// but its hash does not match the inbound token → ErrKeyNotFound.
	inbound, _ := domain.NewWorkloadToken()
	if _, err := svc.ValidateKey(ctx, inbound); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("hash mismatch: want ErrKeyNotFound, got %v", err)
	}
}

// ── WorkloadKeyService: authorize ───────────────────────────

func TestWorkloadKeyService_Authorize(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	repo := memory.NewWorkloadKeyRepo()
	svc := domain.NewWorkloadKeyService(repo, fixedClock(&now))

	_, raw, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  mustWorkerID(t, "agent-1"),
		Scope:     mustScope(t, "tools:*"),
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	// match (wildcard)
	if err := svc.Authorize(ctx, raw, "tools:read"); err != nil {
		t.Fatalf("authorize match: %v", err)
	}
	// no match
	if err := svc.Authorize(ctx, raw, "memory:read"); !errors.Is(err, domain.ErrScopeDenied) {
		t.Fatalf("authorize no-match: want ErrScopeDenied, got %v", err)
	}
	// malformed permission
	if err := svc.Authorize(ctx, raw, "garbage"); !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("authorize bad perm: want ErrInvalidScope, got %v", err)
	}
	// expired
	now = now.Add(2 * time.Hour)
	if err := svc.Authorize(ctx, raw, "tools:read"); !errors.Is(err, domain.ErrKeyExpired) {
		t.Fatalf("authorize expired: want ErrKeyExpired, got %v", err)
	}
}

// ── WorkloadKeyService: revoke / revoke-all / list ──────────

func TestWorkloadKeyService_RevokeAndList(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	repo := memory.NewWorkloadKeyRepo()
	svc := domain.NewWorkloadKeyService(repo, fixedClock(&now))

	w := mustWorkerID(t, "agent-1")
	k1, raw1, _ := svc.IssueKey(ctx, domain.KeyRequest{WorkerID: w, Scope: mustScope(t, "tools:*"), ExpiresAt: now.Add(time.Hour)})
	_, raw2, _ := svc.IssueKey(ctx, domain.KeyRequest{WorkerID: w, Scope: mustScope(t, "memory:*"), ExpiresAt: now.Add(time.Hour)})
	other := mustWorkerID(t, "agent-2")
	_, rawO, _ := svc.IssueKey(ctx, domain.KeyRequest{WorkerID: other, Scope: mustScope(t, "tools:*"), ExpiresAt: now.Add(time.Hour)})

	keys, err := svc.ListKeys(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("list: want 2, got %d", len(keys))
	}

	// Revoke one.
	if err := svc.RevokeKey(ctx, k1.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateKey(ctx, raw1); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("revoked key still valid: %v", err)
	}
	if _, err := svc.ValidateKey(ctx, raw2); err != nil {
		t.Fatalf("revoke hit wrong key: %v", err)
	}

	// Revoke unknown ID → ErrKeyNotFound.
	if err := svc.RevokeKey(ctx, domain.KeyID("nope")); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("revoke unknown: want ErrKeyNotFound, got %v", err)
	}

	// Revoke all for worker.
	if err := svc.RevokeAllKeys(ctx, w); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateKey(ctx, raw2); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("revoke-all missed a key: %v", err)
	}
	// Other worker survives.
	if _, err := svc.ValidateKey(ctx, rawO); err != nil {
		t.Fatalf("revoke-all hit another worker: %v", err)
	}
	left, _ := svc.ListKeys(ctx, w)
	if len(left) != 0 {
		t.Fatalf("revoke-all left keys: %+v", left)
	}
}

// ── WorkloadKeyService: rotate (atomic) ─────────────────────

func TestWorkloadKeyService_Rotate(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	repo := memory.NewWorkloadKeyRepo()
	svc := domain.NewWorkloadKeyService(repo, fixedClock(&now))

	w := mustWorkerID(t, "agent-1")
	old, oldRaw, _ := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  w,
		Scope:     mustScope(t, "tools:read", "memory:*"),
		ExpiresAt: now.Add(time.Hour),
	})

	newKey, newRaw, err := svc.RotateKey(ctx, old.ID())
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// New ID differs, new token differs.
	if newKey.ID() == old.ID() {
		t.Fatal("rotate reused key ID")
	}
	if newRaw.String() == oldRaw.String() {
		t.Fatal("rotate reused token")
	}
	// Old token invalid.
	if _, err := svc.ValidateKey(ctx, oldRaw); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("old token survived rotate: %v", err)
	}
	// New token valid and preserves scope + worker + expiry.
	claims, err := svc.ValidateKey(ctx, newRaw)
	if err != nil {
		t.Fatalf("new token invalid: %v", err)
	}
	if claims.WorkerID.String() != "agent-1" {
		t.Fatalf("rotated worker mismatch: %v", claims.WorkerID)
	}
	if !claims.Scope.Allows(mustPerm(t, "tools:read")) || !claims.Scope.Allows(mustPerm(t, "memory:write")) {
		t.Fatal("rotate lost scope")
	}
	if !newKey.ExpiresAt().Equal(old.ExpiresAt()) {
		t.Fatalf("rotate changed expiry: %v vs %v", newKey.ExpiresAt(), old.ExpiresAt())
	}

	// Rotate unknown → ErrKeyNotFound.
	if _, _, err := svc.RotateKey(ctx, domain.KeyID("nope")); !errors.Is(err, domain.ErrKeyNotFound) {
		t.Fatalf("rotate unknown: want ErrKeyNotFound, got %v", err)
	}
}

// ── Accessors / value-object surface ────────────────────────

func TestAPIKey_AccessorsAndPermissionParts(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewWorkloadKeyService(memory.NewWorkloadKeyRepo(), fixedClock(&now))
	key, raw, err := svc.IssueKey(context.Background(), domain.KeyRequest{
		WorkerID:  mustWorkerID(t, "agent-1"),
		Scope:     mustScope(t, "tools:read"),
		ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if key.IsZero() {
		t.Fatal("issued key reads as zero")
	}
	if (domain.APIKey{}).IsZero() != true {
		t.Fatal("zero APIKey must be zero")
	}
	if key.Hash() != domain.HashWorkloadToken(raw) {
		t.Fatal("Hash() accessor mismatch")
	}
	if !key.CreatedAt().Equal(now) {
		t.Fatalf("CreatedAt: %v", key.CreatedAt())
	}
	if key.ID().String() == "" {
		t.Fatal("KeyID String empty")
	}

	p := mustPerm(t, "tools:read")
	if p.Resource() != "tools" || p.Action() != "read" || p.String() != "tools:read" {
		t.Fatalf("permission parts: %+v / %q", p, p.String())
	}
}

// failStore wraps a WorkloadStore and injects errors on selected operations.
// failDeleteID fails DeleteKey only for a specific ID, so a rollback delete of
// a different (new) key can still succeed — letting tests exercise the
// rollback path precisely.
type failStore struct {
	domain.WorkloadStore
	failCreate   error
	failDeleteID domain.KeyID
	deleteErr    error
}

func (f *failStore) CreateKey(ctx context.Context, k domain.APIKey) error {
	if f.failCreate != nil {
		return f.failCreate
	}
	return f.WorkloadStore.CreateKey(ctx, k)
}

func (f *failStore) DeleteKey(ctx context.Context, id domain.KeyID) error {
	if f.deleteErr != nil && id == f.failDeleteID {
		return f.deleteErr
	}
	return f.WorkloadStore.DeleteKey(ctx, id)
}

func TestWorkloadKeyService_StoreErrorsSurface(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	sentinel := errors.New("db down")

	// IssueKey surfaces CreateKey errors.
	fs := &failStore{WorkloadStore: memory.NewWorkloadKeyRepo(), failCreate: sentinel}
	svc := domain.NewWorkloadKeyService(fs, fixedClock(&now))
	if _, _, err := svc.IssueKey(ctx, domain.KeyRequest{
		WorkerID: mustWorkerID(t, "a"), Scope: mustScope(t, "tools:*"), ExpiresAt: now.Add(time.Hour),
	}); !errors.Is(err, sentinel) {
		t.Fatalf("issue create error: want sentinel, got %v", err)
	}

	// RotateKey rolls back the new key when deleting the old one fails.
	base := memory.NewWorkloadKeyRepo()
	fs2 := &failStore{WorkloadStore: base}
	svc2 := domain.NewWorkloadKeyService(fs2, fixedClock(&now))
	old, _, err := svc2.IssueKey(ctx, domain.KeyRequest{
		WorkerID: mustWorkerID(t, "a"), Scope: mustScope(t, "tools:*"), ExpiresAt: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Fail only the delete of the OLD key; the rollback delete of the new key
	// then succeeds, so exactly the original key remains.
	fs2.failDeleteID = old.ID()
	fs2.deleteErr = sentinel
	if _, _, err := svc2.RotateKey(ctx, old.ID()); !errors.Is(err, sentinel) {
		t.Fatalf("rotate delete error: want sentinel, got %v", err)
	}
	fs2.deleteErr = nil
	// Exactly one key remains — the rollback removed the new one and the old one
	// was never deleted (its delete failed).
	left, _ := base.ListKeysByWorker(ctx, mustWorkerID(t, "a"))
	if len(left) != 1 || left[0].ID() != old.ID() {
		t.Fatalf("rollback left wrong keys: %+v", left)
	}
}

func TestWorkloadKeyService_RejectsExpiredOnIssueIsImmediate(t *testing.T) {
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc := domain.NewWorkloadKeyService(memory.NewWorkloadKeyRepo(), fixedClock(&now))
	// expiry exactly now → treated as already expired (not after now).
	if _, _, err := svc.IssueKey(context.Background(), domain.KeyRequest{
		WorkerID:  mustWorkerID(t, "a"),
		Scope:     mustScope(t, "tools:*"),
		ExpiresAt: now,
	}); !errors.Is(err, domain.ErrInvalidExpiry) {
		t.Fatalf("now expiry: want ErrInvalidExpiry, got %v", err)
	}
}
