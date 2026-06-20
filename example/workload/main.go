// Command workload is a minimal, self-contained walkthrough of workload
// identity: issuing a scoped API key for an agent worker, validating it,
// authorizing a concrete action against its scope, rotating it, and revoking.
// It wires the in-memory adapter so it runs with no external services — swap in
// adapters/sqlite or adapters/pgstore (which rotate atomically) in production.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/klarlabs-studio/auth-go/adapters/memory"
	"github.com/klarlabs-studio/auth-go/domain"
)

func main() {
	ctx := context.Background()

	wl := domain.NewWorkloadKeyService(memory.NewWorkloadKeyRepo(), nil)

	worker, err := domain.NewWorkerID("worker-abc123")
	must(err)
	scope, err := domain.NewScope("memory:read", "memory:write", "browser:read")
	must(err)

	// Issue — the raw token is returned ONCE; only its hash is stored.
	key, token, err := wl.IssueKey(ctx, domain.KeyRequest{
		WorkerID:  worker,
		Scope:     scope,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})
	must(err)
	fmt.Printf("issued key %s; hand this token to the worker once: %s…\n", key.ID(), token.String()[:12])

	// Validate — called on every inbound request from the worker.
	claims, err := wl.ValidateKey(ctx, token)
	must(err)
	fmt.Printf("validated: worker=%s scope=%v\n", claims.WorkerID, claims.Scope.Actions())

	// Authorize a concrete action against the granted scope.
	must(wl.Authorize(ctx, token, "memory:write"))
	fmt.Println("authorized memory:write")
	if err := wl.Authorize(ctx, token, "email:send"); errors.Is(err, domain.ErrScopeDenied) {
		fmt.Println("denied email:send (not in scope), as expected")
	}

	// Rotate — issue new, invalidate old (atomic on the sql adapters).
	newKey, newToken, err := wl.RotateKey(ctx, key.ID())
	must(err)
	fmt.Printf("rotated to key %s; new token=%s…\n", newKey.ID(), newToken.String()[:12])
	if _, err := wl.ValidateKey(ctx, token); errors.Is(err, domain.ErrKeyNotFound) {
		fmt.Println("old token rejected after rotation, as expected")
	}

	// List, then revoke everything for the worker (kill-switch).
	keys, err := wl.ListKeys(ctx, worker)
	must(err)
	fmt.Printf("worker has %d active key(s)\n", len(keys))
	must(wl.RevokeAllKeys(ctx, worker))
	fmt.Println("revoked all keys for worker")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
