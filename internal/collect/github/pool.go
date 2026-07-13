package github

import (
	"context"
	"sync"
)

// DefaultConcurrency is the per-repo worker pool size ForEachRepo uses when
// concurrency <= 0 (docs/architecture.md: "default concurrency 4,
// flag-tunable" — the orchestrator, issue #10, is what exposes the
// --concurrency flag and passes a value through here).
const DefaultConcurrency = 4

// RepoResult pairs one repo with whatever a per-repo function produced for
// it.
type RepoResult[T any] struct {
	Repo  string
	Value T
	Err   error
}

// ForEachRepo runs fn once per repo in repos with up to concurrency
// goroutines in flight at a time (DefaultConcurrency if concurrency <= 0),
// and returns one RepoResult per repo in the same order as repos —
// regardless of completion order, so callers can correlate results back to
// their input without extra bookkeeping.
//
// If ctx is already canceled when a repo's turn to start comes up, fn is
// never called for it and its RepoResult carries ctx.Err(); a repo already
// in flight runs to completion (fn itself is responsible for honoring ctx
// if it wants to abort early — this only stops launching new work).
func ForEachRepo[T any](ctx context.Context, repos []string, concurrency int, fn func(ctx context.Context, repo string) (T, error)) []RepoResult[T] {
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}

	results := make([]RepoResult[T], len(repos))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, repo := range repos {
		// Explicit pre-check, not just the select below: when ctx is
		// already canceled AND the semaphore has room (the common case for
		// the first repo, or whenever concurrency exceeds what's currently
		// in flight), both select cases are immediately ready and Go picks
		// between them at random — so an already-canceled context could
		// still let a repo through on chance alone without this fast path.
		if ctx.Err() != nil {
			results[i] = RepoResult[T]{Repo: repo, Err: ctx.Err()}
			continue
		}
		// Then race acquiring a slot against cancellation, not just
		// check-then-block: a plain "check ctx.Done() then
		// sem <- struct{}{}" would miss cancellation that happens while
		// already blocked waiting for a slot to free up under a full pool.
		select {
		case <-ctx.Done():
			results[i] = RepoResult[T]{Repo: repo, Err: ctx.Err()}
			continue
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(i int, repo string) {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := fn(ctx, repo)
			results[i] = RepoResult[T]{Repo: repo, Value: v, Err: err}
		}(i, repo)
	}

	wg.Wait()
	return results
}
