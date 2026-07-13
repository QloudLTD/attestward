package github

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestForEachRepo_RunsEveryRepoAndPreservesOrder(t *testing.T) {
	repos := []string{"repo-a", "repo-b", "repo-c", "repo-d"}
	results := ForEachRepo(context.Background(), repos, 2, func(_ context.Context, repo string) (string, error) {
		return "processed:" + repo, nil
	})

	if len(results) != len(repos) {
		t.Fatalf("len(results) = %d, want %d", len(results), len(repos))
	}
	for i, repo := range repos {
		if results[i].Repo != repo {
			t.Errorf("results[%d].Repo = %q, want %q (order must match input)", i, results[i].Repo, repo)
		}
		if results[i].Value != "processed:"+repo {
			t.Errorf("results[%d].Value = %q, want %q", i, results[i].Value, "processed:"+repo)
		}
		if results[i].Err != nil {
			t.Errorf("results[%d].Err = %v, want nil", i, results[i].Err)
		}
	}
}

// TestForEachRepo_PreCanceledContextNeverDispatchesAny is a regression
// test for a latent bug found while fixing a near-identical issue in
// cmd/attestor's runCollectors (issue #10's Fable 5 review): when ctx is
// already canceled *before* ForEachRepo is even called, and the semaphore
// has room (true for the first repo), the original select raced ctx.Done()
// against an immediately-ready sem<- — both cases ready at once, so Go's
// random tie-breaking could still let fn run. Confirmed flaky before the
// fix (failed roughly half the time over repeated runs); this asserts it
// deterministically now.
func TestForEachRepo_PreCanceledContextNeverDispatchesAny(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var dispatched int32
	ForEachRepo(ctx, []string{"repo-a"}, 1, func(context.Context, string) (string, error) {
		atomic.AddInt32(&dispatched, 1)
		return "x", nil
	})
	if dispatched != 0 {
		t.Fatal("fn was called despite ctx already being canceled before ForEachRepo started")
	}
}

func TestForEachRepo_NeverExceedsConcurrencyLimit(t *testing.T) {
	repos := make([]string, 20)
	for i := range repos {
		repos[i] = "repo"
	}

	var inFlight, maxInFlight int32
	const concurrency = 3

	ForEachRepo(context.Background(), repos, concurrency, func(_ context.Context, _ string) (struct{}, error) {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			m := atomic.LoadInt32(&maxInFlight)
			if cur <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, cur) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond) // hold the slot briefly so overlap is observable
		atomic.AddInt32(&inFlight, -1)
		return struct{}{}, nil
	})

	if got := atomic.LoadInt32(&maxInFlight); got > concurrency {
		t.Errorf("max observed in-flight = %d, want <= %d", got, concurrency)
	}
}

func TestForEachRepo_DefaultsConcurrencyWhenNonPositive(t *testing.T) {
	repos := make([]string, DefaultConcurrency+5)
	for i := range repos {
		repos[i] = "repo"
	}

	var inFlight, maxInFlight int32
	ForEachRepo(context.Background(), repos, 0, func(_ context.Context, _ string) (struct{}, error) {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			m := atomic.LoadInt32(&maxInFlight)
			if cur <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, cur) {
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		return struct{}{}, nil
	})

	if got := atomic.LoadInt32(&maxInFlight); got > DefaultConcurrency {
		t.Errorf("max observed in-flight = %d, want <= DefaultConcurrency (%d)", got, DefaultConcurrency)
	}
}

func TestForEachRepo_CanceledContextSkipsNotYetStartedRepos(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var started sync.WaitGroup
	started.Add(1)
	release := make(chan struct{})

	repos := []string{"first", "second", "third"}

	// ForEachRepo is synchronous (blocks until every repo is processed), so
	// it must run in its own goroutine here — the test needs to observe
	// "first" running, cancel ctx, and unblock "first" *while ForEachRepo
	// is still in flight*, not after it returns.
	resultsCh := make(chan []RepoResult[string], 1)
	go func() {
		resultsCh <- ForEachRepo(ctx, repos, 1, func(_ context.Context, repo string) (string, error) {
			if repo == "first" {
				started.Done()
				<-release // hold the only worker slot until the test cancels ctx
			}
			// Deliberately ignores ctx: this fn represents work that
			// finishes on its own terms once started, regardless of a
			// cancellation that arrives after it began — that's what
			// "already in flight runs to completion" means. What ctx
			// cancellation actually stops is ForEachRepo launching fn for
			// repos whose turn hasn't come up yet (asserted below).
			return repo, nil
		})
	}()

	// Wait for "first" to actually be running, then cancel. The sleep here
	// is deliberate, not laziness: ForEachRepo's loop is blocked in a
	// select on ctx.Done() vs acquiring "first"'s semaphore slot (still
	// held), so as long as ctx.Done() becomes ready before the slot frees,
	// the select has only one ready case and must take it — no randomness.
	// But that requires the runtime to actually schedule the blocked
	// select goroutine before this one proceeds to close(release) and free
	// the slot; without a yield, that ordering isn't guaranteed. A goroutine
	// wakeup on a closed channel is a microsecond-scale event, so this
	// margin is not a source of real flakiness in practice.
	started.Wait()
	cancel()
	time.Sleep(50 * time.Millisecond)
	close(release)

	var results []RepoResult[string]
	select {
	case results = <-resultsCh:
	case <-time.After(5 * time.Second):
		t.Fatal("ForEachRepo did not return within 5s of cancellation — likely deadlocked")
	}

	if results[0].Repo != "first" || results[0].Err != nil {
		t.Errorf("results[0] = %+v, want the in-flight repo to complete normally", results[0])
	}
	// "second" and "third" were still queued (concurrency=1) when ctx was
	// canceled, so ForEachRepo must not have called fn for them.
	for i := 1; i < len(results); i++ {
		if results[i].Err == nil {
			t.Errorf("results[%d] = %+v, want ctx.Err() (canceled before this repo started)", i, results[i])
		}
	}
}
