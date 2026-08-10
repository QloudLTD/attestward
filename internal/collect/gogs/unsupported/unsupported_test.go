package unsupported

import (
	"context"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	"gitlab.com/sioakeim/attestward/internal/model"
)

func collectAll(t *testing.T, scope collect.Scope) []model.CheckResult {
	t.Helper()
	var all []model.CheckResult
	for _, c := range Collectors() {
		got, err := c.Collect(context.Background(), scope)
		if err != nil {
			t.Fatalf("%s.Collect: %v", c.ID(), err)
		}
		all = append(all, got...)
	}
	return all
}

// TestEveryCheckIsEmittedForEveryRepo is the whole point of this package.
// The failure it guards against is silent: a Gogs pack that simply omits
// the checks Gogs cannot answer gives a reader no way to distinguish "not
// applicable to this platform" from "the scan stopped early", and a missing
// row reads like a clean one.
func TestEveryCheckIsEmittedForEveryRepo(t *testing.T) {
	repos := []string{"alpha", "beta"}
	results := collectAll(t, collect.Scope{Org: "acme", Repos: repos})

	var wantOrg, wantRepo int
	for _, c := range checks {
		if c.scope == orgScoped {
			wantOrg++
		} else {
			wantRepo++
		}
	}
	want := wantOrg + wantRepo*len(repos)
	if len(results) != want {
		t.Fatalf("emitted %d results for %d repos, want %d (%d org-scoped + %d repo-scoped × %d)",
			len(results), len(repos), want, wantOrg, wantRepo, len(repos))
	}

	seen := map[string]int{}
	for _, r := range results {
		seen[r.CheckID]++
	}
	for _, c := range checks {
		want := 1
		if c.scope == repoScoped {
			want = len(repos)
		}
		if seen[c.id] != want {
			t.Errorf("%s emitted %d times, want %d", c.id, seen[c.id], want)
		}
	}
}

// TestOrgScopedChecksSurviveAnEmptyRepoList: a scan that resolved no repos
// still says what it can about the account. Dropping these would let an
// empty repo list quietly shrink the pack.
func TestOrgScopedChecksSurviveAnEmptyRepoList(t *testing.T) {
	results := collectAll(t, collect.Scope{Org: "acme"})
	if len(results) == 0 {
		t.Fatal("no results for a scan with no repos, want the org-scoped checks")
	}
	for _, r := range results {
		if r.Scope.Repo != "" {
			t.Errorf("%s has Repo %q with no repos in scope", r.CheckID, r.Scope.Repo)
		}
	}
}

// TestNothingIsEverVerifiedFail is the honesty invariant. A verified-fail
// asserts that a control was looked for and found absent; nothing here was
// looked for, because there is nothing to look at. If a future edit ever
// makes one of these fail a producer, it fabricates a finding in a signed
// pack.
func TestNothingIsEverVerifiedFail(t *testing.T) {
	for _, r := range collectAll(t, collect.Scope{Org: "acme", Repos: []string{"alpha"}}) {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable — nothing in this package observed anything", r.CheckID, r.Status)
		}
		if len(r.Provenance) != 0 {
			t.Errorf("%s carries provenance, which would claim an API call that never happened", r.CheckID)
		}
		if r.Provenance == nil {
			t.Errorf("%s Provenance is nil, want an empty slice (pack schema invariant)", r.CheckID)
		}
		if r.Facts != nil {
			t.Errorf("%s carries facts, but observed nothing to derive them from", r.CheckID)
		}
	}
}

// TestEveryResultStampsTheGogsPlatform: without this, a Gogs result is
// indistinguishable from a GitHub one carrying the same check ID, and the
// two would be compared against each other in a diff.
func TestEveryResultStampsTheGogsPlatform(t *testing.T) {
	for _, r := range collectAll(t, collect.Scope{Org: "acme", Repos: []string{"alpha"}}) {
		if r.Scope.Platform != platform {
			t.Errorf("%s Scope.Platform = %q, want %q", r.CheckID, r.Scope.Platform, platform)
		}
	}
}

// TestReasonsAreSpecificAndDistinct guards the surface nothing else does.
// Reason strings render verbatim into signed packs and no CI check asserts
// on them; a copy-pasted or generic reason ("unsupported") would tell a
// reader nothing about what to do next. Every reason must be substantive,
// and no two checks may share one — identical prose across two checks is
// the tell for a paste that was never re-read.
func TestReasonsAreSpecificAndDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, c := range checks {
		if len(c.reason) < 60 {
			t.Errorf("%s reason is too terse to be actionable: %q", c.id, c.reason)
		}
		if strings.Contains(strings.ToLower(c.reason), "unsupported") {
			t.Errorf("%s reason says only that it is unsupported, which tells a reader nothing: %q", c.id, c.reason)
		}
		if prev, dup := seen[c.reason]; dup {
			t.Errorf("%s and %s share an identical reason — at least one was pasted and not re-read", prev, c.id)
		}
		seen[c.reason] = c.id
		if c.remediation == "" {
			t.Errorf("%s has no remediation; a reader is left with a gap and no next step", c.id)
		}
	}
}

// TestNoOverlapWithTheRealGogsCollectors: C02 and C10 have real Gogs
// implementations. Listing either here would double-register its IDs and
// panic at init — this test states the intent so the panic, if it ever
// fires, is recognised as this rule rather than a mystery.
func TestNoOverlapWithTheRealGogsCollectors(t *testing.T) {
	for _, c := range checks {
		if strings.HasPrefix(c.id, "C02.") || strings.HasPrefix(c.id, "C10.") {
			t.Errorf("%s belongs to a collector with a real Gogs implementation and must not be listed here", c.id)
		}
	}
}

// TestRegisteredMetadataIsComplete: the generated checks reference is built
// from this metadata, so an empty rubric or remediation ships as a hole in
// customer-facing documentation. Endpoints must stay empty — an endpoint
// would claim a call that never happens.
func TestRegisteredMetadataIsComplete(t *testing.T) {
	for _, c := range checks {
		meta, ok := collect.LookupPlatform(platform, c.id)
		if !ok {
			t.Fatalf("%s is not registered for platform %q", c.id, platform)
		}
		if meta.Collector != c.collectorID {
			t.Errorf("%s Collector = %q, want %q", c.id, meta.Collector, c.collectorID)
		}
		if meta.Title == "" || meta.Remediation == "" {
			t.Errorf("%s has an empty Title or Remediation", c.id)
		}
		if len(meta.Rubric) != 1 {
			t.Errorf("%s registers %d rubric entries, want exactly one (not-checkable is its only possible status)", c.id, len(meta.Rubric))
		}
		if _, ok := meta.Rubric[model.StatusNotCheckable]; !ok {
			t.Errorf("%s has no rubric for not-checkable, its only possible status", c.id)
		}
		if len(meta.Endpoints) != 0 {
			t.Errorf("%s registers endpoints, but no API call backs it", c.id)
		}
	}
}

// TestCollectorsAreGroupedByCollectorID: ID() drives the --check filter and
// the per-collector progress output, so one catch-all collector claiming to
// be C01 through C09 at once would break both.
func TestCollectorsAreGroupedByCollectorID(t *testing.T) {
	got := map[string]bool{}
	for _, c := range Collectors() {
		if got[c.ID()] {
			t.Errorf("collector ID %q returned twice", c.ID())
		}
		got[c.ID()] = true
	}
	want := map[string]bool{}
	for _, c := range checks {
		want[c.collectorID] = true
	}
	if len(got) != len(want) {
		t.Errorf("got %d collectors, want %d (one per distinct collector ID)", len(got), len(want))
	}
	for id := range want {
		if !got[id] {
			t.Errorf("no collector returned for %q", id)
		}
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10)
// once, across all eight collectorID groups this package backs, since one
// implementation stands behind them: everything here is always not-checkable
// by design (TestNothingIsEverVerifiedFail), so there is exactly one status
// per check and the matrix that proves it is not the interesting part.
//
// What the guard buys, forward-looking exactly as it did for repoprotection:
// the day one of these checks starts observing something real — Gogs grows an
// audit-log endpoint, say — it must fail here first, because its rubric will
// still say "always" until a person updates it to match. That is the same
// drift class that has now shipped three times without a mechanical guard.
//
// Two scopes, matching the two states this file's other tests already use:
// a normal org+repo scope, and an org-only scope with no repos (which must
// still emit the org-scoped checks — TestOrgScopedChecksSurviveAnEmptyRepoList
// already pins that; this adds "and every one of those results is documented").
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	byCollector := map[string][]model.CheckResult{}
	for _, scope := range []collect.Scope{
		{Org: "acme", Repos: []string{"alpha"}},
		{Org: "acme"},
	} {
		for _, c := range Collectors() {
			got, err := c.Collect(context.Background(), scope)
			if err != nil {
				t.Fatalf("%s.Collect: %v", c.ID(), err)
			}
			byCollector[c.ID()] = append(byCollector[c.ID()], got...)
		}
	}
	if len(byCollector) != len(Collectors()) {
		t.Fatalf("collected results for %d collector groups, want %d", len(byCollector), len(Collectors()))
	}
	for id, results := range byCollector {
		collecttest.AssertRubricsMatchObservedBehaviour(t, platform, id, results)
	}
}
