package unsupported

import (
	"context"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// TestNothingReportsPassOrFail is the invariant that makes this package safe.
//
// Every entry here describes a control this build did not look at. Reporting
// verified-pass would fabricate evidence; reporting verified-fail would
// assert a control was looked for and found absent, which is equally untrue
// and actively harmful — it tells a producer to fix something that may be
// perfectly configured, inside a document they are about to sign.
func TestNothingReportsPassOrFail(t *testing.T) {
	scope := collect.Scope{Org: "group", Repos: []string{"proj"}}
	for _, c := range Collectors() {
		results, err := c.Collect(context.Background(), scope)
		if err != nil {
			t.Fatalf("%s: Collect: %v", c.ID(), err)
		}
		if len(results) == 0 {
			t.Errorf("%s produced no results; a missing row reads as a clean one", c.ID())
		}
		for _, r := range results {
			if r.Status != model.StatusNotCheckable {
				t.Errorf("%s/%s status = %q, want not-checkable", c.ID(), r.CheckID, r.Status)
			}
			if r.Reason == "" {
				t.Errorf("%s/%s has no reason; not-checkable without a reason is indistinguishable from a bug", c.ID(), r.CheckID)
			}
			if len(r.Provenance) != 0 {
				t.Errorf("%s/%s carries provenance, but no API call was made — that would claim the tool asked a question it never asked", c.ID(), r.CheckID)
			}
			if r.Scope.Platform != platform {
				t.Errorf("%s/%s platform = %q, want %q", c.ID(), r.CheckID, r.Scope.Platform, platform)
			}
		}
	}
}

// TestRepoScopedChecksEmitOncePerProject pins that a GitLab pack has the same
// shape as a GitHub one, so the two can be compared row for row.
func TestRepoScopedChecksEmitOncePerProject(t *testing.T) {
	one := collect.Scope{Org: "g", Repos: []string{"a"}}
	two := collect.Scope{Org: "g", Repos: []string{"a", "b"}}

	count := func(sc collect.Scope) int {
		n := 0
		for _, c := range Collectors() {
			res, err := c.Collect(context.Background(), sc)
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			n += len(res)
		}
		return n
	}
	got1, got2 := count(one), count(two)
	repoScoped := 0
	for _, c := range checks {
		if c.scope == repoScoped2() {
			repoScoped++
		}
	}
	if got2-got1 != repoScoped {
		t.Errorf("adding a project added %d results, want %d (one per repo-scoped check)", got2-got1, repoScoped)
	}
}

func repoScoped2() scope { return repoScoped }

// TestEveryCheckIsRegistered pins that the table and the registry agree, so a
// check cannot be silently dropped from a scan while still appearing in docs.
func TestEveryCheckIsRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, m := range collect.Registered() {
		if m.Platform == platform {
			registered[m.ID] = true
		}
	}
	for _, c := range checks {
		if !registered[c.id] {
			t.Errorf("%s is in the table but not registered for %s", c.id, platform)
		}
	}
}

// The rubric guard is deliberately NOT wired from this package any more.
//
// It used to cover C05.sast-history and C06.sca-history, the two groups whose
// entire check set lived in this table. Both moved out wholesale (to
// internal/collect/gitlab/{sasthistory,scahistory}), and their guard moved
// with them — to a real state matrix, which is strictly better than the
// single always-not-checkable state this package could offer.
//
// What is left in the table is five of C04.secrets-hygiene's six IDs, and
// that group cannot be guarded from here for the reason it never could: the
// sixth, C04.vars.secret-masking, is a real check in
// internal/collect/gitlab/secretshygiene, and this test binary does not
// import that package. collect.Registered() would therefore offer the guard
// only the five IDs it can already see, and it would report full coverage of
// a collector while five sixths of it was all it ever looked at — a guard
// that passes while proving nothing. cmd/attestward's own
// rubricguard_coverage_test.go records the same boundary as a baseline entry.
//
// TestNothingReportsPassOrFail below is what still holds this table honest:
// every entry here is not-checkable unconditionally, and nothing may quietly
// start reporting a verdict.
