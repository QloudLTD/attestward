package unsupported

import (
	"context"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
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

// guardedCollectorIDs are the collector groups whose ENTIRE check set lives in
// this table, and so can be guarded from here. The other two groups this
// package backs are deliberately absent:
//
//   - C04.secrets-hygiene: five of its six IDs are here; the sixth,
//     C04.vars.secret-masking, is a real check in internal/collect/gitlab/
//     secretshygiene with its own guard call. Guarding it from here would
//     PASS, and that is exactly the problem — the registry is populated by
//     package init, and this test binary does not import secretshygiene, so
//     collect.Registered() offers the guard only the five IDs it can already
//     see. It would report full coverage of a collector while five sixths of
//     it was all it ever looked at.
//   - C08.actions-security: a real GitLab CI collector for it is being built,
//     which will move these five IDs out of this table. Guarding the
//     placeholder now would only have to be unwound.
var guardedCollectorIDs = map[string]bool{
	"C05.sast-history": true,
	"C06.sca-history":  true,
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10)
// for the two collector groups above.
//
// One state is the whole matrix here, and that is not a thin one: every check
// in this table is not-checkable unconditionally, with no branch that could
// produce anything else (TestNothingReportsPassOrFail pins that separately),
// so a single collection reaches every status these checks can emit.
//
// What it buys is forward-looking, the same thing it bought the Gogs table:
// the day GitLab SAST or Dependency Scanning findings become readable and one
// of these IDs starts observing something real, this fails first — because its
// rubric will still document not-checkable and nothing else until a person
// updates it.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	scope := collect.Scope{Org: "group", Repos: []string{"proj"}}

	byCollector := map[string][]model.CheckResult{}
	for _, c := range Collectors() {
		if !guardedCollectorIDs[c.ID()] {
			continue
		}
		got, err := c.Collect(context.Background(), scope)
		if err != nil {
			t.Fatalf("%s: Collect: %v", c.ID(), err)
		}
		byCollector[c.ID()] = append(byCollector[c.ID()], got...)
	}
	// Without this a renamed collector ID would silently guard nothing, and the
	// emptiness would read as success.
	if len(byCollector) != len(guardedCollectorIDs) {
		t.Fatalf("collected results for %d collector groups, want %d — a guarded ID no longer resolves to a collector",
			len(byCollector), len(guardedCollectorIDs))
	}

	for id, results := range byCollector {
		// Pinned explicitly rather than counted: a status assertion that only
		// counts rows passes just as happily when the wrong check emitted them.
		for _, r := range results {
			if r.Status != model.StatusNotCheckable {
				t.Errorf("%s/%s status = %q, want not-checkable — the matrix below assumes it is the only "+
					"status these checks reach", id, r.CheckID, r.Status)
			}
		}
		collecttest.AssertRubricsMatchObservedBehaviour(t, platform, id, results)
	}
}
