// Package collecttest holds assertions shared by collector package tests.
//
// It exists for one reason: a defect class that recurred five times across two
// platform trees before anything mechanical caught it. A check's rubric is what
// `attestward checks docs` publishes as the meaning of each result, and nothing
// tied it to the code. So when a check's behaviour was corrected, its rubric
// kept confidently describing the old behaviour — the code was right and the
// published documentation was wrong, which is the harder direction to notice
// and the one a reader has no way to detect.
//
// The guard lived in one package for a while. That was enough to prove it
// works and not enough to stop the class: the two instances after it was
// written were both in packages it did not cover.
package collecttest

import (
	"sort"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// AssertRubricsMatchObservedBehaviour compares the statuses a collector
// actually emits against the statuses its registrations document, failing in
// both directions.
//
// observed must be the union of results from a state matrix broad enough to
// reach every status the collector can produce — typically the happy path, each
// failing-dependency path, and each partial. A thin matrix makes this report
// documented-but-unreachable statuses that are really just uncovered, which is
// a useful failure too: it says the matrix is thin.
//
// Both directions matter and they catch different mistakes:
//
//   - A rubric entry for a status the collector cannot produce is a false
//     promise. It is what `checks docs` prints, so a reader is told a result
//     can mean something it never means.
//   - A status with no entry ships a conclusion with no stated basis, and
//     nothing in the pack explains it.
//
// ⚠ Its limit, which is not fixable here and must not be forgotten: this
// compares which statuses are emitted, NOT whether their descriptions are true.
// A rubric whose wording rots while its status set stays valid — a pass that
// starts being reached by a second, undescribed route — passes this cleanly.
// Two of the five instances of the class were exactly that. Nothing mechanical
// catches description rot; it needs a person reading the rubric whenever a
// status's entry conditions change.
func AssertRubricsMatchObservedBehaviour(t *testing.T, platform, collectorID string, observed []model.CheckResult) {
	t.Helper()
	AssertRubricsMatchObservedBehaviourExcept(t, platform, collectorID, observed, nil)
}

// AssertRubricsMatchObservedBehaviourExcept is the same assertion with named
// exemptions, for checks whose statuses cannot be reached by a pure state
// matrix — typically ones needing a live client, whose statuses are covered by
// collector-level tests instead.
//
// coveredElsewhere maps a check ID to WHY it is exempt, and the reason is
// mandatory rather than decorative: an unexplained exemption list is how a
// check quietly stops being checked. Prefer extending the matrix; reach for
// this only when the status genuinely cannot be produced without I/O.
func AssertRubricsMatchObservedBehaviourExcept(t *testing.T, platform, collectorID string, observed []model.CheckResult, coveredElsewhere map[string]string) {
	t.Helper()
	for _, id := range sortedStringKeys(coveredElsewhere) {
		if coveredElsewhere[id] == "" {
			t.Errorf("%s is exempted from the rubric check with no reason given; an unexplained exemption is how "+
				"a check quietly stops being checked", id)
		}
	}

	seen := map[string]map[model.Status]bool{}
	for _, r := range observed {
		if seen[r.CheckID] == nil {
			seen[r.CheckID] = map[model.Status]bool{}
		}
		seen[r.CheckID][r.Status] = true
	}
	if len(seen) == 0 {
		t.Fatalf("no results observed for %s/%s; this assertion would prove nothing", platform, collectorID)
	}

	registered := map[string]collect.CheckMeta{}
	for _, m := range collect.Registered() {
		if m.Platform == platform && m.Collector == collectorID {
			registered[m.ID] = m
		}
	}
	// Without this the loops below go vacuous whenever a platform or collector
	// ID drifts: results are still collected, they just stop matching, and the
	// emptiness looks like success.
	if len(registered) == 0 {
		t.Fatalf("no checks registered for platform %q collector %q — the filter matches nothing, so this "+
			"assertion is inert; check the platform and collector IDs", platform, collectorID)
	}

	// An exemption for a check that no longer exists is worse than no exemption:
	// it reads as a considered decision while protecting nothing, and it
	// survives every rename and removal silently.
	for _, id := range sortedStringKeys(coveredElsewhere) {
		if _, ok := registered[id]; !ok {
			t.Errorf("%s is exempted but is not registered for %s/%s — the exemption is stale (the check was "+
				"renamed or removed) and should be deleted", id, platform, collectorID)
		}
	}

	for _, id := range sortedKeys(seen) {
		if _, ok := registered[id]; !ok {
			t.Errorf("%s is emitted but not registered for %s/%s, so it has no rubric, no remediation, and no "+
				"entry in `checks docs` at all", id, platform, collectorID)
		}
	}

	for _, id := range sortedMetaKeys(registered) {
		meta := registered[id]
		_, exempt := coveredElsewhere[id]
		emitted, ok := seen[id]
		if !ok {
			if exempt {
				// The whole point of the exemption: this check's statuses come
				// from elsewhere, so not reaching it here is expected.
				continue
			}
			t.Errorf("%s is registered but no state in the matrix emits it — either it is documented and "+
				"unreachable, or the matrix is missing the case that reaches it", id)
			continue
		}
		// Runs for exempted checks too. An exemption says "the matrix cannot
		// REACH all of this check's statuses"; it says nothing about the
		// statuses the matrix does reach, and validating those costs nothing.
		// Skipping them let an exempted check emit an undocumented status
		// unnoticed — an exemption quietly disabling more than it justified.
		for _, status := range sortedStatuses(emitted) {
			if _, documented := meta.Rubric[status]; !documented {
				t.Errorf("%s emits %q but its rubric does not document it — a reader gets a result with no "+
					"stated meaning", id, status)
			}
		}
		if exempt {
			continue
		}
		for _, status := range sortedStatuses(toSet(meta.Rubric)) {
			if !emitted[status] {
				t.Errorf("%s documents %q in its rubric, but no state in the matrix produces it. Either the "+
					"rubric describes behaviour the code no longer has — which is what `checks docs` would then "+
					"publish — or the matrix is missing a case worth covering.", id, status)
			}
		}
	}
}

func toSet(rubric map[model.Status]string) map[model.Status]bool {
	out := make(map[model.Status]bool, len(rubric))
	for k := range rubric {
		out[k] = true
	}
	return out
}

// The three sorted* helpers exist so failures are deterministic. Map iteration
// order would otherwise reorder the errors between runs, which makes a diff
// between two CI logs unreadable.
func sortedKeys(m map[string]map[model.Status]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedMetaKeys(m map[string]collect.CheckMeta) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStatuses(m map[model.Status]bool) []model.Status {
	out := make([]model.Status, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
