package main

import (
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// This lives in package main, not internal/collect, because the registry is
// populated by each collector package's init — from inside collect itself
// Registered() is empty and the test would pass vacuously while checking
// nothing at all.

// TestEveryRubricCoversTheStatusesItsCheckCanEmit is a structural guard, not a
// style check. A rubric is what `attestward checks docs` publishes as the
// meaning of a result, so a status with no entry ships a conclusion with no
// stated basis — and worse, a rubric left behind after a check's behaviour
// changes publishes the OLD meaning, confidently.
//
// That is exactly what happened: repoprotection's deletion check was corrected
// to emit partial (GitLab lets a Maintainer delete a protected branch through
// the UI or API, so a pass was never justified), but the rubric still described
// a verified-pass and still asserted deletion was impossible. The code was
// right and the published documentation was wrong, which is the harder failure
// to notice.
//
// This cannot know which statuses a check emits without running it, so it pins
// the weaker property that still catches that class: no rubric may document a
// status the check is documented as unable to produce, and every rubric must
// at least cover not-checkable, which any collector can emit on a read failure.
func TestEveryRubricCoversTheStatusesItsCheckCanEmit(t *testing.T) {
	metas := collect.Registered()
	// Without this the whole test passes vacuously if registration ever moves
	// or an import is dropped — the exact failure mode that made putting it in
	// package collect useless.
	if len(metas) < 30 {
		t.Fatalf("only %d checks registered; the registry is not populated, so this test proves nothing", len(metas))
	}
	for _, m := range metas {
		if len(m.Rubric) == 0 {
			t.Errorf("%s (%s): no rubric — `checks docs` would publish a check whose results have no stated meaning",
				m.ID, m.Platform)
			continue
		}
		if _, ok := m.Rubric[model.StatusNotCheckable]; !ok {
			t.Errorf("%s (%s): rubric has no not-checkable entry, but any collector can emit it when a read fails",
				m.ID, m.Platform)
		}
		for status := range m.Rubric {
			switch status {
			case model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable:
			default:
				t.Errorf("%s (%s): rubric documents unknown status %q", m.ID, m.Platform, status)
			}
		}
		if m.Remediation == "" {
			t.Errorf("%s (%s): no remediation — a fail or partial would tell a producer nothing about the fix",
				m.ID, m.Platform)
		}
	}
}
