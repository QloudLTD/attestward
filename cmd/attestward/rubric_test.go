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

// TestEveryCheckDocumentsItsResults is a cross-platform floor, not a proof.
//
// A rubric is what `attestward checks docs` publishes as the meaning of each
// result, so a check with none ships conclusions with no stated basis. This
// covers every registered check on every platform, but only weakly: it cannot
// know which statuses a check emits without running it, so it asserts presence
// and enum-validity, not agreement with behaviour.
//
// The strong version of this — rubric keys must equal the statuses the
// collector actually produces — needs the package's own fixtures, so it lives
// per-package. See TestRubricsMatchWhatTheCollectorCanActuallyEmit in
// internal/collect/gitlab/repoprotection, which is what caught the stale
// rubrics this floor passes straight over.
func TestEveryCheckDocumentsItsResults(t *testing.T) {
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
