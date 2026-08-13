package main

import (
	"fmt"
	"sort"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
)

// rubricGuardUnwired lists the collectors that do NOT yet call
// collecttest.AssertRubricsMatchObservedBehaviour. Tracked in issue #10; the
// number is here rather than a bare "see the follow-up issue" so the pointer
// cannot dangle.
//
// This exists because a partially-applied guard is only dangerous when its
// boundary is invisible. Enumerated here, "not yet guarded" is a fact in the
// repository that a reviewer can see, rather than something a reader has to
// infer from which test files happen to exist.
//
// # This list may only shrink
//
// A new collector must either wire the guard or add itself here, deliberately,
// in a diff someone reviews. It cannot quietly arrive unguarded — that is the
// whole point, and it is why this is a baseline rather than a comment.
//
// Wiring is not mechanical: each needs a state matrix that actually reaches
// every status its checks emit, and a thin matrix makes the guard report
// documented-but-unreachable rubrics that are really just uncovered. Rushing
// them would trade real drift detection for noise and exemption sprawl.
var rubricGuardUnwired = map[string]bool{
	"azuredevops/C05.sast-history":     true,
	"azuredevops/C06.sca-history":      true,
	"azuredevops/C07.provenance":       true,
	"azuredevops/C08.actions-security": true,
	"github/C02.repo-protection":       true,
	"github/C06.sca-history":           true,
	"github/C07.provenance":            true,
	"github/C08.actions-security":      true,
	// gitlab/C04.secrets-hygiene: NOT the same shape as every other entry
	// here. This key covers 6 check IDs, not one collector: 5 permanently
	// not-checkable in internal/collect/gitlab/unsupported (they depend on
	// GitLab's paid-tier Secret Detection/Dependency Scanning) plus
	// C04.vars.secret-masking, a real check in internal/collect/gitlab/
	// secretshygiene whose OWN tests DO call the guard. Since this baseline
	// is per-(platform,Collector) — see registered's construction in
	// TestRubricGuardCoverageOnlyShrinks — one real check's guard coverage
	// can't move the whole key to wired while 5 of 6 IDs under it stay
	// unguarded. Unlike every other unwired entry, this one cannot shrink
	// to zero by more guard-wiring alone: the 5 not-checkable IDs would
	// need to actually gain real behaviour (paid-tier collection) before
	// there is anything more here to guard.
	"gitlab/C04.secrets-hygiene": true,
}

// TestRubricGuardCoverageOnlyShrinks fails when a registered collector is
// neither guarded nor listed above.
//
// It cannot tell whether a collector's test calls the assertion — that would
// need source analysis — so it checks the weaker property that still closes the
// hole: every registered collector must be accounted for, one way or the other.
// A new one arriving silently unguarded is the case this makes impossible.
//
// ⚠ Stated so nobody assumes more: deleting the assertion from a package listed
// in rubricGuardWired keeps this green, because this test consults only the two
// maps below and the registry. It proves accounting, not enforcement.
func TestRubricGuardCoverageOnlyShrinks(t *testing.T) {
	registered := map[string]bool{}
	for _, m := range collect.Registered() {
		registered[fmt.Sprintf("%s/%s", m.Platform, m.Collector)] = true
	}
	if len(registered) == 0 {
		t.Fatal("no collectors registered; this test would prove nothing")
	}

	var unaccounted []string
	for key := range registered {
		if !rubricGuardUnwired[key] && !rubricGuardWired[key] {
			unaccounted = append(unaccounted, key)
		}
	}
	sort.Strings(unaccounted)
	for _, key := range unaccounted {
		t.Errorf("collector %s is neither in rubricGuardWired nor rubricGuardUnwired. Wire "+
			"collecttest.AssertRubricsMatchObservedBehaviour into its package test, or add it to the unwired "+
			"baseline deliberately — a collector must not arrive unguarded by omission.", key)
	}

	// A key in BOTH maps passed silently, which matters because moving entries
	// between them is the unit of progress on #10 and will happen ~37 more
	// times. A copy-without-delete would leave a collector listed as wired and
	// as outstanding at once — reading as done on one line and as to-do on
	// another, with the test endorsing both.
	var doubled []string
	for key := range rubricGuardWired {
		if rubricGuardUnwired[key] {
			doubled = append(doubled, key)
		}
	}
	sort.Strings(doubled)
	for _, key := range doubled {
		t.Errorf("%s is in BOTH rubricGuardWired and rubricGuardUnwired; when wiring a collector, move the entry "+
			"rather than copying it", key)
	}

	// A stale baseline is its own failure: an entry for a collector that no
	// longer registers reads as tracked work that does not exist.
	var stale []string
	for key := range rubricGuardUnwired {
		if !registered[key] {
			stale = append(stale, key)
		}
	}
	for key := range rubricGuardWired {
		if !registered[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("%s is listed in a rubric-guard baseline but no longer registers; remove it", key)
	}
}

// rubricGuardWired is the shrinking half: collectors whose package tests call
// the assertion. Moving an entry here is the unit of progress on the follow-up.
var rubricGuardWired = map[string]bool{
	"gitlab/C07.provenance":      true,
	"github/C10.vdp":             true,
	"gogs/C10.vdp":               true,
	"gitlab/C03.env-separation":  true,
	"gitlab/C10.vdp":             true,
	"gogs/C01.org-security":      true,
	"gogs/C03.env-separation":    true,
	"gogs/C04.secrets-hygiene":   true,
	"gogs/C05.sast-history":      true,
	"gogs/C06.sca-history":       true,
	"gogs/C07.provenance":        true,
	"gogs/C08.actions-security":  true,
	"gogs/C09.audit-logging":     true,
	"gitlab/C09.audit-logging":   true,
	"gogs/C02.repo-protection":   true,
	"gitlab/C02.repo-protection": true,
	"github/C01.org-security":    true,
	"github/C05.sast-history":    true,
	// gitlab/C05.sast-history and gitlab/C06.sca-history stay wired, but
	// what backs them changed: they used to be guarded by the trivial
	// always-not-checkable matrix in internal/collect/gitlab/unsupported,
	// and are now guarded by internal/collect/gitlab/{sasthistory,
	// scahistory}, whose own tests call the assertion over an eight- and
	// ten-state matrix. Nothing was left behind in gitlab/unsupported for
	// either — every one of the nine IDs moved — so, unlike
	// gitlab/C04.secrets-hygiene below, neither is a split collector
	// claiming coverage from the half that has tests.
	"gitlab/C05.sast-history":         true,
	"gitlab/C06.sca-history":          true,
	"azuredevops/C04.secrets-hygiene": true,
	"gitlab/C01.org-security":         true,
	"github/C04.secrets-hygiene":      true,
	"github/C09.audit-logging":        true,
	"azuredevops/C01.org-security":    true,
	"azuredevops/C10.vdp":             true,
	"github/C03.env-separation":       true,
	"azuredevops/C09.audit-logging":   true,
	"azuredevops/C03.env-separation":  true,
	"azuredevops/C02.repo-protection": true,
	// gitlab/C08.actions-security is here rather than in the unwired
	// baseline because all five of its check IDs live in ONE package
	// (internal/collect/gitlab/actionssecurity) whose own test calls the
	// assertion over a six-state matrix — nothing was left behind in
	// gitlab/unsupported. Contrast gitlab/C04.secrets-hygiene above,
	// which cannot move while 5 of its 6 IDs stay split across two
	// packages: a split collector cannot claim guard coverage from the
	// half that has tests.
	"gitlab/C08.actions-security": true,
}
