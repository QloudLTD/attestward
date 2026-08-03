package github

import (
	"net/http"
	"strings"
	"testing"
)

// TestClassifyGate_NonGatedStatusIsNone proves a plain success/failure
// status (not one of IsPlanGated's two codes) never produces a gate at
// all, regardless of host.
func TestClassifyGate_NonGatedStatusIsNone(t *testing.T) {
	if got := ClassifyGate(http.StatusForbidden, false, "", ""); got != GateKindNone {
		t.Errorf("ClassifyGate(403, ...) = %v, want GateKindNone", got)
	}
	if got := ClassifyGate(http.StatusForbidden, true, "3.9.0", ""); got != GateKindNone {
		t.Errorf("ClassifyGate(403, ghes, ...) = %v, want GateKindNone", got)
	}
}

// TestClassifyGate_GitHubComIsAlwaysPlan proves today's github.com
// behavior is unchanged: a non-GHES target always classifies a gated
// status as GateKindPlan, never licence or version.
func TestClassifyGate_GitHubComIsAlwaysPlan(t *testing.T) {
	for _, status := range []int{http.StatusPaymentRequired, http.StatusNotFound} {
		if got := ClassifyGate(status, false, "", ""); got != GateKindPlan {
			t.Errorf("ClassifyGate(%d, \"\", \"\") = %v, want GateKindPlan", status, got)
		}
	}
}

// TestClassifyGate_GHESWithoutMinVersionIsLicence proves a GHES target with
// no known minimum-version fact for the endpoint defaults to
// GateKindLicence, never the github.com-flavored GateKindPlan — the epic's
// core fix.
func TestClassifyGate_GHESWithoutMinVersionIsLicence(t *testing.T) {
	if got := ClassifyGate(http.StatusNotFound, true, "3.9.0", ""); got != GateKindLicence {
		t.Errorf("ClassifyGate(404, \"3.9.0\", \"\") = %v, want GateKindLicence", got)
	}
}

// TestClassifyGate_GHESBelowMinVersionIsVersion proves a genuinely known
// minGHESVersion above the installed version produces GateKindVersion
// instead of GateKindLicence.
func TestClassifyGate_GHESBelowMinVersionIsVersion(t *testing.T) {
	if got := ClassifyGate(http.StatusNotFound, true, "3.8.0", "3.9.0"); got != GateKindVersion {
		t.Errorf("ClassifyGate(404, \"3.8.0\", \"3.9.0\") = %v, want GateKindVersion", got)
	}
}

// TestClassifyGate_GHESAtOrAboveMinVersionIsLicence proves the boundary:
// once the installed version reaches minGHESVersion, a gated response
// reverts to GateKindLicence (the endpoint should exist at this version,
// so a gate must mean unlicensed, not absent).
func TestClassifyGate_GHESAtOrAboveMinVersionIsLicence(t *testing.T) {
	if got := ClassifyGate(http.StatusNotFound, true, "3.9.0", "3.9.0"); got != GateKindLicence {
		t.Errorf("ClassifyGate(404, \"3.9.0\", \"3.9.0\") = %v, want GateKindLicence (at minimum version)", got)
	}
	if got := ClassifyGate(http.StatusNotFound, true, "3.12.0", "3.9.0"); got != GateKindLicence {
		t.Errorf("ClassifyGate(404, \"3.12.0\", \"3.9.0\") = %v, want GateKindLicence (above minimum version)", got)
	}
}

// TestGateReason_ProducesDistinctReasonPerKind is issue #12's explicit
// acceptance criterion: each GateKind must render a DIFFERENT and accurate
// Reason string — in particular, GateKindLicence/GateKindVersion must
// never say "plan" (github.com's own concept, wrong on GHES), and
// GateKindPlan must never mention GitHub Enterprise Server.
func TestGateReason_ProducesDistinctReasonPerKind(t *testing.T) {
	feature := "the organization audit log"

	plan := GateReason(GateKindPlan, feature, "", "")
	licence := GateReason(GateKindLicence, feature, "3.9.0", "")
	version := GateReason(GateKindVersion, feature, "3.8.0", "3.9.0")

	if plan == licence || plan == version || licence == version {
		t.Fatalf("expected three distinct reasons, got:\nplan=%q\nlicence=%q\nversion=%q", plan, licence, version)
	}

	if !strings.Contains(plan, "plan") {
		t.Errorf("plan reason = %q, want it to mention \"plan\"", plan)
	}
	if strings.Contains(plan, "Enterprise Server") {
		t.Errorf("plan reason = %q, want no mention of GitHub Enterprise Server", plan)
	}

	if strings.Contains(licence, "plan") {
		t.Errorf("licence reason = %q, want no mention of \"plan\"", licence)
	}
	if !strings.Contains(licence, "Enterprise Server") {
		t.Errorf("licence reason = %q, want it to mention GitHub Enterprise Server", licence)
	}

	if strings.Contains(version, "plan") {
		t.Errorf("version reason = %q, want no mention of \"plan\"", version)
	}
	if !strings.Contains(version, "3.9.0") || !strings.Contains(version, "3.8.0") {
		t.Errorf("version reason = %q, want both the required (3.9.0) and installed (3.8.0) versions named", version)
	}
}

// TestVersionLess covers versionLess's numeric-not-lexicographic
// comparison (3.9.0 < 3.12.0, which a plain string comparison gets wrong)
// and its malformed-input fallback.
func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"3.9.0", "3.12.0", true},
		{"3.12.0", "3.9.0", false},
		{"3.9.0", "3.9.0", false},
		{"3.9.1", "3.9.0", false},
		{"3.9.0", "3.9.1", true},
		{"3", "3.1", true},
		{"bogus", "3.9.0", true}, // malformed component parses as 0, which is genuinely < 3
	}
	for _, tc := range cases {
		if got := versionLess(tc.a, tc.b); got != tc.want {
			t.Errorf("versionLess(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestClassifyGate_GHESWithNoVersionObservedIsStillGHES is the regression
// test for the defect that keying on the observed version rather than the
// configured target produced: a GHES install whose version header never
// arrived — stripped by a proxy, or absent from a load-balancer error that
// happened to be the first response — was classified as github.com, so a
// signed pack could assert that "the org's plan doesn't include GitHub
// Enterprise Cloud's audit-log API" while its own scope.github_url named a
// self-hosted install with no plan tier at all.
func TestClassifyGate_GHESWithNoVersionObservedIsStillGHES(t *testing.T) {
	if got := ClassifyGate(http.StatusNotFound, true, "", ""); got != GateKindLicence {
		t.Errorf("ClassifyGate(404, isGHES=true, no version) = %v, want GateKindLicence", got)
	}
	reason := GateReason(GateKindLicence, "the organization audit log", "", "")
	if strings.Contains(reason, "plan") {
		t.Errorf("reason mentions a plan tier on a GHES install: %q", reason)
	}
	if !strings.Contains(reason, "did not report its version") {
		t.Errorf("reason does not say the version was unknown: %q", reason)
	}
}

// TestGateReason_LicenceNamesNoCause pins what the licence reason is
// allowed to claim. It previously said "most likely not licensed (e.g.
// GitHub Advanced Security)" — a fabricated causal claim, untrue for the
// organization audit log (which has no Advanced Security dependency), and
// it dropped the token-scope alternative that the github.com reason is
// careful to keep. The response establishes exactly one fact: a gated
// status came back.
func TestGateReason_LicenceNamesNoCause(t *testing.T) {
	reason := GateReason(GateKindLicence, "the organization audit log", "3.12.4", "")
	if strings.Contains(reason, "Advanced Security") {
		t.Errorf("reason names a cause the response never established: %q", reason)
	}
	for _, want := range []string{"not licensed", "does not have", "scope"} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason omits the %q possibility, so it ranks causes the response cannot distinguish: %q", want, reason)
		}
	}
	if !strings.Contains(reason, "3.12.4") {
		t.Errorf("reason drops the observed version, which is the one real fact available: %q", reason)
	}
}
