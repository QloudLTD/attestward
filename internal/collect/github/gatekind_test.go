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
	if got := ClassifyGate(http.StatusForbidden, "", ""); got != GateKindNone {
		t.Errorf("ClassifyGate(403, ...) = %v, want GateKindNone", got)
	}
	if got := ClassifyGate(http.StatusForbidden, "3.9.0", ""); got != GateKindNone {
		t.Errorf("ClassifyGate(403, ghes, ...) = %v, want GateKindNone", got)
	}
}

// TestClassifyGate_GitHubComIsAlwaysPlan proves today's github.com
// behavior is unchanged: an empty installedGHESVersion (the github.com
// case) always classifies a gated status as GateKindPlan, never licence
// or version.
func TestClassifyGate_GitHubComIsAlwaysPlan(t *testing.T) {
	for _, status := range []int{http.StatusPaymentRequired, http.StatusNotFound} {
		if got := ClassifyGate(status, "", ""); got != GateKindPlan {
			t.Errorf("ClassifyGate(%d, \"\", \"\") = %v, want GateKindPlan", status, got)
		}
	}
}

// TestClassifyGate_GHESWithoutMinVersionIsLicence proves a GHES target
// (non-empty installedGHESVersion) with no known minimum-version fact for
// the endpoint defaults to GateKindLicence, never the github.com-flavored
// GateKindPlan — issue #12's core fix.
func TestClassifyGate_GHESWithoutMinVersionIsLicence(t *testing.T) {
	if got := ClassifyGate(http.StatusNotFound, "3.9.0", ""); got != GateKindLicence {
		t.Errorf("ClassifyGate(404, \"3.9.0\", \"\") = %v, want GateKindLicence", got)
	}
}

// TestClassifyGate_GHESBelowMinVersionIsVersion proves a genuinely known
// minGHESVersion above the installed version produces GateKindVersion
// instead of GateKindLicence.
func TestClassifyGate_GHESBelowMinVersionIsVersion(t *testing.T) {
	if got := ClassifyGate(http.StatusNotFound, "3.8.0", "3.9.0"); got != GateKindVersion {
		t.Errorf("ClassifyGate(404, \"3.8.0\", \"3.9.0\") = %v, want GateKindVersion", got)
	}
}

// TestClassifyGate_GHESAtOrAboveMinVersionIsLicence proves the boundary:
// once the installed version reaches minGHESVersion, a gated response
// reverts to GateKindLicence (the endpoint should exist at this version,
// so a gate must mean unlicensed, not absent).
func TestClassifyGate_GHESAtOrAboveMinVersionIsLicence(t *testing.T) {
	if got := ClassifyGate(http.StatusNotFound, "3.9.0", "3.9.0"); got != GateKindLicence {
		t.Errorf("ClassifyGate(404, \"3.9.0\", \"3.9.0\") = %v, want GateKindLicence (at minimum version)", got)
	}
	if got := ClassifyGate(http.StatusNotFound, "3.12.0", "3.9.0"); got != GateKindLicence {
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
