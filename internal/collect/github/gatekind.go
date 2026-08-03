package github

import (
	"fmt"
	"strconv"
	"strings"
)

// GateKind classifies why a gated response (IsPlanGated's 402/404) actually
// happened, so a collector can produce an accurate Reason instead of
// unconditionally saying "plan" — true only on github.com. GHES has no
// per-org plan tier at all: a gated response there means either the
// install isn't licensed for the feature (GitHub Advanced Security, an
// Enterprise-only add-on) or the installed GHES version predates the
// endpoint (issue #12's GHES epic — "IsPlanGated already treats both codes
// as gated, but the resulting Reason string would say 'plan' where the
// truth is 'not licensed' or 'not present in this GHES version'").
type GateKind int

const (
	// GateKindNone means statusCode wasn't a gated response at all
	// (IsPlanGated(statusCode) == false).
	GateKindNone GateKind = iota
	// GateKindPlan is github.com's own plan-tier gating — ClassifyGate's
	// behavior before this epic, unchanged for a non-GHES target.
	GateKindPlan
	// GateKindLicence means the target is a GHES install and no known
	// minimum-version fact says the endpoint is version-gated instead —
	// GitHub Advanced Security (or an equivalent add-on) not being
	// licensed on this install is the most likely explanation, but see
	// ClassifyGate's doc comment for the residual ambiguity this shares
	// with GateKindVersion until issue #13's per-endpoint audit supplies
	// real minimum-version data for more checks.
	GateKindLicence
	// GateKindVersion means the target is a GHES install whose detected
	// version is below a known minGHESVersion, so the endpoint is
	// confirmed absent from this release rather than merely unlicensed.
	GateKindVersion
)

// ClassifyGate decides which GateKind a gated (IsPlanGated) statusCode
// represents. installedGHESVersion is "" for a github.com target, or a
// GHES target whose version this Client hasn't observed yet (see
// Client.GHESVersion) — both cases fall back to GateKindPlan/GateKindLicence
// respectively based on whether installedGHESVersion is empty, since an
// unknown version can't be compared against minGHESVersion.
// minGHESVersion is "" when no known minimum version exists yet for this
// endpoint (every check defaults here until issue #13's per-collector
// audit fills a real one in for it).
//
// Only a genuinely known minGHESVersion greater than installedGHESVersion
// produces GateKindVersion; every other GHES case is GateKindLicence. This
// is a deliberate, honest simplification: absent real per-endpoint
// minimum-version data, this tool cannot actually tell "not licensed" and
// "too old to have this endpoint" apart from the response alone — GitHub
// returns the same 402/404 either way. See docs/checks-reference.md's
// per-check GHES notes (issue #13) for which checks have real minimum-
// version data and which are still using this fallback.
func ClassifyGate(statusCode int, installedGHESVersion, minGHESVersion string) GateKind {
	if !IsPlanGated(statusCode) {
		return GateKindNone
	}
	if installedGHESVersion == "" {
		return GateKindPlan
	}
	if minGHESVersion != "" && versionLess(installedGHESVersion, minGHESVersion) {
		return GateKindVersion
	}
	return GateKindLicence
}

// GateReason renders kind into a collector-facing Reason string naming
// feature (e.g. "the organization audit log"), for a natural-reading
// sentence a not-checkable CheckResult can use directly.
// installedGHESVersion/minGHESVersion are only consulted for
// GateKindVersion's message; pass "" for either when kind can't be
// GateKindVersion (ClassifyGate's own return already guarantees that).
func GateReason(kind GateKind, feature, installedGHESVersion, minGHESVersion string) string {
	switch kind {
	case GateKindLicence:
		return fmt.Sprintf("%s is not available on this GitHub Enterprise Server install — most likely not "+
			"licensed (e.g. GitHub Advanced Security), though a version limitation can't be fully ruled out "+
			"from the response alone", feature)
	case GateKindVersion:
		return fmt.Sprintf("%s requires GitHub Enterprise Server %s or later (this install reports %s)",
			feature, minGHESVersion, installedGHESVersion)
	case GateKindPlan:
		return fmt.Sprintf("%s is not available on this org's plan", feature)
	default:
		return fmt.Sprintf("%s: not gated", feature)
	}
}

// versionLess reports whether a < b, comparing GHES version strings
// ("3.9.0", "3.12.4") numerically component by component rather than
// lexicographically (lexicographic string comparison would wrongly rank
// "3.9.0" above "3.12.0"). A component that fails to parse as a number is
// treated as 0, so an unexpected version string degrades to "equal" at
// that component rather than panicking or erroring — callers only need an
// ordering, not full semver validation.
func versionLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var av, bv int
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			return av < bv
		}
	}
	return false
}
