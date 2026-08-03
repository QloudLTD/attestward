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
// produces GateKindVersion; every other GHES case is GateKindLicence.
//
// As of this writing NO check supplies a minGHESVersion — both call sites
// pass "" — so GateKindVersion is unreachable in practice. That is
// deliberate rather than unfinished: inventing a minimum version this
// project has not verified would be exactly the fabricated claim the rest
// of this file exists to prevent. The branch stays because supplying real
// per-endpoint data is a data change, not a code change. This
// is a deliberate, honest simplification: absent real per-endpoint
// minimum-version data, this tool cannot actually tell "not licensed" and
// "too old to have this endpoint" apart from the response alone — GitHub
// returns the same 402/404 either way. See docs/checks-reference.md's
// per-check GHES notes (issue #13) for which checks have real minimum-
// version data and which are still using this fallback.
func ClassifyGate(statusCode int, isGHES bool, installedGHESVersion, minGHESVersion string) GateKind {
	if !IsPlanGated(statusCode) {
		return GateKindNone
	}
	// Keyed on the configured target, NOT on whether a version was
	// observed. Keying on the version meant a GHES scan whose version
	// header never arrived — stripped by a proxy, or missing from a
	// front-end error — reported the github.com reason, so a single signed
	// pack could assert "the org's plan doesn't include GitHub Enterprise
	// Cloud's audit-log API" while its own scope.github_url named a
	// self-hosted install with no plan tier at all. The target is known at
	// preflight; the version is a bonus.
	if !isGHES {
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
		// Deliberately names no cause. The code established exactly one
		// fact — a 402/404 came back — and GitHub returns the same status
		// for a licensing gap, a version that predates the endpoint, and a
		// token without the required scope. An earlier version of this
		// string said "most likely not licensed (e.g. GitHub Advanced
		// Security)", which was a fabricated causal claim: it is simply
		// untrue for the organization audit log, which has no Advanced
		// Security dependency, and it dropped the token-scope alternative
		// that the github.com reason is careful to keep. Listing the
		// possibilities without ranking them is what the response actually
		// supports.
		if installedGHESVersion != "" {
			return fmt.Sprintf("%s is not available on this GitHub Enterprise Server install (reporting version %s). "+
				"The response cannot distinguish between a feature that is not licensed, one this version does not "+
				"have, and a token without the required scope — GitHub returns the same status for all three",
				feature, installedGHESVersion)
		}
		return fmt.Sprintf("%s is not available on this GitHub Enterprise Server install. The response cannot "+
			"distinguish between a feature that is not licensed, one this version does not have, and a token "+
			"without the required scope — GitHub returns the same status for all three. This install did not "+
			"report its version, so the version possibility could not be narrowed further", feature)
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
