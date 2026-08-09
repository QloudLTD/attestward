package vdp

import (
	"regexp"
	"strings"
)

// The two independent signals that count as an actionable intake channel
// on Gogs — the same subset the Azure DevOps twin uses, and for the same
// reason: internal/collect/github/vdp/heuristics.go has a third,
// githubReportingPattern, that matches a GitHub-specific feature and URL
// path ("private vulnerability reporting", "security/advisories") this
// platform has no equivalent of at all (see C10.vdp.private-reporting,
// always not-checkable here for exactly that reason). Porting it would let
// a SECURITY.md pass this check by advertising a feature the instance
// cannot offer.
//
// Duplicated rather than imported from either sibling package: ADR-0005
// keeps platform packages as independent siblings so a new platform never
// reaches into an existing one, and the Azure DevOps twin made this same
// trade for this same ~30 lines. A shared helper package would be the
// alternative; it is not obviously better, and it is not this issue's to
// create.
//
// Known imprecision, carried over verbatim with the patterns themselves —
// both false-positive classes documented on the GitHub original still apply
// here unchanged:
//
//   - urlPattern matches ANY https:// string, including one inside an
//     unrelated code block, so a SECURITY.md whose only https:// text is a
//     code example — with no genuine channel anywhere — verified-passes
//     rather than reporting partial. As on Azure DevOps, there is no third
//     signal here that could independently corroborate a real channel, so
//     this class is if anything more exposed than on GitHub, not less.
//   - emailPattern matches a version-pinned package reference like
//     `go install example.com/tool@v1.2.3` (the version string after `@`
//     satisfies `[\w-]+\.[\w.-]+` the same way a domain does).
var (
	emailPattern = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
	urlPattern   = regexp.MustCompile(`https?://\S+`)
)

// findIntakeChannelMatches reports which of the two signals appear in a
// SECURITY.md's content, as a stable, sorted list suitable for a Facts
// value. An empty result means the file exists but tells a reporter
// nothing about how to reach the producer.
func findIntakeChannelMatches(content string) []string {
	var matches []string
	if emailPattern.MatchString(content) {
		matches = append(matches, "email")
	}
	if urlPattern.MatchString(content) {
		matches = append(matches, "url")
	}
	return matches
}

// describeMatches renders the matched signals for a Reason string. Kept
// separate from findIntakeChannelMatches so the Facts value and the prose
// can never disagree about what was actually found.
func describeMatches(matches []string) string {
	return strings.Join(matches, ", ")
}
