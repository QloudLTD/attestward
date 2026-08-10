package vdp

import (
	"regexp"
	"strings"
)

// The two independent signals that count as an actionable intake channel
// on GitLab — the same subset of internal/collect/github/vdp/heuristics.go's
// three that the Azure DevOps twin uses, and for the identical reason:
// emailPattern and urlPattern are content heuristics, platform-neutral per
// issue #154's own framing, but githubReportingPattern is dropped entirely
// since it matches a GitHub-specific UI feature this platform has no
// equivalent of at all (see C10.vdp.private-reporting, always not-checkable
// for that exact reason) — porting it here would let a SECURITY.md pass
// this check by mentioning a feature that doesn't exist on GitLab.
//
// Duplicated rather than imported from either twin, matching ADR-0005 and
// the identical trade the Azure DevOps twin's own doc comment already
// makes: independent per-platform siblings, ~30 lines duplicated rather
// than a cross-platform package dependency.
//
// Known imprecision, carried over unchanged from both twins' own doc
// comments (their own dogfooding scans of this project found these, and
// this project's own SECURITY.md is exactly the kind of content that could
// trip either false-positive class):
//
//   - urlPattern matches ANY https:// string, including one inside an
//     unrelated code block or command example, not just a genuine intake
//     channel.
//   - emailPattern has the identical failure class for a version-pinned
//     package reference (e.g. `left-pad@1.3.0`) — the version string after
//     `@` satisfies the domain-shaped part of the pattern.
//
// Fixing either precisely would need markdown-aware code-fence exclusion,
// not just a regex — out of scope here, same as both twins.
var (
	emailPattern = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
	urlPattern   = regexp.MustCompile(`https?://\S+`)
)

// intakeMatch is one signal type findIntakeChannelMatches found, plus the
// line it appeared on (for a human-readable Facts snippet — never the
// whole file content, per model.CheckResult's "minimal extracted data"
// contract).
type intakeMatch struct {
	Type    string
	Snippet string
}

// findIntakeChannelMatches checks content against both intake signals, in
// a fixed order, so results are deterministic across identical input. A
// pure function: no I/O, given content the caller already fetched.
func findIntakeChannelMatches(content string) []intakeMatch {
	var matches []intakeMatch
	for _, sig := range []struct {
		typ string
		re  *regexp.Regexp
	}{
		{"email", emailPattern},
		{"url", urlPattern},
	} {
		if loc := sig.re.FindStringIndex(content); loc != nil {
			matches = append(matches, intakeMatch{Type: sig.typ, Snippet: lineContaining(content, loc[0])})
		}
	}
	return matches
}

// lineContaining returns the trimmed line of content that byte offset idx
// falls within.
func lineContaining(content string, idx int) string {
	start := strings.LastIndexByte(content[:idx], '\n') + 1
	end := len(content)
	if rel := strings.IndexByte(content[idx:], '\n'); rel >= 0 {
		end = idx + rel
	}
	return strings.TrimSpace(content[start:end])
}
