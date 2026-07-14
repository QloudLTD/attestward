package vdp

import (
	"regexp"
	"strings"
)

// The three independent signals that count as an actionable intake
// channel. A plain https://... URL alone isn't enough to catch every
// legitimate real-world SECURITY.md: this repo's own SECURITY.md, for
// example, links to GitHub's private-vulnerability-reporting UI with a
// relative markdown link ("(../../security/advisories/new)"), which
// urlPattern alone would miss — githubReportingPattern exists
// specifically to catch that common phrasing/relative-link pattern
// alongside literal email addresses and absolute URLs.
//
// Known imprecision, confirmed via this collector's own dogfooding scan
// of this repo: urlPattern matches ANY https:// string, including one
// inside an unrelated code block (this repo's own SECURITY.md has a
// `cosign verify-blob --certificate-identity-regexp
// "^https://github.com/..."` example under "Verifying releases", which
// matches as a spurious "url" signal). This repo's overall verdict still
// comes out correct only because githubReportingPattern also
// legitimately matches its real reporting link — a SECURITY.md whose
// *only* https:// text was an unrelated code example, with no genuine
// channel anywhere, would incorrectly verified-pass rather than partial.
//
// emailPattern has the identical failure class for a different kind of
// code example: a version-pinned package reference like `go install
// example.com/tool@v1.2.3` or `npm install left-pad@1.3.0` matches (the
// version string after `@` satisfies `[\w-]+\.[\w.-]+` the same as a
// domain would), so a SECURITY.md whose only "@"-shaped text is an
// install command in a code block would also false-positive.
//
// Fixing either precisely would need markdown-aware code-fence
// exclusion, not just a regex — out of scope for the "content
// heuristics" this issue asks for; flagged here rather than silently
// accepted.
var (
	emailPattern           = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
	urlPattern             = regexp.MustCompile(`https?://\S+`)
	githubReportingPattern = regexp.MustCompile(`(?i)private vulnerability reporting|report a vulnerability|security/advisories`)
)

// intakeMatch is one signal type findIntakeChannelMatches found, plus the
// line it appeared on (for a human-readable Facts snippet — never the
// whole file content, per model.CheckResult's "minimal extracted data"
// contract).
type intakeMatch struct {
	Type    string
	Snippet string
}

// findIntakeChannelMatches checks content against all three intake
// signals, in a fixed order, so results are deterministic across
// identical input. It's a pure function: no I/O, given content the
// caller already fetched.
func findIntakeChannelMatches(content string) []intakeMatch {
	var matches []intakeMatch
	for _, sig := range []struct {
		typ string
		re  *regexp.Regexp
	}{
		{"email", emailPattern},
		{"url", urlPattern},
		{"github-reporting-mention", githubReportingPattern},
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
