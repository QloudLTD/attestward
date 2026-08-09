package vdp

import (
	"regexp"
	"strings"
)

// The two independent signals that count as an actionable intake channel
// on Azure DevOps — deliberately a subset of
// internal/collect/github/vdp/heuristics.go's three: emailPattern and
// urlPattern are reproduced here verbatim (content heuristics are
// platform-neutral, per issue #154's own framing), but githubReportingPattern
// is dropped entirely rather than ported, since it matches a GitHub-specific
// UI feature/URL path ("private vulnerability reporting",
// "security/advisories") this platform has no equivalent of at all (see
// C10.vdp.private-reporting, always not-checkable for that exact reason) —
// porting it here would let a SECURITY.md pass this check by mentioning a
// feature that doesn't exist on Azure DevOps.
//
// Duplicated rather than imported from the GitHub package: ADR-0005 keeps
// github and azuredevops as independent siblings so a future platform
// never has to reach into either one (internal/collect/azuredevops/pipelinehistory's
// own doc comment makes the identical trade against runhistory, for the
// identical reason) — issue #154 itself offers this exact choice ("factor
// into a shared helper if trivial, else duplicate ~30 lines rather than
// create a cross-platform package dependency"), and ~30 lines is exactly
// the size of what's duplicated here.
//
// Known imprecision, carried over unchanged from the GitHub twin's own doc
// comment (its own dogfooding scan of that project found these): the
// regexes below are reproduced verbatim, so both false-positive classes
// still apply here exactly as they do there.
//
//   - urlPattern matches ANY https:// string, including one inside an
//     unrelated code block (e.g. a `cosign verify-blob
//     --certificate-identity-regexp "^https://github.com/..."` example) —
//     a SECURITY.md whose *only* https:// text is an unrelated code
//     example, with no genuine channel anywhere, would incorrectly
//     verified-pass rather than partial. Unlike the GitHub twin, there's
//     no third signal here that could independently confirm a real
//     channel exists alongside a spurious code-block match — dropping
//     githubReportingPattern (see above) removes a source of *false*
//     confirmation, but also removes the one thing that happened to keep
//     this exact false-positive class from mattering on the GitHub side,
//     so it is, if anything, more exposed here, not less.
//   - emailPattern has the identical failure class for a different kind
//     of code example: a version-pinned package reference like `go
//     install example.com/tool@v1.2.3` or `npm install left-pad@1.3.0`
//     matches (the version string after `@` satisfies `[\w-]+\.[\w.-]+`
//     the same as a domain would), so a SECURITY.md whose only "@"-shaped
//     text is an install command in a code block would also
//     false-positive.
//
// Fixing either class precisely would need markdown-aware code-fence
// exclusion, not just a regex — out of scope for the "content heuristics"
// issue #154 asks for; flagged here rather than silently accepted, same
// as the GitHub twin does for its own copy of these two regexes.
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
