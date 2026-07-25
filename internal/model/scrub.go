package model

import "regexp"

// secretPatterns matches secret-shaped strings that must never survive into
// a serialized evidence pack: GitHub token prefixes, AWS access keys, Azure
// DevOps PATs, and PEM/PGP private-key blocks. Defense in depth —
// collectors should never put raw secrets into Reason/Facts/Provenance in
// the first place, but this is the last line of defense before anything
// touches disk (docs/threat-model.md).
//
// Order matters for the private-key patterns: the paired BEGIN...END pattern
// runs first and redacts complete blocks; the unpaired BEGIN...(end of
// string) pattern then catches whatever's left starting a private-key
// header with no matching footer (e.g. a block truncated by upstream string
// handling) — redacting to the end of the string rather than leaking the
// key body after a lost footer.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`),
	regexp.MustCompile(`gho_[A-Za-z0-9]{36,}`),
	regexp.MustCompile(`ghs_[A-Za-z0-9]{36,}`),
	regexp.MustCompile(`ghr_[A-Za-z0-9]{36,}`),
	regexp.MustCompile(`ghu_[A-Za-z0-9]{36,}`),
	regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`ASIA[0-9A-Z]{16}`),
	// azureDevOpsPAT matches the documented Azure DevOps personal-access-token
	// shape (issue #192, tightened in its own review round): 84 characters
	// total, with a fixed "AZDO" signature Microsoft's own PAT format
	// reference (learn.microsoft.com, "Use personal access tokens - Azure
	// DevOps", section "PAT format") describes as "Tokens are 84 characters
	// long, with 52 characters being randomized data" and "Tokens issued by
	// Azure DevOps include a fixed AZDO signature at positions 76-80" — that
	// source names FIVE positions for a FOUR-character literal, so it's
	// self-inconsistent about where the signature starts; at least two
	// readings survive, both totaling 84: 76 leading characters + AZDO + 4
	// trailing (0-indexed half-open [76,80)), or 75 leading + AZDO + 5
	// trailing (1-indexed 76-79). Both are matched via alternation — a
	// scrubber that silently never fires on a real PAT because it guessed
	// the wrong offset is worse than one that covers both candidates — but
	// deliberately as two EXACT 84-total combinations, not independent
	// {75,76}/{4,5} ranges: the latter also accepts 75+4+4=83 and
	// 76+4+5=85, matching lengths the source doesn't claim exist (found in
	// review: an earlier version of this pattern did exactly that, and
	// broke the near-miss-length test below). The exact alphabet of the 80
	// non-signature characters is undocumented beyond "randomized data";
	// [A-Za-z0-9] is used, which is known to be INCOMPLETE if the real
	// alphabet includes non-alphanumeric characters (e.g. -, _) — that
	// residual gap is unverified without a real token sample, not
	// eliminated by this pattern. \b at both ends keeps this from silently
	// consuming (and hashing over, unmarked) an unrelated 84-character span
	// embedded inside a longer alphanumeric run that merely happens to
	// contain "azdo" — it only matches when the span is its own token,
	// boundaried by a non-word character ([^0-9A-Za-z_]) or the string's
	// edge (found in review: RE2's \b is a WORD boundary, not specifically
	// alphanumeric — `_` counts as a word character, so `prefix_<PAT>` or
	// `<PAT>_suffix` genuinely would NOT match; behaviorally negligible —
	// a real leaked PAT is delimited by `//` and `@` in a git-clone URL,
	// quotes in JSON, or whitespace, none of which are word characters —
	// but the earlier wording overstated what \b actually guarantees).
	regexp.MustCompile(`(?i)\b(?:[A-Za-z0-9]{76}azdo[A-Za-z0-9]{4}|[A-Za-z0-9]{75}azdo[A-Za-z0-9]{5})\b`),
	regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----.*?-----END [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----`),
	regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----.*$`),
}

const redacted = "[REDACTED]"

func scrubString(s string) string {
	for _, p := range secretPatterns {
		s = p.ReplaceAllString(s, redacted)
	}
	return s
}

// scrubValue redacts secret-shaped strings anywhere inside an arbitrary
// JSON-shaped value — string, []any, map[string]any, or (recursively) any
// nesting thereof — since Facts' own contract (see CheckResult) permits all
// of those, not just top-level strings.
func scrubValue(v any) any {
	switch val := v.(type) {
	case string:
		return scrubString(val)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = scrubValue(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			out[k] = scrubValue(item)
		}
		return out
	default:
		return v
	}
}

// ScrubBytes redacts secret-shaped substrings directly from raw bytes — the
// last-line-of-defense pass issue #24's evidence.json writer runs over the
// final marshaled pack, independent of which struct field a secret happened
// to end up in. Use alongside, not instead of, CheckResult.Scrub/
// EvidencePack.Scrub (those run earlier, e.g. before logging a single
// result), since neither alone is a complete guarantee.
func ScrubBytes(data []byte) []byte {
	return []byte(scrubString(string(data)))
}

// Scrub redacts secret-shaped strings from Reason, every Provenance
// Endpoint, and any string value nested anywhere inside Facts, in place.
func (c *CheckResult) Scrub() {
	c.Reason = scrubString(c.Reason)
	for k, v := range c.Facts {
		c.Facts[k] = scrubValue(v)
	}
	for i := range c.Provenance {
		c.Provenance[i].Endpoint = scrubString(c.Provenance[i].Endpoint)
	}
}

// Scrub applies CheckResult.Scrub to every result in the pack. Called as a
// defensive pass before the pack is written (issue #24), which should also
// run ScrubBytes over the final marshaled output as the true last line of
// defense.
func (p *EvidencePack) Scrub() {
	for i := range p.Results {
		p.Results[i].Scrub()
	}
}
