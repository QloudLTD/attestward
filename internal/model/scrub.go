package model

import "regexp"

// secretPatterns matches secret-shaped strings that must never survive into
// a serialized evidence pack: GitHub token prefixes, AWS access keys, and
// PEM/PGP private-key blocks. Defense in depth — collectors should never put
// raw secrets into Reason/Facts/Provenance in the first place, but this is
// the last line of defense before anything touches disk (docs/threat-model.md).
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
