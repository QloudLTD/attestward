package model

import (
	"strings"
	"testing"
)

func TestScrubRedactsSecretShapedStrings(t *testing.T) {
	cases := map[string]string{
		"github classic PAT":                           "token=ghp_" + strings.Repeat("a", 40),
		"github fine-grained PAT":                      "token=github_pat_" + strings.Repeat("a", 60),
		"github server token":                          "token=ghs_" + strings.Repeat("a", 40),
		"github refresh token":                         "token=ghr_" + strings.Repeat("a", 40),
		"github user-to-server token":                  "token=ghu_" + strings.Repeat("a", 40),
		"aws access key":                               "key=AKIA" + strings.Repeat("A", 16),
		"aws temporary/STS key":                        "key=ASIA" + strings.Repeat("A", 16),
		"azure devops PAT (0-indexed [76,80) reading)": "token=" + strings.Repeat("a", 76) + "azdo" + strings.Repeat("a", 4),
		"azure devops PAT (1-indexed 76-79 reading)":   "token=" + strings.Repeat("a", 75) + "azdo" + strings.Repeat("a", 5),
		"azure devops PAT (uppercase signature, as Microsoft's docs render it)": "token=" + strings.Repeat("a", 76) + "AZDO" + strings.Repeat("a", 4),
		"pem private key block": "-----BEGIN RSA PRIVATE KEY-----\n" +
			strings.Repeat("A", 64) + "\n-----END RSA PRIVATE KEY-----",
		"pgp private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" +
			strings.Repeat("A", 64) + "\n-----END PGP PRIVATE KEY BLOCK-----",
		"truncated pem (no footer)": "-----BEGIN RSA PRIVATE KEY-----\n" +
			strings.Repeat("A", 64) + "\n(truncated, no END marker)",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out := scrubString(in)
			if out == in {
				t.Fatalf("scrubString(%q) did not redact anything", in)
			}
			if strings.Contains(out, "aaaa") || strings.Contains(out, "AAAA") {
				t.Fatalf("scrubString(%q) = %q, secret material survived", in, out)
			}
		})
	}
}

// TestScrubADOPATPositionSensitive proves the Azure DevOps PAT pattern only
// matches the two documented-length-84 shapes — not any 84-character run
// that merely contains "azdo" somewhere else, and not an off-by-one length
// near either boundary (83 or 85, neither of which the source's own "84
// characters" claim admits, even though independently ranging the leading/
// trailing character counts would wrongly accept both — see the pattern's
// own doc comment). Without this, a looser pattern (e.g. a bare "azdo"
// substring search) would false-positive on ordinary text far more often
// than the risk is worth.
func TestScrubADOPATPositionSensitive(t *testing.T) {
	wrongPosition := strings.Repeat("a", 40) + "azdo" + strings.Repeat("a", 40) // 84 chars, azdo at the wrong offset
	if len(wrongPosition) != 84 {
		t.Fatalf("test fixture length = %d, want 84", len(wrongPosition))
	}
	if out := scrubString("token=" + wrongPosition); out != "token="+wrongPosition {
		t.Errorf("scrubString redacted an 84-char string with azdo at the wrong position: %q", out)
	}

	tooShort := strings.Repeat("a", 75) + "azdo" + strings.Repeat("a", 4) // 83 chars total
	if len(tooShort) != 83 {
		t.Fatalf("test fixture length = %d, want 83", len(tooShort))
	}
	if out := scrubString("token=" + tooShort); out != "token="+tooShort {
		t.Errorf("scrubString redacted an 83-char near-miss: %q", out)
	}

	// 76 leading + azdo + 5 trailing = 85 total: satisfies BOTH readings'
	// individual bounds (76 is a valid leading count, 5 is a valid trailing
	// count) but not together — neither reading (a) nor (b) is 85 total.
	// An independently-ranged {75,76}/{4,5} pattern would wrongly accept
	// this; the exact two-combination alternation must not.
	tooLong := strings.Repeat("a", 76) + "azdo" + strings.Repeat("a", 5) // 85 chars total
	if len(tooLong) != 85 {
		t.Fatalf("test fixture length = %d, want 85", len(tooLong))
	}
	if out := scrubString("token=" + tooLong); out != "token="+tooLong {
		t.Errorf("scrubString redacted an 85-char near-miss (76+azdo+5, a combination neither documented reading claims): %q", out)
	}
}

// TestScrubADOPATRequiresTokenBoundary proves the \b anchors at both ends
// of the Azure DevOps PAT pattern: a benign, long alphanumeric run that
// happens to contain "azdo" somewhere in its interior — with ordinary
// alphanumeric characters immediately on both sides of what would
// otherwise be an 84-character matching window — must NOT be redacted.
// Without the boundary requirement, this collapses a real, unrelated value
// (baked into the signed pack hash) into "[REDACTED]" with no record that
// a substitution happened, which is worse than the gap it would be
// closing: a benign 200+ character alphanumeric run is exactly the shape a
// base64-ish blob or a concatenated set of identifiers could take.
func TestScrubADOPATRequiresTokenBoundary(t *testing.T) {
	// 100 leading + "azdo" + 96 trailing = 200 chars; "azdo" sits well
	// inside the run, so any 84-char window covering it is flanked by more
	// alphanumeric characters on both sides — no token boundary anywhere
	// near the match.
	benign := strings.Repeat("b", 100) + "azdo" + strings.Repeat("c", 96)
	if len(benign) != 200 {
		t.Fatalf("test fixture length = %d, want 200", len(benign))
	}
	in := "digest=" + benign
	if out := scrubString(in); out != in {
		t.Errorf("scrubString redacted a benign 200-char alphanumeric run merely because an 84-char window inside it matched the ADO PAT shape: %q", out)
	}
}

func TestScrubValueRecursesIntoSlicesAndMaps(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 40)

	cases := map[string]any{
		"slice":        []any{"clean", "token=" + secret},
		"map":          map[string]any{"nested": "token=" + secret},
		"nested slice": []any{[]any{"token=" + secret}},
		"nested map":   map[string]any{"outer": map[string]any{"inner": "token=" + secret}},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			out := scrubValue(in)
			if strings.Contains(fmtValue(out), secret) {
				t.Fatalf("scrubValue(%v) = %v, secret material survived", in, out)
			}
		})
	}
}

// fmtValue is a test-only helper to search a scrubValue result (which may be
// a string, slice, or map of any nesting) for leftover secret text without
// hand-rolling a type switch per test case.
func fmtValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case []any:
		var sb strings.Builder
		for _, item := range val {
			sb.WriteString(fmtValue(item))
		}
		return sb.String()
	case map[string]any:
		var sb strings.Builder
		for _, item := range val {
			sb.WriteString(fmtValue(item))
		}
		return sb.String()
	default:
		return ""
	}
}

func TestScrubLeavesOrdinaryTextAlone(t *testing.T) {
	in := "main requires 1 approving review and passing status checks"
	if out := scrubString(in); out != in {
		t.Fatalf("scrubString modified ordinary text: got %q want %q", out, in)
	}
}

func TestCheckResultScrubRedactsReasonFactsAndProvenance(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 40)
	cr := CheckResult{
		Reason: "leaked " + secret + " in output",
		Facts: map[string]any{
			"snippet":     "token=" + secret,
			"count":       3,
			"nested_list": []any{"token=" + secret},
			"nested_map":  map[string]any{"inner": "token=" + secret},
		},
		Provenance: []Provenance{
			{Endpoint: "/x?access_token=" + secret},
		},
	}
	cr.Scrub()

	if strings.Contains(cr.Reason, secret) {
		t.Errorf("Reason was not scrubbed: %q", cr.Reason)
	}
	snippet, ok := cr.Facts["snippet"].(string)
	if !ok || strings.Contains(snippet, secret) {
		t.Errorf("Facts[%q] was not scrubbed: %v", "snippet", cr.Facts["snippet"])
	}
	if cr.Facts["count"] != 3 {
		t.Errorf("non-string fact was unexpectedly modified: %v", cr.Facts["count"])
	}
	if strings.Contains(fmtValue(cr.Facts["nested_list"]), secret) {
		t.Errorf("Facts[%q] (nested in a slice) was not scrubbed: %v", "nested_list", cr.Facts["nested_list"])
	}
	if strings.Contains(fmtValue(cr.Facts["nested_map"]), secret) {
		t.Errorf("Facts[%q] (nested in a map) was not scrubbed: %v", "nested_map", cr.Facts["nested_map"])
	}
	if strings.Contains(cr.Provenance[0].Endpoint, secret) {
		t.Errorf("Provenance[0].Endpoint was not scrubbed: %q", cr.Provenance[0].Endpoint)
	}
}

func TestScrubBytesRedactsAcrossMarshaledJSON(t *testing.T) {
	secret := "ghp_" + strings.Repeat("a", 40)
	data := []byte(`{"reason":"token=` + secret + `","facts":{"nested":["token=` + secret + `"]}}`)

	out := ScrubBytes(data)
	if strings.Contains(string(out), secret) {
		t.Fatalf("ScrubBytes did not redact secret material: %s", out)
	}
}
