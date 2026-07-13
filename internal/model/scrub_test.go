package model

import (
	"strings"
	"testing"
)

func TestScrubRedactsSecretShapedStrings(t *testing.T) {
	cases := map[string]string{
		"github classic PAT":          "token=ghp_" + strings.Repeat("a", 40),
		"github fine-grained PAT":     "token=github_pat_" + strings.Repeat("a", 60),
		"github server token":         "token=ghs_" + strings.Repeat("a", 40),
		"github refresh token":        "token=ghr_" + strings.Repeat("a", 40),
		"github user-to-server token": "token=ghu_" + strings.Repeat("a", 40),
		"aws access key":              "key=AKIA" + strings.Repeat("A", 16),
		"aws temporary/STS key":       "key=ASIA" + strings.Repeat("A", 16),
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
