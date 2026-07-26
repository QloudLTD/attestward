package mdescape

import "testing"

// TestEscape_PerRule is issue #222's review finding: internal/mdescape had
// no test file at all, and internal/report's own hostile-string tests
// compute their "expected escaped form" by calling Escape itself
// (self-referential — structurally blind to a regression here, proven by
// mutation: deleting the pipe rule from escaper left ./internal/report/...
// green, and deleting the backtick rule left the ENTIRE repo test suite
// green). One table case per replacer rule, each asserting the literal
// hand-written output — not derived from escaper itself — so a rule
// silently dropped, reordered, or given the wrong replacement text fails
// its own dedicated case instead of hiding behind an unrelated field's
// coverage.
func TestEscape_PerRule(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"backslash", `a\b`, `a\\b`},
		{"backtick", "a`b", "a\\`b"},
		{"asterisk", `a*b`, `a\*b`},
		{"underscore", `a_b`, `a\_b`},
		{"open-bracket", `a[b`, `a\[b`},
		{"close-bracket", `a]b`, `a\]b`},
		{"less-than", `a<b`, `a\<b`},
		{"greater-than", `a>b`, `a\>b`},
		{"pipe", `a|b`, `a\|b`},
		{"newline-flattened-to-space", "a\nb", "a b"},
		{"carriage-return-dropped", "a\rb", "ab"},
		{"crlf-collapses-to-space", "a\r\nb", "a b"},
		{"plain-text-untouched", "plain ascii, no special chars.", "plain ascii, no special chars."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Escape(tc.in); got != tc.want {
				t.Errorf("Escape(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEscape_ScriptTagNeutralized pins issue #25's own acceptance
// criterion directly: a <script> tag must never survive Escape intact,
// since escaping < and > is what breaks it from ever becoming live HTML if
// this markdown is later rendered to HTML by GitHub or any other renderer.
func TestEscape_ScriptTagNeutralized(t *testing.T) {
	got := Escape("<script>alert(1)</script>")
	want := `\<script\>alert(1)\</script\>`
	if got != want {
		t.Errorf("Escape(<script>...) = %q, want %q", got, want)
	}
}

// TestEscape_MarkdownLinkBombBroken pins issue #25's other named threat
// class: a markdown link whose target is a javascript: URL must have its
// [...] syntax broken, so it can never render as a live, clickable link.
func TestEscape_MarkdownLinkBombBroken(t *testing.T) {
	got := Escape("[click here](javascript:alert(1))")
	want := `\[click here\](javascript:alert(1))`
	if got != want {
		t.Errorf("Escape(link bomb) = %q, want %q", got, want)
	}
}

// TestEscape_TableRowBreakingPipeAndCodeSpanBackslashNotDoubled proves two
// things a mutation could independently break without the other catching
// it: a pipe inside what would otherwise be a markdown table cell is
// escaped (so it can't inject a fake extra column), and a literal
// backslash in the input is escaped to a literal double-backslash BEFORE
// the other rules run (per escaper's own doc comment) rather than
// interacting with them — e.g. a backslash immediately followed by a
// backtick must not be read as "already escaping" the backtick and left
// alone.
func TestEscape_TableRowBreakingPipeAndCodeSpanBackslashNotDoubled(t *testing.T) {
	got := Escape("cell one | cell two")
	want := `cell one \| cell two`
	if got != want {
		t.Errorf("Escape(pipe) = %q, want %q", got, want)
	}

	got = Escape("a\\`b")
	want = "a\\\\\\`b"
	if got != want {
		t.Errorf("Escape(backslash-then-backtick) = %q, want %q", got, want)
	}
}

// TestEscape_KitchenSink is a single hostile value packing several rules
// at once (mirrors internal/report's own hostile-Project-value fixtures),
// with the expected output hand-written rather than computed via Escape
// itself — the exact self-referential-assertion gap issue #222's review
// found in internal/report/render_test.go. Both cases here are the actual
// hostilePackProjectValue/hostileScopeProjectValue fixtures that file's own
// assertHostileProjectValuesEscapedForMarkdown checks against report.md's
// real output — this test pins the SAME expected strings independently, so
// a mistake in either place would show up as a mismatch between the two,
// not agree with itself.
func TestEscape_KitchenSink(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "hostilePackProjectValue",
			in:   "pack-project\" onmouseover=\"alert('pack-project')|`code-span-break`\nsecond-line-pack-project",
			want: "pack-project\" onmouseover=\"alert('pack-project')\\|\\`code-span-break\\` second-line-pack-project",
		},
		{
			name: "hostileScopeProjectValue",
			in:   "scope-project\" onmouseover=\"alert('scope-project')|`code-span-break`\nsecond-line-scope-project",
			want: "scope-project\" onmouseover=\"alert('scope-project')\\|\\`code-span-break\\` second-line-scope-project",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Escape(tc.in); got != tc.want {
				t.Errorf("Escape(kitchen sink) =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}
