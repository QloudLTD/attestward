package vdp

import "testing"

func TestFindIntakeChannelMatches(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		wantTypes []string
	}{
		{
			name:      "email address",
			content:   "Please contact security@example.com regarding any issues.",
			wantTypes: []string{"email"},
		},
		{
			name:      "absolute URL",
			content:   "Report vulnerabilities at https://example.com/security/report",
			wantTypes: []string{"url"},
		},
		{
			name:      "relative link to GitHub private reporting, this repo's own real style",
			content:   "- Preferred: [GitHub private vulnerability reporting](../../security/advisories/new)\n(\"Report a vulnerability\" on the Security tab).",
			wantTypes: []string{"github-reporting-mention"},
		},
		{
			name:      "vague content with no channel",
			content:   "# Security Policy\n\nWe take security seriously and appreciate responsible disclosure.",
			wantTypes: nil,
		},
		{
			name:      "multiple signals",
			content:   "Email us at security@example.com or see https://example.com/security for details.",
			wantTypes: []string{"email", "url"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := findIntakeChannelMatches(tt.content)
			if len(matches) != len(tt.wantTypes) {
				t.Fatalf("matches = %+v, want types %v", matches, tt.wantTypes)
			}
			for i, m := range matches {
				if m.Type != tt.wantTypes[i] {
					t.Errorf("matches[%d].Type = %q, want %q", i, m.Type, tt.wantTypes[i])
				}
				if m.Snippet == "" {
					t.Errorf("matches[%d].Snippet is empty, want the matching line", i)
				}
			}
		})
	}
}

func TestFindIntakeChannelMatches_ThisRepoOwnSecurityMD(t *testing.T) {
	// A regression guard: this collector's own project SECURITY.md uses a
	// relative markdown link, not a bare https:// URL — the exact real
	// pattern githubReportingPattern exists to catch. If this ever
	// regresses to zero matches, the collector would wrongly grade its
	// own project's SECURITY.md as "vague".
	content := `# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

- Preferred: [GitHub private vulnerability reporting](../../security/advisories/new)
  ("Report a vulnerability" on the Security tab).
`
	matches := findIntakeChannelMatches(content)
	if len(matches) == 0 {
		t.Fatal("expected at least one match against this repo's own real SECURITY.md style, got none")
	}
}
