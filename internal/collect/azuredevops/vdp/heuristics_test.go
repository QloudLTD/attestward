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

// TestFindIntakeChannelMatches_GitHubOnlyPhrasingFindsNothingOnADO is the
// deliberate-narrowing counterpart to the GitHub twin's
// TestFindIntakeChannelMatches_ThisRepoOwnSecurityMD regression guard: this
// project's own SECURITY.md advertises its channel via a relative markdown
// link plus GitHub-specific phrasing ("GitHub private vulnerability
// reporting", "Report a vulnerability on the Security tab") with no bare
// email or http(s):// URL anywhere — exactly the content
// githubReportingPattern existed to catch on the GitHub side. Dropping that
// pattern here (see heuristics.go's own doc comment: Azure DevOps has no
// equivalent feature to reference) means this exact content now correctly
// finds zero matches — a deliberate behavior difference from the GitHub
// twin, not a regression, since a real ADO producer's SECURITY.md
// referencing a GitHub-only feature would be pointing reporters at
// something that doesn't exist on this platform.
func TestFindIntakeChannelMatches_GitHubOnlyPhrasingFindsNothingOnADO(t *testing.T) {
	content := `# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

- Preferred: [GitHub private vulnerability reporting](../../security/advisories/new)
  ("Report a vulnerability" on the Security tab).
`
	matches := findIntakeChannelMatches(content)
	if len(matches) != 0 {
		t.Errorf("matches = %+v, want none — this content has no bare email or http(s):// URL, only GitHub-specific phrasing this platform's heuristics deliberately don't recognize", matches)
	}
}
