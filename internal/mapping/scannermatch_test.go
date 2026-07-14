package mapping

import (
	"os"
	"regexp"
	"testing"
)

// fixtureExpectations is the cross-matrix: for every workflow-detectable
// signature (dependabot excluded — see TestMatchWorkflow_
// DependabotExcludedFromWorkflowMatching), its fixture file and the
// confidence its detect block should match at.
var fixtureExpectations = []struct {
	fixture         string
	wantSignatureID string
	wantConfidence  MatchConfidence
}{
	{"codeql.yaml", "codeql", ConfidenceHigh},
	{"semgrep.yaml", "semgrep", ConfidenceHigh},
	{"sonarqube.yaml", "sonarqube", ConfidenceHigh},
	{"dependency-review.yaml", "dependency-review-action", ConfidenceHigh},
	{"snyk.yaml", "snyk", ConfidenceMedium},
	{"trivy.yaml", "trivy", ConfidenceHigh},
	{"grype.yaml", "grype", ConfidenceHigh},
	{"osv-scanner.yaml", "osv-scanner", ConfidenceHigh},
	{"cosign.yaml", "cosign", ConfidenceHigh},
	{"slsa-generator.yaml", "slsa-generator", ConfidenceHigh},
	{"attest-build-provenance.yaml", "attest-build-provenance", ConfidenceHigh},
}

func loadFixtureWorkflow(t *testing.T, name string) WorkflowFile {
	t.Helper()
	data, err := os.ReadFile("testdata/workflows/" + name)
	if err != nil {
		t.Fatalf("read testdata/workflows/%s: %v", name, err)
	}
	wf, err := ParseWorkflowFile(data)
	if err != nil {
		t.Fatalf("parse testdata/workflows/%s: %v", name, err)
	}
	return wf
}

// TestMatchWorkflow_CrossMatrix is the issue's own acceptance criterion:
// "every initial signature detects its fixture and does not match the
// others." For each fixture, asserts its own signature matches at the
// expected confidence, and that no OTHER workflow-detectable signature
// also fires against it.
func TestMatchWorkflow_CrossMatrix(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}

	for _, tc := range fixtureExpectations {
		t.Run(tc.fixture, func(t *testing.T) {
			wf := loadFixtureWorkflow(t, tc.fixture)
			matches := reg.MatchWorkflow(wf)

			byID := map[string]ScannerMatch{}
			for _, m := range matches {
				byID[m.SignatureID] = m
			}

			got, ok := byID[tc.wantSignatureID]
			if !ok {
				t.Fatalf("expected signature %q to match %s, but it did not (matches: %+v)", tc.wantSignatureID, tc.fixture, matches)
			}
			if got.Confidence != tc.wantConfidence {
				t.Errorf("signature %q matched %s at confidence %q, want %q", tc.wantSignatureID, tc.fixture, got.Confidence, tc.wantConfidence)
			}

			for _, other := range fixtureExpectations {
				if other.wantSignatureID == tc.wantSignatureID {
					continue
				}
				if m, matched := byID[other.wantSignatureID]; matched {
					t.Errorf("%s unexpectedly also matched signature %q (cross-contamination): %+v", tc.fixture, other.wantSignatureID, m)
				}
			}
		})
	}
}

// TestMatchWorkflow_DependabotExcludedFromWorkflowMatching documents and
// pins the scoping decision in scanner-signatures.yaml's header comment:
// dependabot's real detection mechanism (a config file's presence) can't
// be expressed by this workflow-content matcher, so its detect block is
// deliberately empty and it must never match any fixture here.
func TestMatchWorkflow_DependabotExcludedFromWorkflowMatching(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}

	dep, ok := reg.SignatureByID["dependabot"]
	if !ok {
		t.Fatal("dependabot signature not found in registry")
	}
	if len(dep.Detect.Actions) != 0 || len(dep.Detect.RunPatterns) != 0 || len(dep.Detect.WorkflowNamePatterns) != 0 {
		t.Error("dependabot's detect block is no longer empty — its real detection (config-file presence) was out of scope for issue #16; if this changed intentionally, update this test and scanner-signatures.yaml's header comment")
	}

	for _, tc := range fixtureExpectations {
		wf := loadFixtureWorkflow(t, tc.fixture)
		for _, m := range reg.MatchWorkflow(wf) {
			if m.SignatureID == "dependabot" {
				t.Errorf("dependabot unexpectedly matched %s", tc.fixture)
			}
		}
	}
}

// TestFixtureExpectationsCoverAllDetectableSignatures enforces
// CONTRIBUTING.md's fixture requirement as a real, checked invariant:
// every registry signature with a non-empty detect block must have a
// fixtureExpectations entry. Without this, a new signature added to
// scanner-signatures.yaml without a matching fixture would pass every
// existing test even if its regex happened to fire on some OTHER tool's
// fixture too — nothing would ever inspect its match results, since
// TestMatchWorkflow_CrossMatrix only iterates fixtureExpectations, not the
// registry itself.
func TestFixtureExpectationsCoverAllDetectableSignatures(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}

	covered := map[string]bool{}
	for _, tc := range fixtureExpectations {
		covered[tc.wantSignatureID] = true
	}

	for _, sig := range reg.Signatures {
		detectable := len(sig.Detect.Actions) > 0 || len(sig.Detect.RunPatterns) > 0 || len(sig.Detect.WorkflowNamePatterns) > 0
		if detectable && !covered[sig.ID] {
			t.Errorf("signature %q has a non-empty detect block but no fixtureExpectations entry — add a fixture workflow under testdata/workflows/ and a table entry (see CONTRIBUTING.md's fixture requirement); until then this signature's matching behavior is completely untested", sig.ID)
		}
	}
}

// TestMatchWorkflow_AlternateActionSlugsForExistingSignatures proves each
// of the additional action slugs added to the real registry (beyond the
// one exercised by that tool's canonical testdata/workflows fixture)
// genuinely matches — not enumerated in mappings/scanner-signatures.yaml
// on faith, and not left completely untested just because the tool
// already has one working fixture.
func TestMatchWorkflow_AlternateActionSlugsForExistingSignatures(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}

	tests := []struct {
		name            string
		wf              WorkflowFile
		wantSignatureID string
	}{
		{
			name:            "semgrep renamed org slug (semgrep/semgrep-action)",
			wf:              WorkflowFile{Jobs: map[string]WorkflowJob{"job": {Steps: []WorkflowStep{{Uses: "semgrep/semgrep-action@v1"}}}}},
			wantSignatureID: "semgrep",
		},
		{
			name:            "legacy SonarCloud action",
			wf:              WorkflowFile{Jobs: map[string]WorkflowJob{"job": {Steps: []WorkflowStep{{Uses: "SonarSource/sonarcloud-github-action@v2"}}}}},
			wantSignatureID: "sonarqube",
		},
		{
			name:            "snyk per-language action",
			wf:              WorkflowFile{Jobs: map[string]WorkflowJob{"job": {Steps: []WorkflowStep{{Uses: "snyk/actions/node@master"}}}}},
			wantSignatureID: "snyk",
		},
		{
			name: "OSV-Scanner job-level reusable workflow (not a step)",
			wf: WorkflowFile{Jobs: map[string]WorkflowJob{
				"scan": {Uses: "google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@v2.0.0"},
			}},
			wantSignatureID: "osv-scanner",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := reg.MatchWorkflow(tt.wf)
			for _, m := range matches {
				if m.SignatureID == tt.wantSignatureID {
					if m.Confidence != ConfidenceHigh {
						t.Errorf("matched %q at confidence %q, want high", tt.wantSignatureID, m.Confidence)
					}
					return
				}
			}
			t.Errorf("expected signature %q to match, got %+v", tt.wantSignatureID, matches)
		})
	}
}

// TestMatchWorkflow_EmptyWorkflowMatchesNothing proves the matcher doesn't
// false-positive on a workflow with no recognizable content.
func TestMatchWorkflow_EmptyWorkflowMatchesNothing(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}
	matches := reg.MatchWorkflow(WorkflowFile{Name: "unrelated workflow"})
	if len(matches) != 0 {
		t.Errorf("MatchWorkflow(empty) = %+v, want no matches", matches)
	}
}

// TestMatchWorkflow_ActionMatchOutranksRunPatternMatch proves the
// confidence-priority order: a workflow satisfying both an action matcher
// AND a run_pattern matcher for the same signature reports the action's
// higher confidence, not the weaker one — using a synthetic registry
// (not the real YAML) so this test stays independent of what the current
// production signatures happen to contain.
func TestMatchWorkflow_ActionMatchOutranksRunPatternMatch(t *testing.T) {
	reg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{
				ID:       "both",
				Name:     "Both",
				Category: CategorySAST,
				Detect: ScannerSignatureDetect{
					Actions:     []ActionMatcher{{Slug: "example/scanner-action"}},
					RunPatterns: []string{"scanner-cli"},
				},
				runPatternRegexps: []*regexp.Regexp{regexp.MustCompile("scanner-cli")},
			},
		},
	}
	wf := WorkflowFile{
		Jobs: map[string]WorkflowJob{
			"job": {Steps: []WorkflowStep{
				{Uses: "example/scanner-action@v1"},
				{Run: "scanner-cli scan ."},
			}},
		},
	}
	matches := reg.MatchWorkflow(wf)
	if len(matches) != 1 || matches[0].Confidence != ConfidenceHigh {
		t.Fatalf("MatchWorkflow = %+v, want exactly one match at high confidence", matches)
	}
}

// TestMatchWorkflow_ActionVersionConstraint proves an ActionMatcher with a
// non-empty Version only matches that exact ref, while an empty Version
// matches any ref — using a synthetic registry, same rationale as above.
func TestMatchWorkflow_ActionVersionConstraint(t *testing.T) {
	reg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{
				ID:       "pinned",
				Name:     "Pinned",
				Category: CategorySAST,
				Detect: ScannerSignatureDetect{
					Actions: []ActionMatcher{{Slug: "example/scanner-action", Version: "v2"}},
				},
			},
		},
	}

	v1 := WorkflowFile{Jobs: map[string]WorkflowJob{"job": {Steps: []WorkflowStep{{Uses: "example/scanner-action@v1"}}}}}
	if matches := reg.MatchWorkflow(v1); len(matches) != 0 {
		t.Errorf("MatchWorkflow(@v1) = %+v, want no match (constraint is @v2)", matches)
	}

	v2 := WorkflowFile{Jobs: map[string]WorkflowJob{"job": {Steps: []WorkflowStep{{Uses: "example/scanner-action@v2"}}}}}
	if matches := reg.MatchWorkflow(v2); len(matches) != 1 {
		t.Errorf("MatchWorkflow(@v2) = %+v, want exactly one match", matches)
	}
}

func TestSplitActionRef(t *testing.T) {
	tests := []struct {
		uses     string
		wantSlug string
		wantRef  string
	}{
		{"github/codeql-action/analyze@v4", "github/codeql-action/analyze", "v4"},
		{"actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "actions/checkout", "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"},
		{"no-at-sign", "no-at-sign", ""},
	}
	for _, tt := range tests {
		slug, ref := splitActionRef(tt.uses)
		if slug != tt.wantSlug || ref != tt.wantRef {
			t.Errorf("splitActionRef(%q) = (%q, %q), want (%q, %q)", tt.uses, slug, ref, tt.wantSlug, tt.wantRef)
		}
	}
}
