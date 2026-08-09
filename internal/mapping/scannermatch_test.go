package mapping

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
	{"syft.yaml", "syft", ConfidenceHigh},
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

// TestCategorySBOMNotYetConsumedByAnyCollector pins, with a real assertion
// rather than documentation alone, the claim scanner-signatures.yaml's
// sbom-category header comment makes: as of this writing, no collector
// filters ScannerMatch results down to CategorySBOM the way C05/C06/C07
// filter to CategorySAST/CategorySCA/CategoryProvenance — mirrors
// TestMatchWorkflow_DependabotExcludedFromWorkflowMatching's shape (a real
// check, not just a comment, so a change here forces the YAML comment to
// be revisited in the same diff rather than going stale silently).
//
// This package must never import internal/collect (mapping is upstream of
// collect in the dependency graph — every collector already imports
// mapping, so the reverse would cycle), so this walks internal/collect's
// own .go source as plain text instead of importing it, looking for any
// literal "CategorySBOM" reference. A false failure here (e.g. the string
// appearing only in a comment) is an acceptable, conservative outcome for
// a staleness tripwire — it forces a human to look, which is the point.
func TestCategorySBOMNotYetConsumedByAnyCollector(t *testing.T) {
	root := filepath.Join("..", "collect")
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++
		if bytes.Contains(data, []byte("CategorySBOM")) {
			t.Errorf("%s references mapping.CategorySBOM — a collector now appears to consume the sbom category, so scanner-signatures.yaml's \"no collector filters to CategorySBOM\" header comment (and this test) are stale and need updating together", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	// A missing root already fails loud above (filepath.WalkDir returns an
	// error). This catches the quieter case: the root exists but nothing
	// under it looks like Go source anymore (e.g. collectors moved out of
	// internal/collect while an empty/vestigial directory survived) — the
	// scan above would then trivially find zero "CategorySBOM" references
	// and pass for the wrong reason, exercising nothing.
	if scanned == 0 {
		t.Fatalf("walked %s but found no .go files — this test isn't exercising anything; internal/collect may have moved", root)
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

// TestMatchWorkflow_SyftCLIRequiresOutputFlag pins the syft run_pattern's
// deliberate design (see scanner-signatures.yaml's own comment on the
// entry): it requires an explicit -o/--output flag belonging to an actual
// syft invocation, not a bare mention of the tool name and not a flag
// belonging to some other command on the same line. syft's own default
// output (absent -o/--output) is a human-readable table, not an SBOM at
// all, and a naive pattern either missed real invocation syntax or matched
// prose/unrelated commands — this table is the empirical case list a PR
// #166 review round found by running candidate patterns against synthetic
// cases rather than just inspecting the regex, not by inspection alone.
func TestMatchWorkflow_SyftCLIRequiresOutputFlag(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}

	tests := []struct {
		name      string
		run       string
		wantMatch bool
	}{
		{"bare CLI invocation with -o flag matches", "syft alpine:latest -o cyclonedx-json", true},
		{"scan subcommand with --output flag matches", "syft scan dir:. --output spdx-json=sbom.json", true},
		{"packages alias with --output flag matches", "syft packages . --output json", true},
		{"-o=value equals form matches", "syft dir:. -o=json", true},
		{"install-script URL mention alone does not match", "curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin", false},
		{"bare invocation with no output flag does not match (default table output isn't an SBOM)", "syft alpine:latest", false},
		{"comment-style prose mentioning the tool does not match", "echo 'TODO: generate an SBOM with syft before release'", false},
		// Fully-concatenated -ovalue (no space, no =) is a deliberate,
		// documented non-goal — see the run_patterns comment on this entry
		// in scanner-signatures.yaml for why.
		{"-ovalue fully concatenated does not match (documented non-goal)", "syft dir:. -ojson > sbom.json", false},
		// False positives a review round found empirically: an unanchored
		// `.*` let ANY later -o/--output on the line satisfy the pattern,
		// regardless of which command it actually belonged to.
		{"install one-liner's own curl -o flag does not match", "curl -L https://github.com/anchore/syft/releases/download/v1.0.0/syft_1.0.0_linux_amd64.tar.gz -o syft.tgz", false},
		{"install-then-rename curl -o flag does not match", "curl -sSfL https://get.anchore.io/syft -o install-syft.sh && sh install-syft.sh", false},
		{"a fallback branch where syft is absent does not match", "command -v syft || cyclonedx-py requirements -o sbom.json", false},
		{"a comment mentioning syft with a different tool's --output does not match", "# install syft then run trivy image --format cyclonedx --output sbom.json", false},
		// Mutation-closing: --output-dir must not satisfy the flag class
		// just because it contains "--output" as a substring. (A prior
		// version of this table also carried a "--oom-kill-disable does
		// not match" case with the flag placed BEFORE "syft" in the
		// string — dropped in review: the flag search only ever looks
		// forward from an anchored "syft" match, so that case was true
		// under every mutation, including dropping the anchor entirely,
		// and proved nothing.)
		{"--output-dir does not match (not the SBOM-format flag)", "syft dir:. --output-dir /tmp", false},
		// Exclusion-class mutation kills — dropping \n from
		// [^|;&\n]* (letting the flag search cross into a later,
		// unrelated line) and widening it to .* (letting it cross a
		// same-line ;/&/| into a later, unrelated command) both survived
		// the suite otherwise; see
		// TestMatchWorkflow_SyftFlagSearchStopsAtCommandBoundary for the
		// dedicated cases (kept separate from this table since they need
		// their own doc comment explaining which mutation each one
		// kills).
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf := WorkflowFile{Jobs: map[string]WorkflowJob{"job": {Steps: []WorkflowStep{{Run: tt.run}}}}}
			matches := reg.MatchWorkflow(wf)
			got := false
			for _, m := range matches {
				if m.SignatureID == "syft" {
					got = true
					if m.Confidence != ConfidenceMedium {
						t.Errorf("syft matched at confidence %q, want medium", m.Confidence)
					}
				}
			}
			if got != tt.wantMatch {
				t.Errorf("MatchWorkflow(run=%q) matched syft = %v, want %v (matches: %+v)", tt.run, got, tt.wantMatch, matches)
			}
		})
	}
}

// TestMatchWorkflow_SyftMultiLineRunOnlyMatchesItsOwnLine proves the
// anchor (line start, or right after a ;/&/| separator) treats a genuine
// newline inside a multi-line `run: |` block as its own command boundary
// — the shape of both this file's real syft fixtures (an install line
// followed by the actual invocation on its own subsequent line).
func TestMatchWorkflow_SyftMultiLineRunOnlyMatchesItsOwnLine(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}

	tests := []struct {
		name      string
		run       string
		wantMatch bool
	}{
		{
			"install line then invocation on its own line matches",
			"curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin\nsyft dir:. -o spdx-json=sbom.spdx.json",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf := WorkflowFile{Jobs: map[string]WorkflowJob{"job": {Steps: []WorkflowStep{{Run: tt.run}}}}}
			matches := reg.MatchWorkflow(wf)
			got := false
			for _, m := range matches {
				if m.SignatureID == "syft" {
					got = true
				}
			}
			if got != tt.wantMatch {
				t.Errorf("MatchWorkflow(run=%q) matched syft = %v, want %v (matches: %+v)", tt.run, got, tt.wantMatch, matches)
			}
		})
	}
}

// TestMatchWorkflow_SyftFlagSearchStopsAtCommandBoundary is the syft
// run_pattern's exclusion class ([^|;&\n]*) getting its own dedicated
// coverage — a review round found the rest of this file's syft cases all
// stayed green under two mutations of it that would otherwise have gone
// undetected: dropping \n from the class (letting the flag search cross
// into an unrelated command on a LATER LINE) and widening the whole class
// to `.` (letting it cross a same-line ;/&/| into an unrelated command
// FURTHER ALONG THE SAME LINE — the exact unanchored-`.*` failure mode the
// very first review round of this signature already flagged once). Each
// case below is paired with which mutation it kills.
func TestMatchWorkflow_SyftFlagSearchStopsAtCommandBoundary(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}

	tests := []struct {
		name string
		run  string
	}{
		// Kills: \n dropped from the exclusion class. syft runs with no
		// flag of its own on its own line; a completely different tool's
		// -o flag on the NEXT line must not satisfy the pattern.
		{"unrelated tool's flag on a later line does not match", "syft --version\ntrivy image -o sbom.json"},
		// Kills: exclusion class widened to `.` (unanchored .* again).
		// Both real shell command separators (&& and ;) are covered
		// since they're independent characters in the class.
		{"unrelated tool's flag after && on the same line does not match", "syft version && grype dir:. -o json"},
		{"unrelated tool's flag after ; on the same line does not match", "syft --help; trivy image --output sbom.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wf := WorkflowFile{Jobs: map[string]WorkflowJob{"job": {Steps: []WorkflowStep{{Run: tt.run}}}}}
			matches := reg.MatchWorkflow(wf)
			for _, m := range matches {
				if m.SignatureID == "syft" {
					t.Errorf("MatchWorkflow(run=%q) unexpectedly matched syft via a flag belonging to a different command (matches: %+v)", tt.run, matches)
				}
			}
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
