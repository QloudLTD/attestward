package mapping

import (
	"os"
	"regexp"
	"testing"
)

// mustRegexp compiles pattern for use in a synthetic ScannerSignature's
// pre-compiled regexp fields (normally populated by decodeScannerSignatures
// at load time) — mirrors scannermatch_test.go's identical inline use of
// regexp.MustCompile for its own synthetic registries.
func mustRegexp(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("regexp.Compile(%q): %v", pattern, err)
	}
	return re
}

// TestMatchPipeline_TaskMatchCaseInsensitivityAndMajorPinning is the
// issue's own acceptance criterion for the ado_tasks matcher: task-name
// matching is case-insensitive, an explicit major pins to that exact
// version, and an absent major matches any version. Synthetic registries
// (not the real YAML — #149 adds only the schema+matcher; no signature in
// mappings/scanner-signatures.yaml has an ado_tasks entry yet, that lands
// with #34's follow-on stories).
func TestMatchPipeline_TaskMatchCaseInsensitivityAndMajorPinning(t *testing.T) {
	pinnedReg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{
				ID:       "pinned",
				Name:     "Pinned",
				Category: CategorySCA,
				Detect:   ScannerSignatureDetect{ADOTasks: []ADOTaskMatcher{{Task: "SnykSecurityScan", Major: "1"}}},
			},
		},
	}
	anyMajorReg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{
				ID:       "any-major",
				Name:     "Any Major",
				Category: CategorySCA,
				Detect:   ScannerSignatureDetect{ADOTasks: []ADOTaskMatcher{{Task: "SnykSecurityScan"}}},
			},
		},
	}

	tests := []struct {
		name      string
		reg       *ScannerSignatureRegistry
		taskRef   string
		wantMatch bool
	}{
		{"exact case, pinned major matches", pinnedReg, "SnykSecurityScan@1", true},
		{"different case, pinned major still matches (case-insensitive task name)", pinnedReg, "snyksecurityscAN@1", true},
		{"pinned major, mismatched major does not match", pinnedReg, "SnykSecurityScan@2", false},
		{"pinned major, full version pin (major.minor.patch) still matches on the major segment", pinnedReg, "SnykSecurityScan@1.2.3", true},
		{"pinned major, full version pin with a different major does not match", pinnedReg, "SnykSecurityScan@2.0.0", false},
		{"absent-major matcher matches any explicit major", anyMajorReg, "SnykSecurityScan@3", true},
		{"absent-major matcher matches with no major at all", anyMajorReg, "SnykSecurityScan", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl := PipelineFile{Steps: []PipelineStep{{Task: tt.taskRef}}}
			matches, unresolved := tt.reg.MatchPipeline(pl)
			if len(unresolved) != 0 {
				t.Errorf("unresolved = %+v, want none", unresolved)
			}
			if tt.wantMatch {
				if len(matches) != 1 || matches[0].Confidence != ConfidenceHigh {
					t.Fatalf("MatchPipeline(task=%q) = %+v, want exactly one high-confidence match", tt.taskRef, matches)
				}
			} else if len(matches) != 0 {
				t.Fatalf("MatchPipeline(task=%q) = %+v, want no match", tt.taskRef, matches)
			}
		})
	}
}

// TestMatchPipeline_FullyQualifiedOrGUIDTaskRefDoesNotCrossMatchShortName
// pins the deliberate non-goal documented on ADOTaskMatcher: a
// fully-qualified marketplace task reference
// (publisherId.extensionId.taskName@version) or a bare task GUID must NOT
// cross-match a matcher written against the short task name, since two
// different publishers can share a bare task name — cross-matching would
// violate the registry's per-signature accuracy standard. This is
// intentionally NOT loosened by dot-segment splitting.
func TestMatchPipeline_FullyQualifiedOrGUIDTaskRefDoesNotCrossMatchShortName(t *testing.T) {
	reg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{ID: "short-name", Name: "Short Name", Category: CategorySAST, Detect: ScannerSignatureDetect{ADOTasks: []ADOTaskMatcher{{Task: "codeql-init"}}}},
		},
	}
	tests := []struct {
		name    string
		taskRef string
	}{
		{"fully-qualified marketplace form", "SomePublisher.SomeExtension.codeql-init@1"},
		{"bare task GUID", "00000000-0000-0000-0000-000000000000@1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl := PipelineFile{Steps: []PipelineStep{{Task: tt.taskRef}}}
			matches, _ := reg.MatchPipeline(pl)
			if len(matches) != 0 {
				t.Errorf("MatchPipeline(task=%q) = %+v, want no match (must not cross-match the short-name matcher)", tt.taskRef, matches)
			}
		})
	}
}

// TestMatchPipeline_StepsFoundAtAllNestingLevels proves steps are found
// wherever Azure Pipelines allows them: directly at the top level, nested
// under a job, and nested under a job nested under a stage — three
// distinct signatures, one per level, so each nesting level's contribution
// is independently verifiable.
func TestMatchPipeline_StepsFoundAtAllNestingLevels(t *testing.T) {
	reg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{ID: "top-level", Name: "Top Level", Category: CategorySAST, Detect: ScannerSignatureDetect{ADOTasks: []ADOTaskMatcher{{Task: "TaskA"}}}},
			{ID: "job-level", Name: "Job Level", Category: CategorySAST, Detect: ScannerSignatureDetect{ADOTasks: []ADOTaskMatcher{{Task: "TaskB"}}}},
			{ID: "stage-level", Name: "Stage Level", Category: CategorySAST, Detect: ScannerSignatureDetect{ADOTasks: []ADOTaskMatcher{{Task: "TaskC"}}}},
		},
	}
	raw := []byte(`
name: multi-level pipeline
steps:
  - task: TaskA@1
jobs:
  - job: buildJob
    steps:
      - task: TaskB@1
stages:
  - stage: buildStage
    jobs:
      - job: stageJob
        steps:
          - task: TaskC@1
`)
	pl, err := ParsePipelineFile(raw)
	if err != nil {
		t.Fatalf("ParsePipelineFile: %v", err)
	}
	matches, unresolved := reg.MatchPipeline(pl)
	if len(unresolved) != 0 {
		t.Errorf("unresolved = %+v, want none", unresolved)
	}

	byID := map[string]ScannerMatch{}
	for _, m := range matches {
		byID[m.SignatureID] = m
	}
	for _, id := range []string{"top-level", "job-level", "stage-level"} {
		if m, ok := byID[id]; !ok {
			t.Errorf("expected signature %q to match (matches: %+v)", id, matches)
		} else if m.Confidence != ConfidenceHigh {
			t.Errorf("signature %q matched at confidence %q, want high", id, m.Confidence)
		}
	}
}

// TestMatchPipeline_RunPatternMatchesInlineShellSteps proves run_patterns
// fires against each of Azure Pipelines' four inline-shell step shorthands
// (script/bash/pwsh/powershell), not just one of them.
func TestMatchPipeline_RunPatternMatchesInlineShellSteps(t *testing.T) {
	reg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{
				ID:                "trivy-like",
				Name:              "Trivy-like",
				Category:          CategorySCA,
				Detect:            ScannerSignatureDetect{RunPatterns: []string{"\\btrivy\\b"}},
				runPatternRegexps: []*regexp.Regexp{mustRegexp(t, "\\btrivy\\b")},
			},
		},
	}
	tests := []struct {
		name string
		step PipelineStep
	}{
		{"script", PipelineStep{Script: "trivy image myimage"}},
		{"bash", PipelineStep{Bash: "trivy image myimage"}},
		{"pwsh", PipelineStep{Pwsh: "trivy image myimage"}},
		{"powershell", PipelineStep{PowerShell: "trivy image myimage"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pl := PipelineFile{Steps: []PipelineStep{tt.step}}
			matches, unresolved := reg.MatchPipeline(pl)
			if len(unresolved) != 0 {
				t.Errorf("unresolved = %+v, want none", unresolved)
			}
			if len(matches) != 1 || matches[0].Confidence != ConfidenceMedium {
				t.Fatalf("MatchPipeline(%+v) = %+v, want exactly one medium-confidence match", tt.step, matches)
			}
		})
	}
}

// TestMatchPipeline_TemplateRefsRecordedUnresolvedNotDropped proves a
// `template:` reference at any of the three positions it can appear
// (step, job entry, stage entry) is surfaced as an UnresolvedTemplateRef
// rather than silently vanishing, and that its presence doesn't block a
// real, inspectable match elsewhere in the same file.
func TestMatchPipeline_TemplateRefsRecordedUnresolvedNotDropped(t *testing.T) {
	raw := []byte(`
name: templated pipeline
steps:
  - template: templates/step-template.yml
jobs:
  - template: templates/job-template.yml
  - job: realJob
    steps:
      - task: RealTask@1
stages:
  - template: templates/stage-template.yml
  - stage: realStage
    jobs:
      - job: realStageJob
        steps:
          - task: RealTask@1
`)
	pl, err := ParsePipelineFile(raw)
	if err != nil {
		t.Fatalf("ParsePipelineFile: %v", err)
	}
	reg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{ID: "real", Name: "Real", Category: CategorySAST, Detect: ScannerSignatureDetect{ADOTasks: []ADOTaskMatcher{{Task: "RealTask"}}}},
		},
	}
	matches, unresolved := reg.MatchPipeline(pl)

	wantRefs := map[string]bool{
		"templates/step-template.yml":  true,
		"templates/job-template.yml":   true,
		"templates/stage-template.yml": true,
	}
	if len(unresolved) != len(wantRefs) {
		t.Fatalf("unresolved = %+v, want exactly %d entries", unresolved, len(wantRefs))
	}
	for _, u := range unresolved {
		if !wantRefs[u.Ref] {
			t.Errorf("unexpected unresolved ref %q", u.Ref)
		}
	}

	if len(matches) != 1 || matches[0].SignatureID != "real" {
		t.Errorf("matches = %+v, want exactly the real task match (template refs must not block real content from matching)", matches)
	}
}

// TestMatchPipeline_ExtendsTemplateRecordedUnresolved proves a root-level
// `extends:` block (Microsoft's mandated-template pattern — the entire
// pipeline body supplied by another file, with no Steps/Jobs/Stages of its
// own present at all) is recorded as an UnresolvedTemplateRef exactly like
// a step/job/stage-level `template:` reference, rather than silently
// producing zero matches AND zero unresolved refs — which would look
// indistinguishable from "this pipeline genuinely has no scanner", the
// exact silent-partial-view UnresolvedTemplateRef exists to prevent.
func TestMatchPipeline_ExtendsTemplateRecordedUnresolved(t *testing.T) {
	raw := []byte(`
name: extends-only pipeline
extends:
  template: v1/pipeline.yml@templates
`)
	pl, err := ParsePipelineFile(raw)
	if err != nil {
		t.Fatalf("ParsePipelineFile: %v", err)
	}
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}
	matches, unresolved := reg.MatchPipeline(pl)
	if len(matches) != 0 {
		t.Errorf("matches = %+v, want none (an extends-only pipeline has no inspectable content of its own)", matches)
	}
	if len(unresolved) != 1 || unresolved[0].Ref != "v1/pipeline.yml@templates" {
		t.Fatalf("unresolved = %+v, want exactly one entry for the extends: template", unresolved)
	}
}

// TestParsePipelineFile_MalformedYAMLReturnsErrorNotPanic proves a genuine
// YAML syntax error (here: a tab character, illegal for YAML indentation)
// is reported as an error rather than panicking — mirrors
// ParseWorkflowFile's identical contract for GitHub Actions content.
func TestParsePipelineFile_MalformedYAMLReturnsErrorNotPanic(t *testing.T) {
	_, err := ParsePipelineFile([]byte("steps:\n\t- task: Foo@1\n"))
	if err == nil {
		t.Fatal("expected an error for malformed (tab-indented) YAML, got nil")
	}
}

// TestParsePipelineFile_GitHubWorkflowJobsMapProducesErrorNotPanic feeds a
// real GitHub Actions workflow fixture (whose `jobs:` is a mapping keyed by
// job ID) through ParsePipelineFile, whose PipelineFile.Jobs is a list —
// Azure Pipelines' actual shape. The type mismatch is a clean decode error,
// not a panic, and — since parsing fails — trivially cannot produce a
// false ado_tasks match either.
func TestParsePipelineFile_GitHubWorkflowJobsMapProducesErrorNotPanic(t *testing.T) {
	data, err := os.ReadFile("testdata/workflows/codeql.yaml")
	if err != nil {
		t.Fatalf("read testdata/workflows/codeql.yaml: %v", err)
	}
	if _, err := ParsePipelineFile(data); err == nil {
		t.Fatal("expected an error parsing a GitHub Actions workflow (jobs: map) as an Azure Pipelines file, got nil")
	}
}

// TestMatchPipeline_GitHubStyleStepKeysDoNotFalseMatch proves that
// GitHub-flavored step keys (`uses:`, `run:`, a step's own `name:`) placed
// where Azure Pipelines syntax would allow a step list (so parsing itself
// succeeds) are simply ignored, not misread as an ado_tasks/run_pattern/
// name_pattern signal — PipelineStep has no `uses`/`run`/`name` yaml tags,
// only `task`/`script`|`bash`|`pwsh`|`powershell`/`displayName`. Uses the
// real registry deliberately: it proves the production signatures (whose
// run_patterns/workflow_name_patterns would fire on "snyk" if the matcher
// were reading the wrong fields) genuinely don't cross-fire on GitHub
// content mistakenly run through the ADO matcher.
func TestMatchPipeline_GitHubStyleStepKeysDoNotFalseMatch(t *testing.T) {
	raw := []byte(`
name: GH-flavored content under an ADO-shaped steps list
steps:
  - uses: github/codeql-action/analyze@v4
    run: snyk test
    name: looks like snyk
`)
	pl, err := ParsePipelineFile(raw)
	if err != nil {
		t.Fatalf("ParsePipelineFile: %v", err)
	}
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}
	matches, unresolved := reg.MatchPipeline(pl)
	if len(matches) != 0 {
		t.Errorf("matches = %+v, want none (uses:/run:/name: are GitHub-shaped keys with no Azure Pipelines equivalent field read here)", matches)
	}
	if len(unresolved) != 0 {
		t.Errorf("unresolved = %+v, want none", unresolved)
	}
}

// TestMatchPipeline_ConfidenceLadder proves ado_tasks outranks
// run_patterns even when both match the same signature — the same
// priority MatchWorkflow's actions gives over run_patterns.
func TestMatchPipeline_ConfidenceLadder(t *testing.T) {
	reg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{
				ID:       "layered",
				Name:     "Layered",
				Category: CategorySAST,
				Detect: ScannerSignatureDetect{
					ADOTasks:             []ADOTaskMatcher{{Task: "LayeredTask"}},
					RunPatterns:          []string{"layered-cli"},
					WorkflowNamePatterns: []string{"(?i)layered"},
				},
				runPatternRegexps:          []*regexp.Regexp{mustRegexp(t, "layered-cli")},
				workflowNamePatternRegexps: []*regexp.Regexp{mustRegexp(t, "(?i)layered")},
			},
		},
	}
	pl := PipelineFile{
		Name: "layered pipeline",
		Steps: []PipelineStep{
			{Task: "LayeredTask@1"},
			{Script: "layered-cli scan"},
		},
	}
	matches, _ := reg.MatchPipeline(pl)
	if len(matches) != 1 || matches[0].Confidence != ConfidenceHigh {
		t.Fatalf("MatchPipeline = %+v, want exactly one high-confidence match (ado_tasks outranks run_patterns and workflow_name_patterns)", matches)
	}
}

// TestMatchPipeline_RunPatternOutranksNamePattern proves run_patterns
// outranks workflow_name_patterns when no ado_tasks matcher is present —
// mirroring MatchWorkflow's run_patterns-over-workflow_name_patterns
// priority.
func TestMatchPipeline_RunPatternOutranksNamePattern(t *testing.T) {
	reg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{
				ID:       "layered2",
				Name:     "Layered2",
				Category: CategorySAST,
				Detect: ScannerSignatureDetect{
					RunPatterns:          []string{"layered-cli"},
					WorkflowNamePatterns: []string{"(?i)layered"},
				},
				runPatternRegexps:          []*regexp.Regexp{mustRegexp(t, "layered-cli")},
				workflowNamePatternRegexps: []*regexp.Regexp{mustRegexp(t, "(?i)layered")},
			},
		},
	}
	pl := PipelineFile{
		Name:  "layered pipeline",
		Steps: []PipelineStep{{Script: "layered-cli scan"}},
	}
	matches, _ := reg.MatchPipeline(pl)
	if len(matches) != 1 || matches[0].Confidence != ConfidenceMedium {
		t.Fatalf("MatchPipeline = %+v, want exactly one medium-confidence match (run_patterns outranks workflow_name_patterns)", matches)
	}
}

// TestMatchPipeline_NamePatternMatchesPipelineNameAndStepDisplayName proves
// workflow_name_patterns is checked against both the pipeline's own
// `name:` and each step's `displayName:` — the two ADO-side surfaces the
// issue scopes this matcher to (job/stage names are deliberately out of
// scope).
func TestMatchPipeline_NamePatternMatchesPipelineNameAndStepDisplayName(t *testing.T) {
	reg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{
				ID:                         "slsa-like",
				Name:                       "SLSA-like",
				Category:                   CategoryProvenance,
				Detect:                     ScannerSignatureDetect{WorkflowNamePatterns: []string{"(?i)\\bslsa\\b"}},
				workflowNamePatternRegexps: []*regexp.Regexp{mustRegexp(t, "(?i)\\bslsa\\b")},
			},
		},
	}
	tests := []struct {
		name string
		pl   PipelineFile
	}{
		{"pipeline name matches", PipelineFile{Name: "SLSA provenance"}},
		{"step displayName matches", PipelineFile{Steps: []PipelineStep{{Script: "echo hi", DisplayName: "Generate SLSA attestation"}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, _ := reg.MatchPipeline(tt.pl)
			if len(matches) != 1 || matches[0].Confidence != ConfidenceLow {
				t.Fatalf("MatchPipeline(%+v) = %+v, want exactly one low-confidence match", tt.pl, matches)
			}
		})
	}
}

// TestMatchPipeline_EmptyPipelineMatchesNothing proves the matcher doesn't
// false-positive on a pipeline with no recognizable content — using the
// real registry, mirroring TestMatchWorkflow_EmptyWorkflowMatchesNothing.
func TestMatchPipeline_EmptyPipelineMatchesNothing(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}
	matches, unresolved := reg.MatchPipeline(PipelineFile{Name: "unrelated pipeline"})
	if len(matches) != 0 {
		t.Errorf("matches = %+v, want none", matches)
	}
	if len(unresolved) != 0 {
		t.Errorf("unresolved = %+v, want none", unresolved)
	}
}

// TestMatchPipeline_DeploymentJobStepsNotTraversed pins the known,
// documented gap described on PipelineJobEntry and MatchPipeline: a
// deployment job's steps (nested under strategy.runOnce.deploy.steps)
// are invisible to this matcher — no match, but also no
// UnresolvedTemplateRef, since PipelineJobEntry has no field to recognize
// a deployment job by at all. This test exists so a future change to this
// behavior (in either direction) is a deliberate, reviewed decision rather
// than an unnoticed regression.
func TestMatchPipeline_DeploymentJobStepsNotTraversed(t *testing.T) {
	raw := []byte(`
name: deployment job pipeline
jobs:
  - deployment: DeployWeb
    environment: production
    strategy:
      runOnce:
        deploy:
          steps:
            - task: RealTask@1
`)
	pl, err := ParsePipelineFile(raw)
	if err != nil {
		t.Fatalf("ParsePipelineFile: %v", err)
	}
	reg := &ScannerSignatureRegistry{
		Signatures: []ScannerSignature{
			{ID: "real", Name: "Real", Category: CategorySAST, Detect: ScannerSignatureDetect{ADOTasks: []ADOTaskMatcher{{Task: "RealTask"}}}},
		},
	}
	matches, unresolved := reg.MatchPipeline(pl)
	if len(matches) != 0 {
		t.Errorf("matches = %+v, want none — a deployment job's steps are not traversed by this version of MatchPipeline", matches)
	}
	if len(unresolved) != 0 {
		t.Errorf("unresolved = %+v, want none — a deployment job has no template: field for MatchPipeline to flag as unresolved", unresolved)
	}
}

func TestSplitADOTaskRef(t *testing.T) {
	tests := []struct {
		taskRef     string
		wantName    string
		wantVersion string
	}{
		{"SnykSecurityScan@1", "SnykSecurityScan", "1"},
		{"AdvancedSecurity-Codeql-Init@1", "AdvancedSecurity-Codeql-Init", "1"},
		{"no-at-sign", "no-at-sign", ""},
		{"Foo@Bar@2", "Foo@Bar", "2"},
		{"GoTool@0.3.1", "GoTool", "0.3.1"},
	}
	for _, tt := range tests {
		name, version := splitADOTaskRef(tt.taskRef)
		if name != tt.wantName || version != tt.wantVersion {
			t.Errorf("splitADOTaskRef(%q) = (%q, %q), want (%q, %q)", tt.taskRef, name, version, tt.wantName, tt.wantVersion)
		}
	}
}

// TestAdoTaskMajorSegment proves the major-version segment extracted for
// comparison is the text before the first `.` of the post-`@` version — so
// a full version pin (Microsoft's own docs use forms like "GoTool@0.3.1")
// still resolves to the same major a bare "@1"-style pin would.
func TestAdoTaskMajorSegment(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"1", "1"},
		{"1.2.3", "1"},
		{"0.3.1", "0"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := adoTaskMajorSegment(tt.version); got != tt.want {
			t.Errorf("adoTaskMajorSegment(%q) = %q, want %q", tt.version, got, tt.want)
		}
	}
}

// pipelineFixtureExpectations is the Azure Pipelines counterpart to
// scannermatch_test.go's fixtureExpectations: for every ado_tasks-detectable
// signature (codeql, ghazdo-dependency-scanning, snyk, sonarqube — the
// latter with two fixtures, one per distinct task family it detects, see
// sonarcloud.yaml below), plus the CLI-driven tools whose existing
// run_patterns are exercised only via an ADO script/bash/pwsh/powershell
// step since they have no ado_tasks of their own (trivy, cosign,
// osv-scanner — syft has no existing signature in this registry to attach
// a fixture to, so it's not included here; see #149's PR description),
// its fixture pipeline file and the confidence its detect block should
// match at.
var pipelineFixtureExpectations = []struct {
	fixture         string
	wantSignatureID string
	wantConfidence  MatchConfidence
}{
	{"codeql.yaml", "codeql", ConfidenceHigh},
	{"ghazdo-dependency-scanning.yaml", "ghazdo-dependency-scanning", ConfidenceHigh},
	{"snyk.yaml", "snyk", ConfidenceHigh},
	{"sonarqube.yaml", "sonarqube", ConfidenceHigh},
	// SonarQube Cloud (SonarCloudPrepare/Analyze) is a genuinely different
	// task family from SonarQube Server's, not a version difference of it
	// (issue #167) — its own fixture, same "sonarqube" signature ID.
	{"sonarcloud.yaml", "sonarqube", ConfidenceHigh},
	{"trivy.yaml", "trivy", ConfidenceMedium},
	{"cosign.yaml", "cosign", ConfidenceMedium},
	{"osv-scanner.yaml", "osv-scanner", ConfidenceMedium},
}

func loadFixturePipeline(t *testing.T, name string) PipelineFile {
	t.Helper()
	data, err := os.ReadFile("testdata/pipelines/" + name)
	if err != nil {
		t.Fatalf("read testdata/pipelines/%s: %v", name, err)
	}
	pl, err := ParsePipelineFile(data)
	if err != nil {
		t.Fatalf("parse testdata/pipelines/%s: %v", name, err)
	}
	return pl
}

// TestMatchPipeline_CrossMatrix is scanner-signatures.yaml's own accuracy
// standard, extended to Azure Pipelines: for each fixture, asserts its own
// signature matches at the expected confidence, and that no OTHER
// signature in the FULL registry also fires against it — not just the
// other entries in pipelineFixtureExpectations. On the GitHub side,
// TestMatchWorkflow_CrossMatrix's identical-looking inner loop gets full
// registry coverage for free, because
// TestFixtureExpectationsCoverAllDetectableSignatures requires every
// workflow-detectable signature to already be in fixtureExpectations; the
// ADO side has no equivalent guarantee (most signatures are
// cross-platform via run_patterns/workflow_name_patterns without an
// ado_tasks entry or a dedicated pipeline fixture of their own), so this
// loop checks reg.Signatures directly instead.
func TestMatchPipeline_CrossMatrix(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}

	for _, tc := range pipelineFixtureExpectations {
		t.Run(tc.fixture, func(t *testing.T) {
			pl := loadFixturePipeline(t, tc.fixture)
			matches, unresolved := reg.MatchPipeline(pl)
			if len(unresolved) != 0 {
				t.Errorf("unresolved = %+v, want none (these fixtures contain no template:/extends: refs)", unresolved)
			}

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

			for _, other := range reg.Signatures {
				if other.ID == tc.wantSignatureID {
					continue
				}
				if m, matched := byID[other.ID]; matched {
					t.Errorf("%s unexpectedly also matched signature %q (cross-contamination): %+v", tc.fixture, other.ID, m)
				}
			}
		})
	}
}

// TestPipelineFixtureExpectationsCoverAllADOTaskSignatures enforces the
// same invariant TestFixtureExpectationsCoverAllDetectableSignatures does
// for GitHub Actions: every registry signature with a non-empty ado_tasks
// block must have a pipelineFixtureExpectations entry, so a future
// ado_tasks addition without a matching fixture doesn't pass every
// existing test untested.
func TestPipelineFixtureExpectationsCoverAllADOTaskSignatures(t *testing.T) {
	reg, err := LoadScannerSignatures("../../mappings/scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignatures: %v", err)
	}

	covered := map[string]bool{}
	for _, tc := range pipelineFixtureExpectations {
		covered[tc.wantSignatureID] = true
	}

	for _, sig := range reg.Signatures {
		if len(sig.Detect.ADOTasks) > 0 && !covered[sig.ID] {
			t.Errorf("signature %q has a non-empty ado_tasks block but no pipelineFixtureExpectations entry — add a fixture pipeline under testdata/pipelines/ and a table entry", sig.ID)
		}
	}
}
