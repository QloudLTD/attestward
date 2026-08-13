package cihistory

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect/gitlab/gitlabfixture"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/mappings"
	"gopkg.in/yaml.v3"
)

func loadRegistry(t *testing.T) *mapping.ScannerSignatureRegistry {
	t.Helper()
	reg, err := mapping.LoadScannerSignaturesFS(mappings.FS, "scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("load scanner signatures: %v", err)
	}
	return reg
}

// recordedMergedYAML returns the merged CI configuration from the recorded
// lint of a project running GitLab's stock SAST, Dependency Scanning and
// Secret Detection templates.
func recordedMergedYAML(t *testing.T) string {
	t.Helper()
	var lint CILintResponse
	if err := json.Unmarshal(gitlabfixture.MustLoad(t, "ci-lint-security-templates.json"), &lint); err != nil {
		t.Fatalf("decode ci-lint fixture: %v", err)
	}
	if lint.MergedYAML == "" {
		t.Fatal("ci-lint fixture has an empty merged_yaml, so every assertion below would be vacuous")
	}
	return lint.MergedYAML
}

func jobNames(jobs []ScannerJob) []string {
	out := make([]string, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.Name)
	}
	sort.Strings(out)
	return out
}

// -----------------------------------------------------------------------
// merged-configuration matching, against the real recorded response
// -----------------------------------------------------------------------

// TestStockSASTTemplateMatchesOnlyRunnableAnalyzers is the central test of
// this package. In the live configuration this fixture was cut from, GitLab's
// stock SAST template declared `artifacts: reports: sast:` on twenty-one
// entries and only eight of them could ever run — the other thirteen were two
// hidden anchors (".sast-analyzer", ".deprecated-16.8") and eleven entries
// permanently disabled with `rules: [{when: never}]` (the `sast`
// configuration-only stub plus ten retired analyzers). A matcher that counted
// the declaration alone would credit every project including the template
// with thirteen scanners it does not have.
//
// The fixture keeps one of each kind (semgrep-sast and gitlab-advanced-sast
// runnable, bandit-sast disabled, .sast-analyzer hidden, `sast` the
// configuration-only stub) rather than all twenty-one, so the discrimination
// stays visible without carrying 27 KB of template.
func TestStockSASTTemplateMatchesOnlyRunnableAnalyzers(t *testing.T) {
	jobs, ok := MatchMergedConfig(recordedMergedYAML(t), ReportTypeSAST, mapping.CategorySAST, loadRegistry(t))
	if !ok {
		t.Fatal("MatchMergedConfig reported the recorded merged configuration unparseable")
	}
	want := []string{"gitlab-advanced-sast", "semgrep-sast"}
	if got := jobNames(jobs); !reflect.DeepEqual(got, want) {
		t.Errorf("matched SAST jobs = %v, want %v", got, want)
	}
	for _, j := range jobs {
		if j.Confidence != ConfidenceHigh {
			t.Errorf("%s confidence = %q, want high — the report declaration is GitLab's own contract", j.Name, j.Confidence)
		}
		if j.MatchedOn != "artifacts.reports.sast" {
			t.Errorf("%s matched_on = %q", j.Name, j.MatchedOn)
		}
	}
}

// TestDisabledAndHiddenSASTJobsAreExcludedByName names the entries the test
// above excludes only implicitly. Without this, narrowing the matcher (e.g.
// dropping the hidden-job skip) could still pass the DeepEqual above if the
// exclusion moved rather than disappeared.
func TestDisabledAndHiddenSASTJobsAreExcludedByName(t *testing.T) {
	jobs, _ := MatchMergedConfig(recordedMergedYAML(t), ReportTypeSAST, mapping.CategorySAST, loadRegistry(t))
	matched := map[string]bool{}
	for _, j := range jobs {
		matched[j.Name] = true
	}
	for _, excluded := range []string{
		".sast-analyzer", // a hidden anchor other jobs extend
		"sast",           // the configuration-only stub, rules: [{when: never}]
		"bandit-sast",    // a retired analyzer, rules: [{when: never}]
	} {
		if matched[excluded] {
			t.Errorf("%q was matched as a runnable SAST job", excluded)
		}
	}
}

// TestSecretDetectionIsNotSASTOrSCA pins the category boundary: the recorded
// configuration also runs Secret Detection, which is C04's subject. A
// project running ONLY secret detection must not read as having either of
// this build's two scanners.
func TestSecretDetectionIsNotSASTOrSCA(t *testing.T) {
	reg := loadRegistry(t)
	merged := recordedMergedYAML(t)
	for _, tc := range []struct {
		reportType string
		category   mapping.ScannerCategory
	}{
		{ReportTypeSAST, mapping.CategorySAST},
		{ReportTypeDependencyScanning, mapping.CategorySCA},
	} {
		jobs, _ := MatchMergedConfig(merged, tc.reportType, tc.category, reg)
		for _, j := range jobs {
			if j.Name == "secret_detection" {
				t.Errorf("secret_detection matched as a %s scanner", tc.reportType)
			}
		}
	}
}

func TestStockDependencyScanningTemplateMatchesItsAnalyzers(t *testing.T) {
	jobs, ok := MatchMergedConfig(recordedMergedYAML(t), ReportTypeDependencyScanning, mapping.CategorySCA, loadRegistry(t))
	if !ok {
		t.Fatal("MatchMergedConfig reported the recorded merged configuration unparseable")
	}
	want := []string{"gemnasium-dependency_scanning", "gemnasium-maven-dependency_scanning"}
	if got := jobNames(jobs); !reflect.DeepEqual(got, want) {
		t.Errorf("matched dependency-scanning jobs = %v, want %v", got, want)
	}
}

// -----------------------------------------------------------------------
// the confidence ladder
// -----------------------------------------------------------------------

func TestConfidenceLadder(t *testing.T) {
	reg := loadRegistry(t)
	cases := []struct {
		name           string
		merged         string
		wantJob        string
		wantConfidence Confidence
		wantMatchedOn  string
	}{
		{
			name:           "a report declaration is high confidence",
			merged:         "scan:\n  script:\n  - ./whatever\n  artifacts:\n    reports:\n      sast: gl-sast-report.json\n",
			wantJob:        "scan",
			wantConfidence: ConfidenceHigh,
			wantMatchedOn:  "artifacts.reports.sast",
		},
		{
			name:           "a CLI invocation with no report declaration is medium confidence",
			merged:         "audit:\n  script:\n  - semgrep --config auto\n",
			wantJob:        "audit",
			wantConfidence: ConfidenceMedium,
			wantMatchedOn:  `run_pattern:\bsemgrep\b`,
		},
		{
			name:           "a suggestive job name alone is low confidence",
			merged:         "semgrep:\n  script:\n  - make check\n",
			wantJob:        "semgrep",
			wantConfidence: ConfidenceLow,
			wantMatchedOn:  `job_name_pattern:(?i)\bsemgrep\b`,
		},
		{
			name:           "before_script counts as invocation text too",
			merged:         "audit:\n  before_script:\n  - semgrep --config auto\n  script:\n  - true\n",
			wantJob:        "audit",
			wantConfidence: ConfidenceMedium,
			wantMatchedOn:  `run_pattern:\bsemgrep\b`,
		},
		{
			name:           "a scalar script is read, not silently dropped",
			merged:         "audit:\n  script: semgrep --config auto\n",
			wantJob:        "audit",
			wantConfidence: ConfidenceMedium,
			wantMatchedOn:  `run_pattern:\bsemgrep\b`,
		},
		{
			name:           "a nested script list is flattened, not silently dropped",
			merged:         "audit:\n  script:\n  - - semgrep --config auto\n    - echo done\n",
			wantJob:        "audit",
			wantConfidence: ConfidenceMedium,
			wantMatchedOn:  `run_pattern:\bsemgrep\b`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jobs, ok := MatchMergedConfig(tc.merged, ReportTypeSAST, mapping.CategorySAST, reg)
			if !ok {
				t.Fatal("reported unparseable")
			}
			if len(jobs) != 1 {
				t.Fatalf("matched %d jobs, want exactly 1: %+v", len(jobs), jobs)
			}
			if jobs[0].Name != tc.wantJob || jobs[0].Confidence != tc.wantConfidence || jobs[0].MatchedOn != tc.wantMatchedOn {
				t.Errorf("got %+v, want job=%q confidence=%q matched_on=%q",
					jobs[0], tc.wantJob, tc.wantConfidence, tc.wantMatchedOn)
			}
		})
	}
}

// TestSCACLIToolIsMatchedForItsOwnCategoryOnly guards the category filter on
// the two registry-driven tiers: `snyk test` is an SCA signature, so it must
// not surface as a SAST match.
func TestSCACLIToolIsMatchedForItsOwnCategoryOnly(t *testing.T) {
	reg := loadRegistry(t)
	const merged = "deps:\n  script:\n  - snyk test --all-projects\n"

	sca, _ := MatchMergedConfig(merged, ReportTypeDependencyScanning, mapping.CategorySCA, reg)
	if len(sca) != 1 || sca[0].Confidence != ConfidenceMedium || sca[0].Tool != "Snyk" {
		t.Fatalf("SCA match = %+v, want one medium-confidence Snyk match", sca)
	}
	if sast, _ := MatchMergedConfig(merged, ReportTypeSAST, mapping.CategorySAST, reg); len(sast) != 0 {
		t.Errorf("SAST match = %+v, want none — snyk is an SCA signature", sast)
	}
}

func TestUnparseableMergedConfigIsReportedNotSilentlyEmpty(t *testing.T) {
	reg := loadRegistry(t)
	if _, ok := MatchMergedConfig("\tnot: [valid\n  yaml", ReportTypeSAST, mapping.CategorySAST, reg); ok {
		t.Error("unparseable YAML reported ok — a parse failure must not read as \"no scanner configured\"")
	}
	if _, ok := MatchMergedConfig("   ", ReportTypeSAST, mapping.CategorySAST, reg); ok {
		t.Error("empty merged config reported ok")
	}
}

func TestCanNeverRunOnlyFiresForAnUnconditionalNever(t *testing.T) {
	reg := loadRegistry(t)
	cases := []struct {
		name        string
		rules       string
		wantMatched bool
	}{
		{"no rules at all", "", true},
		{"an unconditional never", "  rules:\n  - when: never\n", false},
		{"never, but gated on a condition", "  rules:\n  - if: $X == \"1\"\n    when: never\n", true},
		{"never, then a positive rule", "  rules:\n  - when: never\n  - if: $CI\n    when: always\n", true},
		{"an exists-gated never", "  rules:\n  - exists:\n    - go.sum\n    when: never\n", true},
		{"an ordinary rule", "  rules:\n  - if: $CI_COMMIT_BRANCH\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			merged := "scan:\n  script:\n  - ./x\n  artifacts:\n    reports:\n      sast: r.json\n" + tc.rules
			jobs, ok := MatchMergedConfig(merged, ReportTypeSAST, mapping.CategorySAST, reg)
			if !ok {
				t.Fatal("reported unparseable")
			}
			if matched := len(jobs) == 1; matched != tc.wantMatched {
				t.Errorf("matched = %v, want %v (jobs=%+v)", matched, tc.wantMatched, jobs)
			}
		})
	}
}

// TestHiddenJobIsSkippedEvenWhenItCouldOtherwiseRun closes a gap mutation
// testing found: every hidden entry in the recorded template ALSO carries an
// unconditional `when: never`, so canNeverRun was quietly covering for the
// hidden-job skip and deleting that skip broke nothing. A hidden anchor with
// no rules at all is a real shape — GitLab's own `.cyclonedx-reports` and
// `.secret-analyzer` are exactly that — and one declaring a SAST report would
// be counted as a configured scanner without this.
func TestHiddenJobIsSkippedEvenWhenItCouldOtherwiseRun(t *testing.T) {
	const merged = ".sast-analyzer:\n  script:\n  - /analyzer run\n  artifacts:\n    reports:\n      sast: gl-sast-report.json\n"
	jobs, ok := MatchMergedConfig(merged, ReportTypeSAST, mapping.CategorySAST, loadRegistry(t))
	if !ok {
		t.Fatal("reported unparseable")
	}
	if len(jobs) != 0 {
		t.Errorf("matched %+v — a hidden anchor is a template for other jobs to extend, never a job GitLab runs", jobs)
	}
}

func TestStrongestConfidence(t *testing.T) {
	if _, ok := StrongestConfidence(nil); ok {
		t.Error("StrongestConfidence(nil) reported ok")
	}
	got, ok := StrongestConfidence([]ScannerJob{
		{Confidence: ConfidenceLow}, {Confidence: ConfidenceHigh}, {Confidence: ConfidenceMedium},
	})
	if !ok || got != ConfidenceHigh {
		t.Errorf("StrongestConfidence = %q/%v, want high/true", got, ok)
	}
	if got, _ := StrongestConfidence([]ScannerJob{{Confidence: ConfidenceLow}, {Confidence: ConfidenceMedium}}); got != ConfidenceMedium {
		t.Errorf("StrongestConfidence = %q, want medium", got)
	}
}

// -----------------------------------------------------------------------
// run selection, against the real recorded jobs listing
// -----------------------------------------------------------------------

func recordedJobRuns(t *testing.T) []JobRun {
	t.Helper()
	runs, err := DecodeJobs(gitlabfixture.MustLoad(t, "jobs-security-pipelines.json"))
	if err != nil {
		t.Fatalf("decode jobs fixture: %v", err)
	}
	if len(runs) != 14 {
		t.Fatalf("decoded %d runs from the jobs fixture, want 14", len(runs))
	}
	return runs
}

// TestSelectRunsMatchesByNameAndByPublishedReport exercises both signals
// against the recorded listing: five semgrep-sast runs match by name, and a
// renamed job that still published a SAST report matches by artifact.
func TestSelectRunsMatchesByNameAndByPublishedReport(t *testing.T) {
	runs := recordedJobRuns(t)
	configured := []ScannerJob{{Name: "semgrep-sast", Confidence: ConfidenceHigh}}

	got := SelectRuns(runs, configured, ReportTypeSAST)
	if len(got) != 5 {
		t.Fatalf("selected %d runs, want the 5 recorded semgrep-sast runs: %+v", len(got), got)
	}
	for _, r := range got {
		if r.Name != "semgrep-sast" {
			t.Errorf("selected %q, want only semgrep-sast", r.Name)
		}
	}

	// The renamed-job case: nothing in the configuration is called
	// "code-scan", but the run published a SAST report, so it counts.
	renamed := append(runs, JobRun{Name: "code-scan", Status: "success", ReportTypes: []string{"sast"}})
	if got := SelectRuns(renamed, configured, ReportTypeSAST); len(got) != 6 {
		t.Errorf("selected %d runs, want 6 once a renamed job's published SAST report is counted", len(got))
	}
}

// TestSelectRunsIgnoresAnotherCategorysReport pins the report-type filter:
// the recorded listing also contains secret_detection and
// gemnasium-dependency_scanning runs, and neither is a SAST run.
func TestSelectRunsIgnoresAnotherCategorysReport(t *testing.T) {
	got := SelectRuns(recordedJobRuns(t), nil, ReportTypeSAST)
	for _, r := range got {
		if r.Name != "semgrep-sast" {
			t.Errorf("selected %q by artifact alone, want only jobs publishing a sast report", r.Name)
		}
	}
	if len(got) != 5 {
		t.Errorf("selected %d runs by artifact alone, want the 5 semgrep-sast runs", len(got))
	}
}

// -----------------------------------------------------------------------
// coverage and cadence
// -----------------------------------------------------------------------

func TestLinkRunsToReleasesJoinsOnTheReleaseCommit(t *testing.T) {
	releases := []Release{
		{TagName: "v3", CommitSHA: "aaa"},
		{TagName: "v2", CommitSHA: "bbb"},
		{TagName: "v1", CommitSHA: "ccc"},
	}
	runs := []JobRun{
		{Name: "sast", Status: "success", PipelineSHA: "aaa"},
		{Name: "sast", Status: "failed", PipelineSHA: "bbb"},
		// A run on a commit no release was cut from must not cover anything.
		{Name: "sast", Status: "success", PipelineSHA: "ddd"},
	}
	got := LinkRunsToReleases(releases, runs)
	want := []CoverageStatus{CoverageRan, CoverageFailed, CoverageMissing}
	for i, c := range got {
		if c.Status != want[i] {
			t.Errorf("%s coverage = %q, want %q", c.Release.TagName, c.Status, want[i])
		}
	}
}

// TestOneSuccessAmongFailuresIsRan pins the precedence: a failed first
// attempt followed by a successful retry is evidence the scan happened, and
// the order the runs arrive in must not change that.
func TestOneSuccessAmongFailuresIsRan(t *testing.T) {
	releases := []Release{{TagName: "v1", CommitSHA: "aaa"}}
	for _, order := range [][]JobRun{
		{{Status: "failed", PipelineSHA: "aaa"}, {Status: "success", PipelineSHA: "aaa"}},
		{{Status: "success", PipelineSHA: "aaa"}, {Status: "failed", PipelineSHA: "aaa"}},
	} {
		if got := LinkRunsToReleases(releases, order); got[0].Status != CoverageRan {
			t.Errorf("coverage = %q for %+v, want ran", got[0].Status, order)
		}
	}
}

// TestCanceledRunIsNotASuccessfulScan guards the one status that reads like
// a non-failure but evidences nothing.
func TestCanceledRunIsNotASuccessfulScan(t *testing.T) {
	releases := []Release{{TagName: "v1", CommitSHA: "aaa"}}
	got := LinkRunsToReleases(releases, []JobRun{{Status: "canceled", PipelineSHA: "aaa"}})
	if got[0].Status != CoverageFailed {
		t.Errorf("coverage = %q for a canceled run, want failed", got[0].Status)
	}
}

func TestComputeCadence(t *testing.T) {
	now := day(28)
	windowStart := day(0)

	t.Run("counts only finished runs inside the window", func(t *testing.T) {
		c := ComputeCadence([]JobRun{
			{FinishedAt: day(7)},
			{FinishedAt: day(14)},
			{FinishedAt: day(-5)}, // before the window
			{},                    // never finished
		}, windowStart, now)
		if c.Runs != 2 {
			t.Errorf("Runs = %d, want 2", c.Runs)
		}
		if c.RunsPerWeek != 0.5 {
			t.Errorf("RunsPerWeek = %v, want 0.5 (2 runs over 4 weeks)", c.RunsPerWeek)
		}
	})

	t.Run("the trailing gap counts, not just gaps between runs", func(t *testing.T) {
		// One run on day 1 and nothing since is a 27-day silence, which is
		// the whole point of the measure — a version that only measured
		// run-to-run gaps would report 0.
		c := ComputeCadence([]JobRun{{FinishedAt: day(1)}}, windowStart, now)
		if c.LongestGapDays != 27 {
			t.Errorf("LongestGapDays = %v, want 27", c.LongestGapDays)
		}
	})

	t.Run("the leading gap counts too", func(t *testing.T) {
		c := ComputeCadence([]JobRun{{FinishedAt: day(20)}, {FinishedAt: day(27)}}, windowStart, now)
		if c.LongestGapDays != 20 {
			t.Errorf("LongestGapDays = %v, want 20 (window start to the first run)", c.LongestGapDays)
		}
	})

	t.Run("out-of-order runs are sorted before gaps are measured", func(t *testing.T) {
		ordered := ComputeCadence([]JobRun{{FinishedAt: day(7)}, {FinishedAt: day(14)}, {FinishedAt: day(21)}}, windowStart, now)
		shuffled := ComputeCadence([]JobRun{{FinishedAt: day(21)}, {FinishedAt: day(7)}, {FinishedAt: day(14)}}, windowStart, now)
		if ordered != shuffled {
			t.Errorf("cadence depends on input order: %+v vs %+v", ordered, shuffled)
		}
		if ordered.LongestGapDays != 7 {
			t.Errorf("LongestGapDays = %v, want 7", ordered.LongestGapDays)
		}
	})

	t.Run("no runs at all is the whole window as one gap", func(t *testing.T) {
		c := ComputeCadence(nil, windowStart, now)
		if c.Runs != 0 || c.LongestGapDays != 28 {
			t.Errorf("cadence = %+v, want 0 runs and a 28-day gap", c)
		}
	})
}

// -----------------------------------------------------------------------
// the dependency-manifest table
// -----------------------------------------------------------------------

// wantDependencyManifestNames is an independent literal of the three
// `exists:` globs GitLab's own Dependency Scanning template gates its
// analyzers on. Independent on purpose: reading the expectation out of the
// table being asserted would let the table silently narrow — the same trap
// TestEveryStaticCloudCredentialNameIsDetected was written to close in
// internal/collect/gitlab/actionssecurity.
var wantDependencyManifestNames = []string{
	// .gemnasium-shared-rule
	"Gemfile.lock", "composer.lock", "gems.locked", "go.sum", "npm-shrinkwrap.json",
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "packages.lock.json", "conan.lock",
	// .gemnasium-maven-shared-rule
	"build.gradle", "build.gradle.kts", "build.sbt", "pom.xml",
	// .gemnasium-python-shared-rule
	"requirements.txt", "requirements.pip", "Pipfile", "Pipfile.lock", "requires.txt",
	"setup.py", "poetry.lock", "uv.lock",
}

// TestDependencyManifestTableMatchesGitLabsOwnExistsRules re-derives the
// table from the recorded merged configuration rather than trusting the
// transcription — the globs are right there in the fixture, so a typo in the
// Go table (or a future GitLab change, once the fixture is re-recorded) fails
// here instead of silently under-detecting a manifest.
func TestDependencyManifestTableMatchesGitLabsOwnExistsRules(t *testing.T) {
	got := DependencyManifestNames()
	if len(got) != len(wantDependencyManifestNames) {
		t.Errorf("table has %d entries, want %d", len(got), len(wantDependencyManifestNames))
	}
	for _, name := range wantDependencyManifestNames {
		if !got[name] {
			t.Errorf("%q is missing from dependencyManifestNames", name)
		}
	}

	fromFixture := existsGlobFilenames(t, recordedMergedYAML(t))
	if len(fromFixture) == 0 {
		t.Fatal("no exists: globs found in the recorded merged configuration; this assertion would prove nothing")
	}
	for _, name := range fromFixture {
		if !got[name] {
			t.Errorf("%q appears in GitLab's own exists: rule but is not in dependencyManifestNames", name)
		}
	}
}

// existsGlobFilenames pulls the filenames out of every
// `**/{a,b,c}`-shaped exists: glob in a merged configuration.
func existsGlobFilenames(t *testing.T, merged string) []string {
	t.Helper()
	type existsRules struct {
		Rules []struct {
			Exists []string `yaml:"exists"`
		} `yaml:"rules"`
		Exists []string `yaml:"exists"`
	}
	var raw map[string]yaml.Node
	if err := yaml.Unmarshal([]byte(merged), &raw); err != nil {
		t.Fatalf("parse merged configuration: %v", err)
	}
	doc := map[string]existsRules{}
	// Scoped to the three Dependency-Scanning shared rules by name. The same
	// merged configuration also carries the SAST analyzers' own `exists:`
	// globs, which list SOURCE-file extensions (*.go, *.java, application*.yml)
	// rather than dependency manifests — a table built from all of them would
	// be a different, wrong thing.
	for name, node := range raw {
		if !strings.HasPrefix(name, ".gemnasium") || node.Kind != yaml.MappingNode {
			continue
		}
		var entry existsRules
		if err := node.Decode(&entry); err == nil {
			doc[name] = entry
		}
	}
	if len(doc) != 3 {
		t.Fatalf("found %d .gemnasium* shared rules in the recorded configuration, want 3", len(doc))
	}
	var out []string
	gather := func(globs []string) {
		for _, g := range globs {
			openBrace, closeBrace := strings.Index(g, "{"), strings.Index(g, "}")
			if openBrace < 0 || closeBrace < openBrace {
				continue
			}
			for _, name := range strings.Split(g[openBrace+1:closeBrace], ",") {
				out = append(out, strings.TrimSpace(name))
			}
		}
	}
	for _, entry := range doc {
		gather(entry.Exists)
		for _, r := range entry.Rules {
			gather(r.Exists)
		}
	}
	return out
}

func TestFinishedAtNilDoesNotStopTheDecode(t *testing.T) {
	runs, err := DecodeJobs([]byte(`[{"name":"a","status":"running","finished_at":null,"pipeline":{"sha":"x"}}]`))
	if err != nil {
		t.Fatalf("DecodeJobs: %v", err)
	}
	if len(runs) != 1 || !runs[0].FinishedAt.IsZero() {
		t.Errorf("runs = %+v, want one run with a zero FinishedAt", runs)
	}
}

func TestJobRunSucceededOnlyForSuccess(t *testing.T) {
	for status, want := range map[string]bool{
		"success": true, "failed": false, "canceled": false, "skipped": false, "running": false, "manual": false,
	} {
		if got := (JobRun{Status: status}).Succeeded(); got != want {
			t.Errorf("Succeeded(%q) = %v, want %v", status, got, want)
		}
	}
}

func TestPlural(t *testing.T) {
	if got := Plural(1, "release", "releases"); got != "1 release" {
		t.Errorf("Plural(1) = %q", got)
	}
	if got := Plural(3, "release", "releases"); got != "3 releases" {
		t.Errorf("Plural(3) = %q", got)
	}
	if got := Plural(0, "release", "releases"); got != "0 releases" {
		t.Errorf("Plural(0) = %q", got)
	}
}
