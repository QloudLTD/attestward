package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/collect/github/orgsecurity"
	"gitlab.com/sioakeim/attestward/internal/integrity"
	"gitlab.com/sioakeim/attestward/internal/model"
)

func TestComputeExitCode(t *testing.T) {
	tests := []struct {
		name    string
		results []model.CheckResult
		want    int
	}{
		{"empty results", nil, exitOK},
		{"all pass", []model.CheckResult{{Status: model.StatusVerifiedPass}}, exitOK},
		{"a fail is a gap", []model.CheckResult{{Status: model.StatusVerifiedPass}, {Status: model.StatusVerifiedFail}}, exitGaps},
		{"a partial is a gap", []model.CheckResult{{Status: model.StatusPartial}}, exitGaps},
		{"self-attested alone is not a gap", []model.CheckResult{{Status: model.StatusSelfAttested}}, exitOK},
		{"not-checkable alone is not a gap", []model.CheckResult{{Status: model.StatusNotCheckable}}, exitOK},
		{"self-attested + not-checkable mixed is not a gap", []model.CheckResult{{Status: model.StatusSelfAttested}, {Status: model.StatusNotCheckable}}, exitOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeExitCode(tt.results); got != tt.want {
				t.Errorf("computeExitCode(%v) = %d, want %d", tt.results, got, tt.want)
			}
		})
	}
}

type fakeScanCollector struct {
	id      string
	results []model.CheckResult
	err     error
}

func (f fakeScanCollector) ID() string { return f.id }
func (f fakeScanCollector) Collect(context.Context, collect.Scope) ([]model.CheckResult, error) {
	return f.results, f.err
}

func TestFilterCollectors(t *testing.T) {
	all := []collect.Collector{
		fakeScanCollector{id: "C01.org-security"},
		fakeScanCollector{id: "C05.sast-history"},
		fakeScanCollector{id: "C05.other"},
	}

	if got := filterCollectors(all, nil); len(got) != 3 {
		t.Errorf("filterCollectors(nil) len = %d, want 3 (empty filter runs everything)", len(got))
	}

	got := filterCollectors(all, []string{"C05"})
	if len(got) != 2 {
		t.Fatalf("filterCollectors([C05]) len = %d, want 2", len(got))
	}
	for _, c := range got {
		if c.ID() != "C05.sast-history" && c.ID() != "C05.other" {
			t.Errorf("unexpected collector in filtered set: %s", c.ID())
		}
	}
}

// TestFilterCollectors_RealOrgSecurityMatchesItsOwnDocumentedExample uses the
// actual orgsecurity.Collector (not a fake) to prove --check C01 — the exact
// example filterCollectors' own doc comment gives, and runScanCmd's --check
// flag help text — genuinely resolves to it. A fake with a hand-picked ID
// (as in TestFilterCollectors above) can't catch a real collector's ID
// drifting out of the "C01.<name>" convention the whole --check filter
// mechanism depends on.
func TestFilterCollectors_RealOrgSecurityMatchesItsOwnDocumentedExample(t *testing.T) {
	c := orgsecurity.New(ghcollect.NewClient("ghp_test-token"))
	all := []collect.Collector{c}

	got := filterCollectors(all, []string{"C01"})
	if len(got) != 1 {
		t.Fatalf("filterCollectors([C01]) len = %d, want 1 (org-security's ID %q must match the --check C01 prefix)", len(got), c.ID())
	}
}

func TestRunCollectors_ErrorBecomesNotCheckableAndOthersStillRun(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "C01.ok", results: []model.CheckResult{{CheckID: "C01.ok", Status: model.StatusVerifiedPass}}},
		fakeScanCollector{id: "C02.broken", err: errors.New("API unreachable")},
	}

	results, outcomes := runCollectors(context.Background(), collectors, collect.Scope{Org: "attestward-demo"}, 2)
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	if len(outcomes) != 2 {
		t.Fatalf("len(outcomes) = %d, want 2 (one summary per collector)", len(outcomes))
	}

	byID := map[string]model.CheckResult{}
	for _, r := range results {
		byID[r.CheckID] = r
	}
	if byID["C01.ok"].Status != model.StatusVerifiedPass {
		t.Errorf("C01.ok status = %q, want verified-pass", byID["C01.ok"].Status)
	}
	broken, ok := byID["C02.broken"]
	if !ok {
		t.Fatal("C02.broken missing from results — a collector error must still produce a result, not vanish")
	}
	if broken.Status != model.StatusNotCheckable {
		t.Errorf("C02.broken status = %q, want not-checkable", broken.Status)
	}
	if broken.Reason == "" {
		t.Error("C02.broken Reason is empty, want the underlying error recorded")
	}
	if broken.Provenance == nil {
		t.Error("C02.broken Provenance is nil, want a non-nil empty slice (schema invariant)")
	}

	var brokenOutcome *collectorOutcome
	for i := range outcomes {
		if outcomes[i].id == "C02.broken" {
			brokenOutcome = &outcomes[i]
		}
	}
	if brokenOutcome == nil || brokenOutcome.err == nil {
		t.Error("outcomes did not record C02.broken's error — the per-collector summary line would wrongly say \"done\"")
	}
}

func TestRunCollectors_ResultsSortedByCheckID(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "C09.z", results: []model.CheckResult{{CheckID: "C09.z", Status: model.StatusVerifiedPass}}},
		fakeScanCollector{id: "C01.a", results: []model.CheckResult{{CheckID: "C01.a", Status: model.StatusVerifiedPass}}},
	}
	results, _ := runCollectors(context.Background(), collectors, collect.Scope{Org: "attestward-demo"}, 2)
	if len(results) != 2 || results[0].CheckID != "C01.a" || results[1].CheckID != "C09.z" {
		t.Errorf("results = %v, want sorted by CheckID", results)
	}
}

func TestRunCollectors_CanceledContextSurfacesAsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	collectors := []collect.Collector{
		fakeScanCollector{id: "C01.never-runs", results: []model.CheckResult{{CheckID: "C01.never-runs", Status: model.StatusVerifiedPass}}},
	}

	_, outcomes := runCollectors(ctx, collectors, collect.Scope{Org: "attestward-demo"}, 1)
	if len(outcomes) != 1 || outcomes[0].err == nil {
		t.Fatalf("outcomes = %v, want the collector's outcome to carry ctx.Err()", outcomes)
	}
}

func TestRunScan_EndToEndWithFakeCollectorsAndRealMappings(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "DEMO.pass", results: []model.CheckResult{
			{CheckID: "DEMO.pass", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: "attestward-demo", Repo: "good-repo"}},
		}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo"}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if result.exitCode != exitOK {
		t.Errorf("exitCode = %d, want %d", result.exitCode, exitOK)
	}
	demoCount, saCount := 0, 0
	for _, r := range result.pack.Results {
		if strings.HasPrefix(r.CheckID, "SA.") {
			saCount++
			if r.Status != model.StatusNotCheckable {
				t.Errorf("self-attestation result %s status = %q, want not-checkable (no --self-attestation-file given)", r.CheckID, r.Status)
			}
			continue
		}
		demoCount++
	}
	if demoCount != 1 {
		t.Fatalf("non-self-attestation results = %d, want 1 (DEMO.pass); full Results = %v", demoCount, result.pack.Results)
	}
	if saCount == 0 {
		t.Fatal("no self-attestation results found — self-attestation questions should always be included")
	}
	if result.pack.MappingVersions.SelfAttestation == "" {
		t.Error("pack.MappingVersions.SelfAttestation is empty, want it set")
	}
	if result.pack.Scope.Org != "attestward-demo" || len(result.pack.Scope.Repos) != 1 {
		t.Errorf("pack.Scope = %+v, want org=attestward-demo repos=[good-repo]", result.pack.Scope)
	}
	// Platform-field write policy (issue #148): runScan writes "github"
	// explicitly rather than leaving it absent, even though absent means
	// the same thing today — a signed evidence pack should be
	// self-describing, not lean on an implicit default.
	if result.pack.Scope.Platform != "github" {
		t.Errorf("pack.Scope.Platform = %q, want %q (written explicitly, not left absent)", result.pack.Scope.Platform, "github")
	}
	if result.pack.Rollup == nil {
		t.Fatal("pack.Rollup is nil, want it populated (even if empty) by BuildRollup")
	}
	if result.pack.ScanStartedAt.IsZero() || result.pack.ScanEndedAt.IsZero() {
		t.Error("ScanStartedAt/ScanEndedAt are zero, want them set")
	}
	if result.pack.ScanEndedAt.Before(result.pack.ScanStartedAt) {
		t.Error("ScanEndedAt is before ScanStartedAt")
	}
}

// TestRunScan_MappingVersionsEveryFieldPopulated is issue #255's own guard:
// MappingVersions' doc comment claims it "records the version field of
// every mappings/*.yaml file consulted during a scan" — a claim that was
// false for ScannerSignatures from the field's introduction until this
// issue, with nothing catching it. Rather than hand-listing each field
// name (the same staleness risk any manually-maintained list has — see
// docs/threat-model.md's own persistent-runner-state paragraph, found
// stale for the identical reason during #257's review), this walks every
// string field on model.MappingVersions via reflection and asserts it's
// non-empty, so a future field added to the struct without also being
// wired into runScan's pack construction fails this test automatically
// rather than needing a second manual addition here to catch it.
func TestRunScan_MappingVersionsEveryFieldPopulated(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "DEMO.pass", results: []model.CheckResult{
			{CheckID: "DEMO.pass", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: "attestward-demo", Repo: "good-repo"}},
		}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo"}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}

	v := reflect.ValueOf(result.pack.MappingVersions)
	tp := v.Type()
	// Issue #263's own review: without this, an emptied MappingVersions
	// struct (every field removed) would make the loop below iterate zero
	// times and pass vacuously — the exact silent-pass failure mode this
	// test exists to prevent, just one level up. Reaching that state today
	// is a compile error in four places (this file's own call sites), so
	// the risk is low, but the whole point of this test is to not depend
	// on someone noticing.
	if v.NumField() == 0 {
		t.Fatal("model.MappingVersions has no fields — this test would pass vacuously; something is very wrong")
	}
	for i := 0; i < v.NumField(); i++ {
		field := tp.Field(i)
		if field.Type.Kind() != reflect.String {
			t.Fatalf("MappingVersions.%s is not a string field — this test assumes every field is a version string; update the test if that's no longer true", field.Name)
		}
		if v.Field(i).String() == "" {
			t.Errorf("MappingVersions.%s is empty — its own doc comment claims every field \"records the version field of every mappings/*.yaml file consulted during a scan\"; wire it up in runScan's pack construction", field.Name)
		}
	}
}

func TestRunScan_GapExitsWithCode2(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "DEMO.fail", results: []model.CheckResult{
			{CheckID: "DEMO.fail", Status: model.StatusVerifiedFail, Scope: model.ScopeRef{Org: "attestward-demo", Repo: "good-repo"}},
		}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo"}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if result.exitCode != exitGaps {
		t.Errorf("exitCode = %d, want %d", result.exitCode, exitGaps)
	}
}

// TestRunScan_CheckFilterSkipsNonMatchingCollectors also locks in a
// deliberate design choice: --check's own doc comment scopes it to
// "registered collector[s]" specifically (it exists to skip spending
// GitHub API rate-limit budget on collectors the caller doesn't want) —
// self-attestation results cost no API calls and aren't sourced from
// collectors at all, so they're always included regardless of --check,
// not filtered by it.
func TestRunScan_CheckFilterSkipsNonMatchingCollectors(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "C01.included", results: []model.CheckResult{{CheckID: "C01.included", Status: model.StatusVerifiedPass}}},
		fakeScanCollector{id: "C05.excluded", results: []model.CheckResult{{CheckID: "C05.excluded", Status: model.StatusVerifiedFail}}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo"}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, []string{"C01"}, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	demoCount, saCount := 0, 0
	for _, r := range result.pack.Results {
		if strings.HasPrefix(r.CheckID, "SA.") {
			saCount++
			continue
		}
		if r.CheckID != "C01.included" {
			t.Errorf("unexpected non-self-attestation result %s (C05.excluded should have been filtered out)", r.CheckID)
		}
		demoCount++
	}
	if demoCount != 1 {
		t.Fatalf("non-self-attestation results = %d, want 1 (C01.included); full Results = %v", demoCount, result.pack.Results)
	}
	if saCount == 0 {
		t.Fatal("no self-attestation results found — --check must not filter them out")
	}
	// Proves the filter actually excluded the failing collector, not just
	// happened to still pass for an unrelated reason.
	if result.exitCode != exitOK {
		t.Errorf("exitCode = %d, want %d (the only failing collector was filtered out)", result.exitCode, exitOK)
	}
}

// TestRunScan_TypoedCheckFilterErrorsLoudly guards against the scenario the
// Fable 5 review flagged: a --check value that matches nothing (a likely
// typo) used to silently run zero collectors and produce a "clean" exit 0
// pack — indistinguishable from a genuinely all-clear scan for a
// truthfulness-focused tool.
func TestRunScan_SelfAttestationFileProvided_AnsweredQuestionsAreSelfAttested(t *testing.T) {
	answersPath := filepath.Join(t.TempDir(), "answers.yaml")
	answersYAML := `answers:
  - id: SA.dev-security-training
    answer: "yes"
    evidence_ref: "https://example.invalid/training-policy"
    attested_by: "Jane Doe, CTO"
    date: "2026-07-14"
`
	if err := os.WriteFile(answersPath, []byte(answersYAML), 0o644); err != nil {
		t.Fatalf("write answers file: %v", err)
	}

	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo", SelfAttestationFile: answersPath}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}

	var answered, unanswered int
	for _, r := range result.pack.Results {
		if r.CheckID != "SA.dev-security-training" {
			if strings.HasPrefix(r.CheckID, "SA.") {
				unanswered++
				if r.Status != model.StatusNotCheckable {
					t.Errorf("%s status = %q, want not-checkable (left unanswered)", r.CheckID, r.Status)
				}
			}
			continue
		}
		answered++
		if r.Status != model.StatusSelfAttested {
			t.Fatalf("SA.dev-security-training status = %q, want self-attested", r.Status)
		}
		if r.Facts["answer"] != "yes" || r.Facts["attested_by"] != "Jane Doe, CTO" {
			t.Errorf("SA.dev-security-training facts = %#v, want answer/attested_by populated from the answers file", r.Facts)
		}
	}
	if answered != 1 {
		t.Fatalf("answered self-attestation results = %d, want 1", answered)
	}
	if unanswered == 0 {
		t.Fatal("want at least one other self-attestation question left not-checkable (the answers file only answered one)")
	}
	// Even a fully-affirmative self-attestation must never move the exit
	// code to gaps-found — self-attested never counts as a verified gap or
	// a verified pass either way.
	if result.exitCode != exitOK {
		t.Errorf("exitCode = %d, want %d", result.exitCode, exitOK)
	}
}

func TestRunScan_SelfAttestationFile_UnknownQuestionIDErrorsLoudly(t *testing.T) {
	answersPath := filepath.Join(t.TempDir(), "answers.yaml")
	if err := os.WriteFile(answersPath, []byte("answers:\n  - id: SA.does-not-exist\n    answer: \"yes\"\n"), 0o644); err != nil {
		t.Fatalf("write answers file: %v", err)
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo", SelfAttestationFile: answersPath}, scanConfig{}, nil)

	_, err := runScan(context.Background(), cfg, nil, deps)
	if err == nil {
		t.Fatal("runScan with an unknown self-attestation question id = nil error, want a loud error")
	}
}

func TestRunScan_TypoedCheckFilterErrorsLoudly(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "C01.real", results: []model.CheckResult{{CheckID: "C01.real", Status: model.StatusVerifiedPass}}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo"}, scanConfig{}, nil)

	_, err := runScan(context.Background(), cfg, []string{"C99-typo"}, deps)
	if err == nil {
		t.Fatal("runScan with a --check filter matching nothing = nil error, want a loud error naming the typo")
	}
}

func TestRunScan_OrgCheckerFailurePropagates(t *testing.T) {
	deps := scanDeps{
		repoLister: &fakeRepoLister{},
		orgChecker: &fakeOrgChecker{err: errors.New("404 account not found")},
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "nonexistent-org"}, scanConfig{}, nil)

	_, err := runScan(context.Background(), cfg, nil, deps)
	if err == nil {
		t.Fatal("runScan with a failing orgChecker = nil error, want the preflight failure propagated")
	}
}

// TestRunScan_AccountTypeFlowsIntoScope confirms runScan threads the
// account type CheckAccount discovers all the way into collect.Scope
// (issue #102) — every collector that branches on scope.AccountType
// depends on this actually happening, not just compiling.
func TestRunScan_AccountTypeFlowsIntoScope(t *testing.T) {
	var gotScope collect.Scope
	collectors := []collect.Collector{
		fakeScanCollectorFunc{id: "DEMO.check", fn: func(_ context.Context, scope collect.Scope) ([]model.CheckResult, error) {
			gotScope = scope
			return []model.CheckResult{{CheckID: "DEMO.check", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: scope.Org}}}, nil
		}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "ssdf"}}},
		orgChecker: &fakeOrgChecker{accountType: collect.AccountTypeUser},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "sioakim", Repos: []string{"ssdf"}}, scanConfig{}, nil)

	if _, err := runScan(context.Background(), cfg, nil, deps); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if gotScope.AccountType != collect.AccountTypeUser {
		t.Errorf("scope.AccountType = %q, want user (CheckAccount reported user)", gotScope.AccountType)
	}
}

type fakeOrgChecker struct {
	err         error
	accountType collect.AccountType
}

func (f *fakeOrgChecker) CheckAccount(context.Context, string) (collect.AccountType, error) {
	return f.accountType, f.err
}

// fakeScanCollectorFunc is fakeScanCollector's function-backed sibling —
// used only by tests that need to observe the Scope a collector was
// actually called with, rather than just returning fixed results.
type fakeScanCollectorFunc struct {
	id string
	fn func(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error)
}

func (f fakeScanCollectorFunc) ID() string { return f.id }
func (f fakeScanCollectorFunc) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	return f.fn(ctx, scope)
}

// TestRunScan_ProjectFlowsIntoCollectorScope mirrors
// TestRunScan_AccountTypeFlowsIntoScope for issue #148's collect.Scope.Project
// field: a future ADO collector reading scope.Project depends on runScan
// actually threading cfg.Project through, not just compiling.
func TestRunScan_ProjectFlowsIntoCollectorScope(t *testing.T) {
	var gotScope collect.Scope
	collectors := []collect.Collector{
		fakeScanCollectorFunc{id: "DEMO.check", fn: func(_ context.Context, scope collect.Scope) ([]model.CheckResult, error) {
			gotScope = scope
			return []model.CheckResult{{CheckID: "DEMO.check", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: scope.Org}}}, nil
		}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo", Platform: "azuredevops", Project: "my-project"}, scanConfig{}, nil)

	if _, err := runScan(context.Background(), cfg, nil, deps); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if gotScope.Project != "my-project" {
		t.Errorf("scope.Project = %q, want my-project", gotScope.Project)
	}
}

// TestRunScan_PackScopeRecordsPlatformAndProject proves runScan's pack
// assembly no longer hardcodes "github": a non-default platform/project
// flow all the way into the written pack's top-level Scope.
func TestRunScan_PackScopeRecordsPlatformAndProject(t *testing.T) {
	collectors := []collect.Collector{fakeScanCollector{id: "DEMO.pass", results: []model.CheckResult{
		{CheckID: "DEMO.pass", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: "attestward-demo"}},
	}}}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo", Platform: "azuredevops", Project: "my-project"}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if result.pack.Scope.Platform != "azuredevops" {
		t.Errorf("pack.Scope.Platform = %q, want azuredevops", result.pack.Scope.Platform)
	}
	if result.pack.Scope.Project != "my-project" {
		t.Errorf("pack.Scope.Project = %q, want my-project", result.pack.Scope.Project)
	}
}

// TestRunScan_BackfillsScopePlatformOntoEveryResult pins the review finding
// from #164: the orchestrator, not each collector, is the single source of
// truth for a result's ScopeRef.Platform/Project. The fake collector here
// deliberately sets the WRONG platform on its own result to prove runScan
// overwrites it rather than trusting it — and the self-attestation results
// (which never set Scope.Platform themselves) must end up stamped too.
func TestRunScan_BackfillsScopePlatformOntoEveryResult(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "DEMO.pass", results: []model.CheckResult{
			{CheckID: "DEMO.pass", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: "attestward-demo", Repo: "good-repo", Platform: "a-collector-cannot-be-trusted-to-set-this"}},
		}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo"}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if len(result.pack.Results) == 0 {
		t.Fatal("no results produced")
	}
	for _, r := range result.pack.Results {
		if r.Scope.Platform != "github" {
			t.Errorf("result %s Scope.Platform = %q, want %q (orchestrator must overwrite whatever a collector set)", r.CheckID, r.Scope.Platform, "github")
		}
	}
}

// TestRunScan_ProjectStampedWhenGenuinelyTrueOfTheResult pins issue #221:
// stampResultsWithPlatform used to set Scope.Project on every result
// unconditionally, so a signed Azure DevOps pack recorded a project scope
// on org-wide findings too — e.g. C01.org.2fa-required, whose verdict has
// nothing to do with any one project. Project is now kept for a result
// whenever it's actually true of that result: a check registered
// ScopeLevelProject (C03.env.exists), OR any result that carries a Repo
// (C02.branch.protection-exists — an ADO repo genuinely lives inside a
// project, so Project is real context there too, not a guess) — and
// cleared only for a genuinely org-scoped result with neither
// (C01.org.2fa-required). Deliberately uses three REAL registered check
// IDs rather than fake ones, so the assertion exercises the real
// collect.LookupPlatform/CheckMeta.ScopeLevel path stampResultsWithPlatform
// now depends on — a synthetic, unregistered ID would take the
// "not project-scoped" branch regardless of whether the lookup logic is
// even correct, and prove nothing.
//
// The C01 fake result deliberately sets Scope.Project to "wrong-project"
// rather than leaving it empty (found in review of #229): no real ADO
// collector ever sets Project on an org-scoped result today, so leaving
// it unset here would make this test pass identically whether
// stampResultsWithPlatform actually clears the field or just trusts
// whatever a collector already put there — the "orchestrator overwrites,
// never preserves" property the doc comment on stampResultsWithPlatform
// spends several lines asserting would be completely unpinned. Deleting
// the function's `else { Scope.Project = "" }` branch entirely must fail
// this test; it silently didn't before this fix.
func TestRunScan_ProjectStampedWhenGenuinelyTrueOfTheResult(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "fake.mixed-scope", results: []model.CheckResult{
			{CheckID: "C01.org.2fa-required", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: "attestward-demo", Project: "wrong-project"}},
			{CheckID: "C03.env.exists", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: "attestward-demo", Project: "my-project"}},
			{CheckID: "C02.branch.protection-exists", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: "attestward-demo", Repo: "good-repo", Project: "my-project"}},
		}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo", Platform: "azuredevops", Project: "my-project"}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}

	byID := map[string]model.CheckResult{}
	for _, r := range result.pack.Results {
		byID[r.CheckID] = r
	}

	orgResult, ok := byID["C01.org.2fa-required"]
	if !ok {
		t.Fatal("C01.org.2fa-required missing from pack results")
	}
	if orgResult.Scope.Project != "" {
		t.Errorf("C01.org.2fa-required (org-scoped, ScopeLevel unset, no Repo) Scope.Project = %q, want empty — an org-wide finding must not claim a project scope in the signed pack", orgResult.Scope.Project)
	}

	projResult, ok := byID["C03.env.exists"]
	if !ok {
		t.Fatal("C03.env.exists missing from pack results")
	}
	if projResult.Scope.Project != "my-project" {
		t.Errorf("C03.env.exists (registered ScopeLevelProject) Scope.Project = %q, want my-project", projResult.Scope.Project)
	}

	repoResult, ok := byID["C02.branch.protection-exists"]
	if !ok {
		t.Fatal("C02.branch.protection-exists missing from pack results")
	}
	if repoResult.Scope.Project != "my-project" {
		t.Errorf("C02.branch.protection-exists (repo-scoped, ScopeLevel unset, but has a Repo) Scope.Project = %q, want my-project — a repo genuinely lives inside a project, so this isn't a false claim", repoResult.Scope.Project)
	}
}

// TestResolveScanToken_GitHub / TestResolveScanToken_AzureDevOps* pin issue
// #148's token-sourcing branch: github reads GITHUB_TOKEN (unchanged from
// before this issue), azuredevops reads AZURE_DEVOPS_EXT_PAT and never
// consults GITHUB_TOKEN at all, and says so in its missing-PAT error.
func TestResolveScanToken_GitHubReadsGitHubToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_test-token")

	token, err := resolveScanToken("github")
	if err != nil {
		t.Fatalf("resolveScanToken: %v", err)
	}
	if token != "ghp_test-token" {
		t.Errorf("token = %q, want ghp_test-token", token)
	}
}

func TestResolveScanToken_GitHubMissingTokenErrors(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")

	if _, err := resolveScanToken("github"); err == nil {
		t.Fatal("resolveScanToken(github) with no GITHUB_TOKEN = nil error, want an error")
	}
	if _, err := resolveScanToken(""); err == nil {
		t.Fatal(`resolveScanToken("") with no GITHUB_TOKEN = nil error, want an error (empty platform defaults to github)`)
	}
}

func TestResolveScanToken_AzureDevOpsReadsPATIgnoresGitHubToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_should-be-ignored")
	t.Setenv("AZURE_DEVOPS_EXT_PAT", "ado-pat")

	token, err := resolveScanToken("azuredevops")
	if err != nil {
		t.Fatalf("resolveScanToken: %v", err)
	}
	if token != "ado-pat" {
		t.Errorf("token = %q, want ado-pat", token)
	}
}

func TestResolveScanToken_AzureDevOpsMissingPATErrorsAndMentionsGitHubTokenIgnored(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_irrelevant")
	t.Setenv("AZURE_DEVOPS_EXT_PAT", "")

	_, err := resolveScanToken("azuredevops")
	if err == nil {
		t.Fatal("resolveScanToken(azuredevops) with no AZURE_DEVOPS_EXT_PAT = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Errorf("error = %v, want it to explicitly mention that GITHUB_TOKEN is ignored, got: %v", err, err)
	}
}

// TestResolveScanToken_Gogs* mirror the azuredevops pair for the third
// platform (Gogs issue #3). GOGS_TOKEN is a Gogs personal access token —
// its REST API rejects HTTP basic auth outright, so a token is the only
// credential that can work and there is nothing else to fall back to.
func TestResolveScanToken_GogsReadsGogsTokenIgnoresGitHubToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_should-be-ignored")
	t.Setenv("GOGS_TOKEN", "gogs-token")

	token, err := resolveScanToken("gogs")
	if err != nil {
		t.Fatalf("resolveScanToken: %v", err)
	}
	if token != "gogs-token" {
		t.Errorf("token = %q, want gogs-token", token)
	}
}

func TestResolveScanToken_GogsMissingTokenErrorsAndMentionsGitHubTokenIgnored(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "ghp_irrelevant")
	t.Setenv("GOGS_TOKEN", "")

	_, err := resolveScanToken("gogs")
	if err == nil {
		t.Fatal("resolveScanToken(gogs) with no GOGS_TOKEN = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "GOGS_TOKEN") {
		t.Errorf("error = %v, want it to name GOGS_TOKEN", err)
	}
	if !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Errorf("error = %v, want it to explicitly mention that GITHUB_TOKEN is ignored", err)
	}
}

// TestBuildScanDeps_GitHub/AzureDevOps* pin the CLI wiring layer's
// per-platform branch — unit-tested directly rather than through cobra
// (issue #148's acceptance criterion).
func TestBuildScanDeps_GitHubWiresRepoListerAndOrgChecker(t *testing.T) {
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo"}, scanConfig{}, nil)
	deps, err := buildScanDeps(cfg, "ghp_test-token", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("buildScanDeps: %v", err)
	}
	if deps.repoLister == nil || deps.orgChecker == nil || deps.client == nil {
		t.Error("github scanDeps missing repoLister/orgChecker/client")
	}
	if len(deps.collectors) == 0 {
		t.Error("github scanDeps has zero collectors, want the real ten")
	}
}

// TestBuildScanDeps_AzureDevOpsWiresOrgSecurityCollector proves the CLI
// wiring layer actually reaches defaultAzureDevOpsCollectors: as of issues
// #150 (S4, two PRs), #151 (S5, two PRs), #152 (S6, three collector PRs:
// pipelinehistory landed first, then C05, then C06), #153 (S7, two
// collector PRs: C07 then C08, the epic's last story), and #154 (S8, two
// PRs), an azuredevops scan gets every real collector landed so far — the
// epic's full set: C01 org-security, C02 repo-protection, C03
// env-separation, C04 secrets-hygiene, C05 sast-history, C06 sca-history,
// C07 provenance, C08 pipeline-security, C09 audit-logging, and C10 vdp —
// replacing this same test's pre-#150 assertion that buildScanDeps refused
// the scan outright (see git history for that version). repoLister/
// orgChecker stay nil regardless, since no ADO implementation of either
// exists yet (see buildScanDeps' own doc comment) — a real gap for
// repoprotection, vdp, sasthistory, scahistory, and secretshygiene
// specifically, since all five are project/repo-scoped ADO collectors
// that consult scope.Repos, but not one buildScanDeps itself needs to
// close (repo resolution happens later, in runScan; env-separation and
// pipelinesecurity never consult scope.Repos at all). Asserting all ten
// collector IDs (not just a non-zero count) catches
// defaultAzureDevOpsCollectors silently dropping one of them, which a
// bare len() check would miss.
func TestBuildScanDeps_AzureDevOpsWiresOrgSecurityCollector(t *testing.T) {
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo", Platform: "azuredevops", Project: "proj"}, scanConfig{}, nil)
	deps, err := buildScanDeps(cfg, "ado-pat", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("buildScanDeps: %v", err)
	}
	if len(deps.collectors) != 10 {
		t.Fatalf("azuredevops scanDeps has %d collectors, want exactly 10 (C01 org-security, C02 repo-protection, C03 env-separation, C04 secrets-hygiene, C05 sast-history, C06 sca-history, C07 provenance, C08 pipeline-security, C09 audit-logging, C10 vdp)", len(deps.collectors))
	}
	gotIDs := map[string]bool{}
	for _, c := range deps.collectors {
		gotIDs[c.ID()] = true
	}
	for _, wantID := range []string{"C01.org-security", "C02.repo-protection", "C03.env-separation", "C04.secrets-hygiene", "C05.sast-history", "C06.sca-history", "C07.provenance", "C08.actions-security", "C09.audit-logging", "C10.vdp"} {
		if !gotIDs[wantID] {
			t.Errorf("azuredevops scanDeps.collectors missing %q, got %v", wantID, gotIDs)
		}
	}
	if deps.repoLister != nil || deps.orgChecker != nil {
		t.Error("azuredevops scanDeps has a non-nil repoLister/orgChecker, want both nil until a real ADO implementation of either exists")
	}
}

// TestBuildScanDeps_GogsWiresEveryCollectorAndARepoLister replaces this
// test's earlier version, which asserted that buildScanDeps refused a gogs
// scan outright while no collector existed (see git history). Now that the
// C10 vdp collector and the unsupported-check collectors are wired, the
// honest behaviour is the opposite: the scan runs, and every check ID a
// Gogs pack should contain has a collector behind it.
//
// Asserting the collector IDs rather than a bare count is what catches
// defaultGogsCollectors silently dropping one — a dropped unsupported
// collector would remove several checks from the pack entirely, which
// reads as a clean scan rather than a broken one.
func TestBuildScanDeps_GogsWiresEveryCollectorAndARepoLister(t *testing.T) {
	cfg := mergeScanConfig(scanConfig{Org: "sioakim", Platform: "gogs", GogsURL: "https://gogs.example.com"}, scanConfig{}, nil)
	deps, err := buildScanDeps(cfg, "gogs-token", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("buildScanDeps: %v", err)
	}

	gotIDs := map[string]bool{}
	for _, c := range deps.collectors {
		gotIDs[c.ID()] = true
	}
	for _, wantID := range []string{
		"C01.org-security", "C03.env-separation", "C04.secrets-hygiene",
		"C05.sast-history", "C06.sca-history", "C07.provenance",
		"C08.actions-security", "C09.audit-logging", "C10.vdp",
		// C02 landed on its own branch, after the wiring branch was cut.
		// Its absence from this list is how it stayed unwired and
		// invisible in a real pack while every test stayed green — the
		// collector existed, was never imported, so never registered and
		// never ran.
		"C02.repo-protection",
	} {
		if !gotIDs[wantID] {
			t.Errorf("gogs scanDeps.collectors missing %q, got %v", wantID, gotIDs)
		}
	}

	// Unlike the azuredevops branch, a Gogs scan gets a real repo lister:
	// one endpoint lists an account's repos, so --repo narrows a scan
	// rather than being required for one to work at all.
	if deps.repoLister == nil {
		t.Error("gogs scanDeps has a nil repoLister, so every scan would demand an explicit --repo")
	}
	// orgChecker stays nil: Gogs does not distinguish a user account from
	// an organization on any endpoint this scan touches, so there is no
	// account type to resolve.
	if deps.orgChecker != nil {
		t.Error("gogs scanDeps has a non-nil orgChecker, but Gogs has no account-type distinction to check")
	}
	if deps.client != nil {
		t.Error("gogs scanDeps carries a GitHub client")
	}
}

func TestWriteEvidencePack_WritesValidJSON(t *testing.T) {
	dir := t.TempDir()
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestward-demo", Repos: []string{"good-repo"}},
		Results:       []model.CheckResult{},
	}

	if _, err := writeEvidencePack(pack, dir); err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "evidence.json"))
	if err != nil {
		t.Fatalf("read evidence.json: %v", err)
	}
	var roundTripped model.EvidencePack
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("evidence.json is not valid JSON: %v", err)
	}
	if roundTripped.Scope.Org != "attestward-demo" {
		t.Errorf("roundTripped.Scope.Org = %q, want attestward-demo", roundTripped.Scope.Org)
	}
}

// TestWriteEvidencePack_ReturnedHashMatchesWrittenBytes proves the hash
// writeEvidencePack returns is genuinely the hash of what's on disk (not,
// say, the hash of the pre-scrub bytes, or of the pack before marshaling)
// — issue #27's single-source-of-truth requirement for "the hash of this
// pack". It further wires the returned hash through integrity.WriteSidecar
// exactly as runScanCmd does, then confirms integrity.VerifyFile succeeds
// end-to-end against the real written file, and fails after a tamper.
func TestWriteEvidencePack_ReturnedHashMatchesWrittenBytes(t *testing.T) {
	dir := t.TempDir()
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestward-demo", Repos: []string{"good-repo"}},
		Results:       []model.CheckResult{},
	}

	hash, err := writeEvidencePack(pack, dir)
	if err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}

	path := filepath.Join(dir, "evidence.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence.json: %v", err)
	}
	if want := integrity.Hash(data); hash != want {
		t.Fatalf("writeEvidencePack returned hash %q, want %q (the actual hash of the written bytes)", hash, want)
	}

	if err := integrity.WriteSidecar(path, hash); err != nil {
		t.Fatalf("WriteSidecar: %v", err)
	}
	ok, _, _, err := integrity.VerifyFile(path)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if !ok {
		t.Error("VerifyFile on a freshly written pack + its own sidecar = false, want true")
	}

	if err := os.WriteFile(path, append(data, 'X'), 0o644); err != nil {
		t.Fatalf("tamper evidence.json: %v", err)
	}
	ok, _, _, err = integrity.VerifyFile(path)
	if err != nil {
		t.Fatalf("VerifyFile after tamper: %v", err)
	}
	if ok {
		t.Error("VerifyFile after appending a byte to evidence.json = true, want false")
	}
}

func TestWriteEvidencePack_ScrubsSecretsFromFinalBytes(t *testing.T) {
	dir := t.TempDir()
	secret := "ghp_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestward-demo", Repos: []string{"good-repo"}},
		ScanStartedAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
		ScanEndedAt:   time.Date(2026, 7, 13, 12, 0, 5, 0, time.UTC),
		Results: []model.CheckResult{
			{CheckID: "X", Status: model.StatusVerifiedPass, Reason: "leaked " + secret, Scope: model.ScopeRef{Org: "attestward-demo"}, Provenance: []model.Provenance{}},
		},
	}

	hash, err := writeEvidencePack(pack, dir)
	if err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "evidence.json"))
	if err != nil {
		t.Fatalf("read evidence.json: %v", err)
	}
	if bytes.Contains(data, []byte(secret)) {
		t.Error("secret survived into evidence.json")
	}
	// This is the one fixture in this file where scrubbing actually
	// changes the bytes (the empty-Results/no-secret fixtures elsewhere
	// are scrub no-ops, so they can't tell "hashed before scrubbing" from
	// "hashed after" apart) — so this is the assertion that actually
	// proves writeEvidencePack's returned hash describes the bytes really
	// written, not the pre-scrub bytes.
	if want := integrity.Hash(data); hash != want {
		t.Errorf("writeEvidencePack returned hash %q, want %q (the hash of the post-scrub bytes actually on disk)", hash, want)
	}
}

// TestWriteEvidencePack_RejectsSchemaInvalidPack proves the pre-write
// validation (issue #24) actually blocks a write rather than being dead
// code: a pack with an invalid Status must produce an error and leave no
// evidence.json in outDir at all — never a half-valid file on disk.
func TestWriteEvidencePack_RejectsSchemaInvalidPack(t *testing.T) {
	dir := t.TempDir()
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestward-demo", Repos: []string{"good-repo"}},
		Results: []model.CheckResult{
			{CheckID: "X", Status: model.Status("not-a-real-status"), Scope: model.ScopeRef{Org: "attestward-demo"}, Provenance: []model.Provenance{}},
		},
	}

	if _, err := writeEvidencePack(pack, dir); err == nil {
		t.Fatal("writeEvidencePack with an invalid status = nil error, want a pre-write validation error")
	}
	if _, err := os.Stat(filepath.Join(dir, "evidence.json")); !os.IsNotExist(err) {
		t.Errorf("evidence.json exists after a rejected write (stat err = %v), want no file at all", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("dir contains %d entr(y/ies) after a rejected write, want none (no leftover temp file either): %v", len(entries), entries)
	}
}

// TestWriteEvidencePack_RejectsOversizedFacts proves ValidateFactsSizes is
// actually wired into the real write path, not just unit-tested in
// isolation.
// TestWriteEvidencePack_OversizedFactsStillWrites locks in a deliberate
// design choice: unlike a schema violation, an oversized fact is
// advisory only (see ValidateFactsSizes' doc comment) — a large org's
// genuinely large finding count (many unpinned actions, a long release
// history, both unbounded by any collector-side cap) is a real, correct
// result this tool exists to report, not a reason to destroy the whole
// scan's evidence. writeEvidencePack must still write the pack, with the
// oversized fact intact, not silently truncated or dropped.
func TestWriteEvidencePack_OversizedFactsStillWrites(t *testing.T) {
	dir := t.TempDir()
	oversized := strings.Repeat("x", model.MaxFactValueBytes+1)
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestward-demo", Repos: []string{"good-repo"}},
		Results: []model.CheckResult{
			{
				CheckID: "X", Status: model.StatusVerifiedPass,
				Scope: model.ScopeRef{Org: "attestward-demo"}, Provenance: []model.Provenance{},
				Facts: map[string]any{"large_but_legitimate": oversized},
			},
		},
	}

	if _, err := writeEvidencePack(pack, dir); err != nil {
		t.Fatalf("writeEvidencePack with an oversized-but-legitimate fact = %v, want no error", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "evidence.json"))
	if err != nil {
		t.Fatalf("read evidence.json: %v", err)
	}
	if !bytes.Contains(data, []byte(oversized)) {
		t.Error("the oversized fact's value did not survive into evidence.json — it must never be silently truncated or dropped")
	}
}

// TestRunScan_OversizedFactWarnsButStillSucceeds proves runScan surfaces
// ValidateFactsSizes' finding as a warning (visible to the operator) but
// never fails the scan over it.
func TestRunScan_OversizedFactWarnsButStillSucceeds(t *testing.T) {
	oversized := strings.Repeat("x", model.MaxFactValueBytes+1)
	var stdout bytes.Buffer
	deps := scanDeps{
		collectors: []collect.Collector{
			fakeScanCollector{id: "DEMO.pass", results: []model.CheckResult{
				{
					CheckID: "DEMO.pass", Status: model.StatusVerifiedPass,
					Scope: model.ScopeRef{Org: "attestward-demo", Repo: "good-repo"},
					Facts: map[string]any{"large_but_legitimate": oversized},
				},
			}},
		},
		stdout: &stdout,
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo", Repos: []string{"good-repo"}}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if !strings.Contains(stdout.String(), "large_but_legitimate") {
		t.Errorf("stdout = %q, want a warning naming the oversized fact", stdout.String())
	}
	if result.pack.Results[0].Facts["large_but_legitimate"] != oversized {
		t.Error("the oversized fact was dropped or altered in the returned pack, want it intact")
	}
}

// TestWriteEvidencePack_AtomicWriteLeavesNoTempFileOnSuccess proves the
// temp-file-plus-rename path (issue #24) cleans up after itself: after a
// successful write, outDir must contain exactly evidence.json, no
// leftover .evidence-*.json.tmp file.
func TestWriteEvidencePack_AtomicWriteLeavesNoTempFileOnSuccess(t *testing.T) {
	dir := t.TempDir()
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestward-demo", Repos: []string{"good-repo"}},
		Results: []model.CheckResult{
			{CheckID: "X", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: "attestward-demo"}, Provenance: []model.Provenance{}},
		},
	}

	if _, err := writeEvidencePack(pack, dir); err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "evidence.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("dir entries = %v, want exactly [evidence.json]", names)
	}
}

// TestRunScan_DeterministicAcrossRunsWithFixedClock is issue #24's core
// acceptance criterion: two scans over identical fixtures (same
// collectors, same fixed clock — a real scan never gets a fixed clock,
// but the marshaling/ordering logic under test doesn't know or care where
// its timestamps came from) must produce byte-identical evidence.json
// content.
func TestRunScan_DeterministicAcrossRunsWithFixedClock(t *testing.T) {
	fixedTime := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	newDeps := func() scanDeps {
		return scanDeps{
			collectors: []collect.Collector{
				fakeScanCollector{id: "DEMO.pass", results: []model.CheckResult{
					{
						CheckID: "DEMO.pass", Status: model.StatusVerifiedPass,
						Scope: model.ScopeRef{Org: "attestward-demo", Repo: "good-repo"},
						Provenance: []model.Provenance{
							{Endpoint: "/repos/attestward-demo/good-repo", Method: "GET", Timestamp: fixedTime, HTTPStatus: 200, ResponseSHA256: strings.Repeat("a", 64)},
						},
						Facts: map[string]any{"some_fact": 1},
					},
				}},
			},
			stdout: &bytes.Buffer{},
			now:    func() time.Time { return fixedTime },
		}
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestward-demo", Repos: []string{"good-repo"}}, scanConfig{}, nil)

	result1, err := runScan(context.Background(), cfg, nil, newDeps())
	if err != nil {
		t.Fatalf("runScan (1): %v", err)
	}
	result2, err := runScan(context.Background(), cfg, nil, newDeps())
	if err != nil {
		t.Fatalf("runScan (2): %v", err)
	}

	data1, err := json.MarshalIndent(result1.pack, "", "  ")
	if err != nil {
		t.Fatalf("marshal run 1: %v", err)
	}
	data2, err := json.MarshalIndent(result2.pack, "", "  ")
	if err != nil {
		t.Fatalf("marshal run 2: %v", err)
	}
	if !bytes.Equal(data1, data2) {
		t.Errorf("two runScan calls over identical fixtures produced different JSON:\n--- run 1 ---\n%s\n--- run 2 ---\n%s", data1, data2)
	}

	// Also prove the two on-disk files (through the real writer, not just
	// the in-memory struct) are byte-identical.
	dir1, dir2 := t.TempDir(), t.TempDir()
	hash1, err := writeEvidencePack(result1.pack, dir1)
	if err != nil {
		t.Fatalf("writeEvidencePack (1): %v", err)
	}
	hash2, err := writeEvidencePack(result2.pack, dir2)
	if err != nil {
		t.Fatalf("writeEvidencePack (2): %v", err)
	}
	if hash1 != hash2 {
		t.Errorf("writeEvidencePack returned different hashes for identical fixtures: %q vs %q", hash1, hash2)
	}
	written1, err := os.ReadFile(filepath.Join(dir1, "evidence.json"))
	if err != nil {
		t.Fatalf("read written pack 1: %v", err)
	}
	written2, err := os.ReadFile(filepath.Join(dir2, "evidence.json"))
	if err != nil {
		t.Fatalf("read written pack 2: %v", err)
	}
	if !bytes.Equal(written1, written2) {
		t.Error("two on-disk evidence.json files from identical fixtures are not byte-identical")
	}
}
