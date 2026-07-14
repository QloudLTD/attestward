package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/collect/github/orgsecurity"
	"github.com/sioakim/ssdf/internal/model"
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

	results, outcomes := runCollectors(context.Background(), collectors, collect.Scope{Org: "attestor-demo"}, 2)
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
	results, _ := runCollectors(context.Background(), collectors, collect.Scope{Org: "attestor-demo"}, 2)
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

	_, outcomes := runCollectors(ctx, collectors, collect.Scope{Org: "attestor-demo"}, 1)
	if len(outcomes) != 1 || outcomes[0].err == nil {
		t.Fatalf("outcomes = %v, want the collector's outcome to carry ctx.Err()", outcomes)
	}
}

func TestRunScan_EndToEndWithFakeCollectorsAndRealMappings(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "DEMO.pass", results: []model.CheckResult{
			{CheckID: "DEMO.pass", Status: model.StatusVerifiedPass, Scope: model.ScopeRef{Org: "attestor-demo", Repo: "good-repo"}},
		}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestor-demo"}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if result.exitCode != exitOK {
		t.Errorf("exitCode = %d, want %d", result.exitCode, exitOK)
	}
	if len(result.pack.Results) != 1 {
		t.Fatalf("len(Results) = %d, want 1", len(result.pack.Results))
	}
	if result.pack.Scope.Org != "attestor-demo" || len(result.pack.Scope.Repos) != 1 {
		t.Errorf("pack.Scope = %+v, want org=attestor-demo repos=[good-repo]", result.pack.Scope)
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

func TestRunScan_GapExitsWithCode2(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "DEMO.fail", results: []model.CheckResult{
			{CheckID: "DEMO.fail", Status: model.StatusVerifiedFail, Scope: model.ScopeRef{Org: "attestor-demo", Repo: "good-repo"}},
		}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestor-demo"}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if result.exitCode != exitGaps {
		t.Errorf("exitCode = %d, want %d", result.exitCode, exitGaps)
	}
}

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
	cfg := mergeScanConfig(scanConfig{Org: "attestor-demo"}, scanConfig{}, nil)

	result, err := runScan(context.Background(), cfg, []string{"C01"}, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if len(result.pack.Results) != 1 || result.pack.Results[0].CheckID != "C01.included" {
		t.Fatalf("Results = %v, want only C01.included (C05.excluded filtered out)", result.pack.Results)
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
func TestRunScan_TypoedCheckFilterErrorsLoudly(t *testing.T) {
	collectors := []collect.Collector{
		fakeScanCollector{id: "C01.real", results: []model.CheckResult{{CheckID: "C01.real", Status: model.StatusVerifiedPass}}},
	}
	deps := scanDeps{
		repoLister: &fakeRepoLister{repos: []repoInfo{{Name: "good-repo"}}},
		collectors: collectors,
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "attestor-demo"}, scanConfig{}, nil)

	_, err := runScan(context.Background(), cfg, []string{"C99-typo"}, deps)
	if err == nil {
		t.Fatal("runScan with a --check filter matching nothing = nil error, want a loud error naming the typo")
	}
}

func TestRunScan_OrgCheckerFailurePropagates(t *testing.T) {
	deps := scanDeps{
		repoLister: &fakeRepoLister{},
		orgChecker: &fakeOrgChecker{err: errors.New("404 org not found")},
		stdout:     &bytes.Buffer{},
	}
	cfg := mergeScanConfig(scanConfig{Org: "nonexistent-org"}, scanConfig{}, nil)

	_, err := runScan(context.Background(), cfg, nil, deps)
	if err == nil {
		t.Fatal("runScan with a failing orgChecker = nil error, want the preflight failure propagated")
	}
}

type fakeOrgChecker struct{ err error }

func (f *fakeOrgChecker) CheckOrgVisible(context.Context, string) error { return f.err }

func TestWriteEvidencePack_WritesValidJSON(t *testing.T) {
	dir := t.TempDir()
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestor-demo", Repos: []string{"good-repo"}},
		Results:       []model.CheckResult{},
	}

	if err := writeEvidencePack(pack, dir); err != nil {
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
	if roundTripped.Scope.Org != "attestor-demo" {
		t.Errorf("roundTripped.Scope.Org = %q, want attestor-demo", roundTripped.Scope.Org)
	}
}

func TestWriteEvidencePack_ScrubsSecretsFromFinalBytes(t *testing.T) {
	dir := t.TempDir()
	secret := "ghp_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestor-demo"},
		Results: []model.CheckResult{
			{CheckID: "X", Reason: "leaked " + secret, Provenance: []model.Provenance{}},
		},
	}

	if err := writeEvidencePack(pack, dir); err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "evidence.json"))
	if err != nil {
		t.Fatalf("read evidence.json: %v", err)
	}
	if bytes.Contains(data, []byte(secret)) {
		t.Error("secret survived into evidence.json")
	}
}
