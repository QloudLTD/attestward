//go:build integration

// Integration test (issue #155, epic #34's v0.2 Azure DevOps parity work):
// twin of TestIntegration_DemoOrgMatchesFixtures (integration_test.go) for
// the azuredevops platform. Runs a real `attestward scan --platform
// azuredevops` against the ADO demo project (see hack/demo-ado-setup.sh,
// fixtures-ado.yaml) and asserts every produced result against
// fixtures-ado.yaml — the same API-drift tripwire role the GitHub test
// plays, wired into integration-scan.yaml as a second, independent job.
// Requires AZURE_DEVOPS_EXT_PAT in the environment — the same read-only
// token env var `attestward scan --platform azuredevops` itself reads
// (resolveScanToken in scan.go); skips cleanly if unset, so `go test
// ./...` (no -tags integration) and a tagged run without the token both
// stay green rather than failing loud for an unrelated reason, matching
// the GitHub twin's contract exactly.
package main

import (
	"context"
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"gitlab.com/sioakeim/attestward/internal/model"
)

// The ADO demo project's project/repo names are fixed constants, not read
// from fixtures-ado.yaml — deliberately unlike the GitHub twin, which
// derives its scan's org/repos from fixtures.yaml, so moving the GitHub demo
// org is a data edit there rather than a code change (proven for real by
// issue #9: the original org's owning account was banned and the demo org
// moved to a fresh one, Qloud-ltd-com, via exactly that mechanism — no org
// name is actually permanent). ADO_ORG is an environment variable instead
// of a constant for the same reason: the org itself (unlike the
// project/repo names within it) may need to move without a code change —
// see issue #155's own latest comment, which records the live org as
// dev.azure.com/seciq but treats that as the current answer, not a fixed
// one.
const (
	adoDemoProject  = "attestward-demo"
	adoDemoGoodRepo = "demo-good"
	adoDemoBadRepo  = "demo-bad"
)

// adoOrg resolves the Azure DevOps org to scan: ADO_ORG if set, "seciq"
// (the live demo org confirmed in issue #155's own latest comment)
// otherwise.
func adoOrg() string {
	if org := os.Getenv("ADO_ORG"); org != "" {
		return org
	}
	return "seciq"
}

// adoFixturesFile is fixturesFile's (integration_test.go) Azure DevOps
// twin: it reuses fixtureCheck's identical per-check {check_id, status,
// note} shape unchanged, adding only the Platform/Project preamble fields
// fixtures-ado.yaml's header carries that the GitHub-only fixtures.yaml
// schema has no equivalent for. Org/Project/Repos are read here purely as
// documentation/a schema-sanity anchor, NOT to configure the scan itself
// — see the constants above and adoOrg's own doc comment for why this
// test's actual scan parameters are fixed constants (or an env var) rather
// than sourced from this file the way the GitHub twin sources its org and
// repos from fixtures.yaml.
type adoFixturesFile struct {
	Platform   string                    `yaml:"platform"`
	Org        string                    `yaml:"org"`
	Project    string                    `yaml:"project"`
	Repos      []string                  `yaml:"repos"`
	OrgChecks  []fixtureCheck            `yaml:"org_checks"`
	RepoChecks map[string][]fixtureCheck `yaml:"repo_checks"`
}

func TestIntegration_ADODemoOrgMatchesFixtures(t *testing.T) {
	token := os.Getenv("AZURE_DEVOPS_EXT_PAT")
	if token == "" {
		t.Skip("AZURE_DEVOPS_EXT_PAT not set — skipping live integration test")
	}

	data, err := os.ReadFile("../../fixtures-ado.yaml")
	if err != nil {
		t.Fatalf("read fixtures-ado.yaml: %v", err)
	}
	var fx adoFixturesFile
	if err := yaml.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parse fixtures-ado.yaml: %v", err)
	}
	if fx.Platform != platformAzureDevOps {
		t.Fatalf("fixtures-ado.yaml platform = %q, want %q", fx.Platform, platformAzureDevOps)
	}

	org := adoOrg()
	repos := []string{adoDemoGoodRepo, adoDemoBadRepo}

	// repoLister/orgChecker/client are all left nil, exactly matching
	// buildScanDeps' real azuredevops branch in scan.go: there is no ADO
	// repo-listing/account-type support yet, so --repo (here, repos above)
	// must be supplied explicitly — resolveRepos returns the explicit list
	// unchanged without ever consulting a nil lister when it's non-empty.
	deps := scanDeps{
		collectors: defaultAzureDevOpsCollectors(org, adoDemoProject, token),
		stdout:     os.Stdout,
	}
	cfg := scanConfig{
		Platform:          platformAzureDevOps,
		Org:               org,
		Project:           adoDemoProject,
		Repos:             repos,
		ReleaseTagPattern: defaultReleaseTagPattern,
		LookbackReleases:  defaultLookbackReleases,
		LookbackMonths:    defaultLookbackMonths,
		Out:               t.TempDir(),
		// Concurrency left at zero deliberately: runCollectors' own
		// concurrency<=0 guard already defaults it, the same fallback the
		// real CLI path relies on via mergeScanConfig — no need to
		// duplicate that default here.
	}

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}

	// assertFixtureChecks (integration_test.go) already fails loudly —
	// via its own len(expected)==0 guard — rather than silently passing
	// if fixtures-ado.yaml's org_checks/repo_checks were ever an empty
	// skeleton again (e.g. reverted, or a fresh platform's fixtures file
	// mid-authoring, before it's ever been filled from a real scan): a
	// real scan always produces at least the org-scoped self-attestation
	// not-checkable results (mapping.BuildSelfAttestedResults sets
	// Scope.Org only, never Scope.Repo), so org_checks is never
	// legitimately empty once AZURE_DEVOPS_EXT_PAT is set and this test
	// actually runs against a live scan — an empty-skeleton state can
	// only ever read as a hard failure here, never as green.
	assertFixtureChecks(t, result.pack.Results, "", fx.OrgChecks)
	for _, repo := range repos {
		assertFixtureChecks(t, result.pack.Results, repo, fx.RepoChecks[repo])
	}
	assertADOFixturesCoverAllResults(t, result.pack.Results, fx)
}

// assertADOFixturesCoverAllResults is assertFixturesCoverAllResults'
// (integration_test.go) Azure DevOps twin: the identical reverse-coverage
// check — every CheckID the scan actually produced must have a fixture
// expectation somewhere in fixtures-ado.yaml, or a new ADO collector/check
// landed without fixtures-ado.yaml being updated to match. Duplicated
// rather than generalized over fixturesFile/adoFixturesFile: both structs
// already diverge (Platform/Project have no GitHub equivalent), and this
// epic's own ADO packages consistently choose ~10-30 lines of duplication
// over a shared cross-platform helper for exactly this kind of
// small, platform-parallel logic (see e.g. internal/collect/azuredevops/
// vdp/heuristics.go's own doc comment on the identical trade-off).
func assertADOFixturesCoverAllResults(t *testing.T, results []model.CheckResult, fx adoFixturesFile) {
	t.Helper()
	covered := map[string]bool{}
	for _, c := range fx.OrgChecks {
		covered[c.CheckID] = true
	}
	for _, checks := range fx.RepoChecks {
		for _, c := range checks {
			covered[c.CheckID] = true
		}
	}
	for _, r := range results {
		if !covered[r.CheckID] {
			t.Errorf("%s (repo=%q): scan produced this check but fixtures-ado.yaml has no expectation for it anywhere — a new collector/check landed without fixtures-ado.yaml being updated", r.CheckID, r.Scope.Repo)
		}
	}
}
