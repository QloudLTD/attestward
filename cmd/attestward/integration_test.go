//go:build integration

// Integration test (issue #15): runs a real `attestward scan` against the
// public demo org (see hack/demo-org-setup.sh, DECISIONS.md's D5) and
// asserts every result against fixtures.yaml — the API-drift tripwire the
// scheduled integration-scan.yaml workflow runs weekly. Requires
// GITHUB_TOKEN in the environment (a low-privilege, read-only PAT scoped
// to the demo org is enough — see CONTRIBUTING.md's "Integration tests"
// section); skips cleanly if unset, so `go test ./...` (no -tags
// integration) and a tagged run without the token both stay green rather
// than failing loud for an unrelated reason. integration-scan.yaml's own
// workflow step guards against this same skip behavior masking a genuinely
// missing CI secret — see that file.
package main

import (
	"context"
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	ghcollect "github.com/sioakim/attestward/internal/collect/github"
	"github.com/sioakim/attestward/internal/model"
)

type fixturesFile struct {
	Org        string                    `yaml:"org"`
	Repos      []string                  `yaml:"repos"`
	OrgChecks  []fixtureCheck            `yaml:"org_checks"`
	RepoChecks map[string][]fixtureCheck `yaml:"repo_checks"`
}

type fixtureCheck struct {
	CheckID string `yaml:"check_id"`
	Status  string `yaml:"status"`
	Note    string `yaml:"note,omitempty"`
}

func TestIntegration_DemoOrgMatchesFixtures(t *testing.T) {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		t.Skip("GITHUB_TOKEN not set — skipping live integration test")
	}

	data, err := os.ReadFile("../../fixtures.yaml")
	if err != nil {
		t.Fatalf("read fixtures.yaml: %v", err)
	}
	var fx fixturesFile
	if err := yaml.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parse fixtures.yaml: %v", err)
	}
	if fx.Org == "" || len(fx.Repos) == 0 {
		t.Fatalf("fixtures.yaml missing org/repos: %+v", fx)
	}

	client := ghcollect.NewClient(token)
	deps := scanDeps{
		repoLister: &restRepoLister{client: client.REST},
		orgChecker: &restOrgChecker{client: client.REST},
		client:     client,
		collectors: defaultCollectors(token),
		stdout:     os.Stdout,
	}
	cfg := scanConfig{
		Org:               fx.Org,
		Repos:             fx.Repos,
		ReleaseTagPattern: defaultReleaseTagPattern,
		LookbackReleases:  defaultLookbackReleases,
		LookbackMonths:    defaultLookbackMonths,
		Out:               t.TempDir(),
		Concurrency:       ghcollect.DefaultConcurrency,
	}

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}

	assertFixtureChecks(t, result.pack.Results, "", fx.OrgChecks)
	for _, repo := range fx.Repos {
		assertFixtureChecks(t, result.pack.Results, repo, fx.RepoChecks[repo])
	}
	assertFixturesCoverAllResults(t, result.pack.Results, fx)
}

func assertFixtureChecks(t *testing.T, results []model.CheckResult, repo string, expected []fixtureCheck) {
	t.Helper()
	if len(expected) == 0 {
		t.Fatalf("fixtures.yaml has no expectations for repo=%q — likely a fixtures.yaml bug, not a real empty case", repo)
	}
	byID := map[string]model.CheckResult{}
	for _, r := range results {
		if r.Scope.Repo == repo {
			byID[r.CheckID] = r
		}
	}
	for _, exp := range expected {
		got, ok := byID[exp.CheckID]
		if !ok {
			t.Errorf("%s (repo=%q): missing from scan results — collector removed, renamed, or repo scope mismatch", exp.CheckID, repo)
			continue
		}
		if string(got.Status) != exp.Status {
			t.Errorf("%s (repo=%q): status = %q, want %q (reason=%q)", exp.CheckID, repo, got.Status, exp.Status, got.Reason)
		}
	}
}

// assertFixturesCoverAllResults is the reverse of assertFixtureChecks:
// fails loudly if the scan produced a CheckID fixtures.yaml has no
// expectation for at all — e.g. a new collector's checks landing without
// fixtures.yaml being updated to match. Without this, an uncovered check
// would pass unasserted forever rather than failing until someone
// remembers to append it here.
func assertFixturesCoverAllResults(t *testing.T, results []model.CheckResult, fx fixturesFile) {
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
			t.Errorf("%s (repo=%q): scan produced this check but fixtures.yaml has no expectation for it anywhere — a new collector/check landed without fixtures.yaml being updated", r.CheckID, r.Scope.Repo)
		}
	}
}
