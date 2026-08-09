//go:build integration

// Integration test (Gogs issue #9): the Gogs twin of
// TestIntegration_DemoOrgMatchesFixtures and its Azure DevOps sibling. Runs
// a real `attestward scan --platform gogs` and asserts every produced
// result against fixtures-gogs.yaml.
//
// # This one cannot run in CI, and that is deliberate
//
// The GitHub and Azure DevOps integration tests run on hosted CI against
// public demo estates. This one cannot: the Gogs instance it targets is
// reachable only from one network — a Cloudflare WAF rule restricts the
// public hostname to a single WAN IP, and git-over-SSH is LAN-only — and
// this repo has no self-hosted runners any more.
//
// So it is opt-in and locally run, guarded on GOGS_TOKEN *and* GOGS_URL,
// and it skips cleanly when either is unset. That means an untagged `go
// test ./...` and a tagged run without credentials both stay green, exactly
// like the two existing integration tests.
//
// Wiring this into a CI job would be worse than leaving it out: the job
// would either fail for a network reason unrelated to any change, or —
// far worse — skip silently and render as a passing check, which reads as
// "the live Gogs scan is verified" to anyone glancing at the run. An
// honestly absent test beats a green one that never ran.
//
// To run it:
//
//	GOGS_URL=https://gogs.example.com GOGS_TOKEN=... go test -tags integration ./cmd/attestward -run TestIntegration_Gogs -v
package main

import (
	"context"
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"gitlab.com/sioakeim/attestward/internal/model"
)

// gogsFixturesFile mirrors adoFixturesFile's role, reusing fixtureCheck's
// {check_id, status, note} shape unchanged. There is no Project field:
// Gogs has no project concept.
//
// Org and Repos ARE used to configure the scan here, unlike the ADO twin's
// fixed constants — the account and repo this test targets are the ones the
// fixture table was captured from, and reading both from the same file
// keeps them from drifting apart silently.
type gogsFixturesFile struct {
	Platform   string                    `yaml:"platform"`
	Org        string                    `yaml:"org"`
	Repos      []string                  `yaml:"repos"`
	OrgChecks  []fixtureCheck            `yaml:"org_checks"`
	RepoChecks map[string][]fixtureCheck `yaml:"repo_checks"`
}

func TestIntegration_GogsMatchesFixtures(t *testing.T) {
	token := os.Getenv("GOGS_TOKEN")
	baseURL := os.Getenv("GOGS_URL")
	if token == "" || baseURL == "" {
		t.Skip("GOGS_TOKEN and GOGS_URL not both set — skipping live Gogs integration test (see this file's doc comment for why it is local-only)")
	}

	data, err := os.ReadFile("../../fixtures-gogs.yaml")
	if err != nil {
		t.Fatalf("read fixtures-gogs.yaml: %v", err)
	}
	var fx gogsFixturesFile
	if err := yaml.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parse fixtures-gogs.yaml: %v", err)
	}
	if fx.Platform != platformGogs {
		t.Fatalf("fixtures-gogs.yaml platform = %q, want %q", fx.Platform, platformGogs)
	}
	if fx.Org == "" || len(fx.Repos) == 0 {
		t.Fatal("fixtures-gogs.yaml names no org or no repos, so this test would assert nothing")
	}

	cfg := scanConfig{
		Platform:          platformGogs,
		GogsURL:           baseURL,
		Org:               fx.Org,
		Repos:             fx.Repos,
		ReleaseTagPattern: defaultReleaseTagPattern,
		LookbackReleases:  defaultLookbackReleases,
		LookbackMonths:    defaultLookbackMonths,
		Out:               t.TempDir(),
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("the fixture file describes a config the CLI would reject: %v", err)
	}

	// Built through buildScanDeps rather than by assembling scanDeps by
	// hand, so this exercises the same wiring the shipped binary uses —
	// including the repo lister, which the ADO twin has no equivalent of.
	deps, err := buildScanDeps(cfg, token, os.Stdout)
	if err != nil {
		t.Fatalf("buildScanDeps: %v", err)
	}

	result, err := runScan(context.Background(), cfg, nil, deps)
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}

	assertFixtureChecks(t, result.pack.Results, "", fx.OrgChecks)
	for _, repo := range fx.Repos {
		assertFixtureChecks(t, result.pack.Results, repo, fx.RepoChecks[repo])
	}
	assertGogsFixturesCoverAllResults(t, result.pack.Results, fx)

	// The two positive results are the whole of what this platform can
	// prove, so they are asserted by name rather than only by the table
	// above: if a Gogs API change ever turned them not-checkable, every
	// per-check assertion would still pass against a table regenerated
	// from that same broken scan. This is the one thing a regenerated
	// fixture table cannot protect.
	verified := 0
	for _, r := range result.pack.Results {
		if r.Status == "verified-pass" {
			verified++
		}
	}
	if verified == 0 {
		t.Error("the scan produced no verified-pass result at all — Gogs' only positive evidence (C10 security-md and intake-channel) has stopped working")
	}
}

// assertGogsFixturesCoverAllResults is the Gogs counterpart of the two
// existing coverage assertions: every result the scan produced must appear
// in the fixture table, so a newly added check can never slip into a pack
// without someone deciding what its expected status is.
func assertGogsFixturesCoverAllResults(t *testing.T, results []model.CheckResult, fx gogsFixturesFile) {
	t.Helper()

	expected := map[string]bool{}
	for _, c := range fx.OrgChecks {
		expected[""+"\x00"+c.CheckID] = true
	}
	for repo, checks := range fx.RepoChecks {
		for _, c := range checks {
			expected[repo+"\x00"+c.CheckID] = true
		}
	}

	for _, r := range results {
		key := r.Scope.Repo + "\x00" + r.CheckID
		if !expected[key] {
			t.Errorf("result %s (repo %q) has no entry in fixtures-gogs.yaml — add it with the status you expect rather than leaving it unasserted", r.CheckID, r.Scope.Repo)
		}
	}
}
