package vdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/model"
)

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode fixture response: %v", err)
	}
}

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func newCollectorForServer(t *testing.T, server *httptest.Server) *Collector {
	t.Helper()
	c := New("ghp_test-token", ghcollect.ClientConfig{})
	c.newClientForTest = func(token string) *ghcollect.Client {
		client := ghcollect.NewClient(token, ghcollect.ClientConfig{})
		baseURL, err := url.Parse(server.URL + "/")
		if err != nil {
			t.Fatalf("parse test server URL: %v", err)
		}
		client.REST.BaseURL = baseURL
		return client
	}
	return c
}

// newGHESCollectorForServer mirrors newCollectorForServer, but resolves
// each per-repo client through ghcollect.ResolveHostConfig the way a real
// --github-url scan would (issue #13's GHES epic), and wraps handler in
// http.StripPrefix("/api/v3", handler) — go-github's request builder adds
// that prefix for a GHES base URL, and stripping it before dispatch lets a
// GHES scenario reuse this package's existing github.com-shaped mux
// helpers (registerSecurityMDLookup et al.) unmodified, rather than
// hand-duplicating every candidatePaths entry under a second prefix.
func newGHESCollectorForServer(t *testing.T, handler http.Handler) *Collector {
	t.Helper()
	server := httptest.NewServer(http.StripPrefix("/api/v3", handler))
	t.Cleanup(server.Close)

	cfg, err := ghcollect.ResolveHostConfig(server.URL, "")
	if err != nil {
		t.Fatalf("ResolveHostConfig: %v", err)
	}
	c := New("ghp_test-token", cfg)
	c.newClientForTest = func(token string) *ghcollect.Client {
		return ghcollect.NewClient(token, cfg)
	}
	return c
}

func byID(results []model.CheckResult) map[string]model.CheckResult {
	m := map[string]model.CheckResult{}
	for _, r := range results {
		m[r.CheckID] = r
	}
	return m
}

func registerNotFound(t *testing.T, mux *http.ServeMux, path string) {
	t.Helper()
	mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
}

// registerSecurityMDLookup registers 404 for every candidate path in both
// the repo and the org's .github repo, except where content is supplied
// in found (keyed by "owner:path", e.g. "widgets:SECURITY.md" or
// ".github:.github/SECURITY.md"), which serves that content instead — so
// a test states only what it wants resolved, and every other candidate
// naturally 404s exactly once, mirroring resolveSecurityMD's own
// try-next-path behavior without double-registering any single path
// (composing a blanket "register everything absent" pass with a separate
// override pass on the same mux panics: net/http.ServeMux rejects an
// exact-duplicate pattern).
func registerSecurityMDLookup(t *testing.T, mux *http.ServeMux, org, repo string, found map[string]string) {
	t.Helper()
	for _, owner := range []string{repo, ".github"} {
		for _, path := range candidatePaths {
			key := owner + ":" + path
			fullPath := "/repos/" + org + "/" + owner + "/contents/" + path
			if content, ok := found[key]; ok {
				mux.HandleFunc(fullPath, func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusOK, map[string]any{"content": content, "sha": "content-sha", "type": "file"})
				})
				continue
			}
			registerNotFound(t, mux, fullPath)
		}
	}
}

func registerPrivateReporting(t *testing.T, mux *http.ServeMux, org, repo string, enabled bool) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/private-vulnerability-reporting", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"enabled": enabled})
	})
}

func registerPrivateReportingStatus(t *testing.T, mux *http.ServeMux, org, repo string, status int) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/private-vulnerability-reporting", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, status, map[string]any{"message": "not found"})
	})
}

func registerDotGithubRepoExists(t *testing.T, mux *http.ServeMux, org string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/.github", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+org+"/.github" {
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"name": ".github", "default_branch": "main"})
	})
}

func registerDotGithubRepoMissing(t *testing.T, mux *http.ServeMux, org string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/.github", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/"+org+"/.github" {
			return
		}
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
}

const goodSecurityMD = `# Security Policy

## Reporting a vulnerability

- Preferred: [GitHub private vulnerability reporting](../../security/advisories/new)
  ("Report a vulnerability" on the Security tab).
`

const vagueSecurityMD = `# Security Policy

We take security seriously and appreciate responsible disclosure.
`

func TestCollect_SecurityMDInRepoRoot_AllRepoChecksPass(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, map[string]string{repo + ":SECURITY.md": goodSecurityMD})
	registerPrivateReporting(t, mux, org, repo, true)
	registerDotGithubRepoMissing(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[securityMDID].Status; got != model.StatusVerifiedPass {
		t.Errorf("security-md = %q, want verified-pass; reason=%q", got, m[securityMDID].Reason)
	}
	if got := m[securityMDID].Facts["from_org_fallback"]; got != false {
		t.Errorf("from_org_fallback = %v, want false", got)
	}
	if got := m[intakeChannelID].Status; got != model.StatusVerifiedPass {
		t.Errorf("intake-channel = %q, want verified-pass; reason=%q", got, m[intakeChannelID].Reason)
	}
	if got := m[privateReportingID].Status; got != model.StatusVerifiedPass {
		t.Errorf("private-reporting = %q, want verified-pass; reason=%q", got, m[privateReportingID].Reason)
	}
}

// TestCollect_GHESHost_SecurityMDInRepoRoot_AllRepoChecksPass mirrors
// TestCollect_SecurityMDInRepoRoot_AllRepoChecksPass against a GHES-shaped
// base URL (issue #13's GHES epic) — securityMDID/intakeChannelID were
// audited as ghcollect.GHESNoteSupported (basic contents reads), while
// privateReportingID is this package's one ghcollect.GHESNoteUnverified
// check (see vdp.go's checkGHESNotes): private-vulnerability-reporting is
// recent enough on github.com that its GHES availability isn't verified.
// This scenario still exercises it (registerPrivateReporting fixtures a
// 200 either way) to prove routing works regardless of that open
// question — the Reason/Facts honesty is unaffected by which host served
// the response. Alongside (not replacing) the github.com scenario, so
// both drift together.
func TestCollect_GHESHost_SecurityMDInRepoRoot_AllRepoChecksPass(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, map[string]string{repo + ":SECURITY.md": goodSecurityMD})
	registerPrivateReporting(t, mux, org, repo, true)
	registerDotGithubRepoMissing(t, mux, org)

	c := newGHESCollectorForServer(t, mux)
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	for _, id := range []string{securityMDID, intakeChannelID, privateReportingID} {
		if got := m[id].Status; got != model.StatusVerifiedPass {
			t.Errorf("%s = %q, want verified-pass; reason=%q", id, got, m[id].Reason)
		}
		for _, p := range m[id].Provenance {
			if !strings.HasPrefix(p.Endpoint, "/api/v3") {
				t.Errorf("%s provenance Endpoint = %q, want a /api/v3 prefix (GHES routing)", id, p.Endpoint)
			}
		}
	}
}

func TestCollect_SecurityMDResolvesViaDotGithubDir_PreferredOverRoot(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, map[string]string{
		repo + ":.github/SECURITY.md": goodSecurityMD,
		repo + ":SECURITY.md":         goodSecurityMD,
	})
	registerPrivateReporting(t, mux, org, repo, false)
	registerDotGithubRepoMissing(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[securityMDID].Facts["resolved_path"]; got != ".github/SECURITY.md" {
		t.Errorf("resolved_path = %v, want %q (.github/ takes precedence over repo root)", got, ".github/SECURITY.md")
	}
}

func TestCollect_SecurityMDMissingInRepo_ResolvesViaOrgFallback(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, map[string]string{".github:SECURITY.md": goodSecurityMD})
	registerPrivateReporting(t, mux, org, repo, false)
	registerDotGithubRepoExists(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[securityMDID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("security-md = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}
	if got.Facts["from_org_fallback"] != true {
		t.Errorf("from_org_fallback = %v, want true", got.Facts["from_org_fallback"])
	}
	if got.Facts["resolved_repo"] != org+"/.github" {
		t.Errorf("resolved_repo = %v, want %q", got.Facts["resolved_repo"], org+"/.github")
	}
}

func TestCollect_SecurityMDNowhere_VerifiedFail(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, nil)
	registerPrivateReporting(t, mux, org, repo, false)
	registerDotGithubRepoMissing(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[securityMDID].Status; got != model.StatusVerifiedFail {
		t.Errorf("security-md = %q, want verified-fail; reason=%q", got, m[securityMDID].Reason)
	}
	if got := m[intakeChannelID].Status; got != model.StatusVerifiedFail {
		t.Errorf("intake-channel = %q, want verified-fail (no file to advertise a channel); reason=%q", got, m[intakeChannelID].Reason)
	}
}

// TestCollect_SecurityMDExistsButUndecodable_NotCheckableNotFail guards
// against a genuinely-existing SECURITY.md whose content the Contents API
// can't return inline (encoding "none" — GitHub's documented behavior for
// files over 1MB) being silently misreported as "no SECURITY.md found"
// (verified-fail) instead of not-checkable. A file that demonstrably
// exists but couldn't be read is a real error, not a confirmed absence.
func TestCollect_SecurityMDExistsButUndecodable_NotCheckableNotFail(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/SECURITY.md", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"type": "file", "encoding": "none", "size": 2_000_000, "name": "SECURITY.md"})
	})
	registerPrivateReporting(t, mux, org, repo, false)
	registerDotGithubRepoMissing(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[securityMDID].Status; got != model.StatusNotCheckable {
		t.Errorf("security-md = %q, want not-checkable (file exists but couldn't be decoded — a real error, not a confirmed absence); reason=%q", got, m[securityMDID].Reason)
	}
}

func TestCollect_VagueSecurityMD_IntakeChannelPartial(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, map[string]string{repo + ":SECURITY.md": vagueSecurityMD})
	registerPrivateReporting(t, mux, org, repo, false)
	registerDotGithubRepoMissing(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[securityMDID].Status; got != model.StatusVerifiedPass {
		t.Errorf("security-md = %q, want verified-pass (the file exists, even if vague); reason=%q", got, m[securityMDID].Reason)
	}
	if got := m[intakeChannelID].Status; got != model.StatusPartial {
		t.Errorf("intake-channel = %q, want partial; reason=%q", got, m[intakeChannelID].Reason)
	}
}

func TestCollect_PrivateReportingPlanGated404_NotCheckable(t *testing.T) {
	org, repo := "acme", "private-repo"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, map[string]string{repo + ":SECURITY.md": goodSecurityMD})
	registerPrivateReportingStatus(t, mux, org, repo, http.StatusNotFound)
	registerDotGithubRepoMissing(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[privateReportingID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("private-reporting = %q, want not-checkable (undocumented 404 semantics, not asserted as disabled); reason=%q", got.Status, got.Reason)
	}
	// security-md and intake-channel must be unaffected by
	// private-reporting's own failure — a completely independent API call.
	if got := m[securityMDID].Status; got != model.StatusVerifiedPass {
		t.Errorf("security-md = %q, want verified-pass (independent of private-reporting's failure); reason=%q", got, m[securityMDID].Reason)
	}
}

func TestCollect_PrivateReportingForbidden_NotCheckablePermissionReason(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, map[string]string{repo + ":SECURITY.md": goodSecurityMD})
	registerPrivateReportingStatus(t, mux, org, repo, http.StatusForbidden)
	registerDotGithubRepoMissing(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[privateReportingID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("private-reporting = %q, want not-checkable", got.Status)
	}
	if !strings.Contains(got.Reason, "permission") {
		t.Errorf("private-reporting reason = %q, want it to name a permission problem (not the plan-gated 404 wording, a distinct branch)", got.Reason)
	}
}

func TestCollect_SecurityMDResolveFailure403_SecurityMDAndIntakeChannelNotCheckable(t *testing.T) {
	org, repo := "acme", "forbidden-repo"
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/SECURITY.md", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})
	registerPrivateReporting(t, mux, org, repo, true)
	registerDotGithubRepoMissing(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[securityMDID].Status; got != model.StatusNotCheckable {
		t.Errorf("security-md = %q, want not-checkable; reason=%q", got, m[securityMDID].Reason)
	}
	if got := m[intakeChannelID].Status; got != model.StatusNotCheckable {
		t.Errorf("intake-channel = %q, want not-checkable; reason=%q", got, m[intakeChannelID].Reason)
	}
	// private-reporting must be unaffected — independent API call.
	if got := m[privateReportingID].Status; got != model.StatusVerifiedPass {
		t.Errorf("private-reporting = %q, want verified-pass (independent of security-md's failure); reason=%q", got, m[privateReportingID].Reason)
	}
}

func TestCollect_OrgSecurityPolicy_NoDotGithubRepo_NotCheckable(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, nil)
	registerPrivateReporting(t, mux, org, repo, false)
	registerDotGithubRepoMissing(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[securityPolicyOrgID].Status; got != model.StatusNotCheckable {
		t.Errorf("security-policy-org = %q, want not-checkable; reason=%q", got, m[securityPolicyOrgID].Reason)
	}
}

func TestCollect_OrgSecurityPolicy_DotGithubRepoExistsNoSecurityMD_VerifiedFail(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, nil)
	registerPrivateReporting(t, mux, org, repo, false)
	registerDotGithubRepoExists(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[securityPolicyOrgID].Status; got != model.StatusVerifiedFail {
		t.Errorf("security-policy-org = %q, want verified-fail (.github repo exists but empty); reason=%q", got, m[securityPolicyOrgID].Reason)
	}
}

func TestCollect_OrgSecurityPolicy_DotGithubRepoHasSecurityMD_VerifiedPass(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerSecurityMDLookup(t, mux, org, repo, map[string]string{".github:SECURITY.md": goodSecurityMD})
	registerPrivateReporting(t, mux, org, repo, false)
	registerDotGithubRepoExists(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[securityPolicyOrgID].Status; got != model.StatusVerifiedPass {
		t.Errorf("security-policy-org = %q, want verified-pass; reason=%q", got, m[securityPolicyOrgID].Reason)
	}
}

func TestCollect_PreCanceledContextProducesNotCheckableNotPanic(t *testing.T) {
	org, repo := "acme", "canceled-repo"
	mux := http.NewServeMux()
	registerDotGithubRepoMissing(t, mux, org)

	c := newCollectorForServer(t, newTestServer(t, mux))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := c.Collect(ctx, collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range repoCheckIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable for a pre-canceled context", id, got)
		}
	}
}

func TestChecksRegistered(t *testing.T) {
	for _, id := range checkIDs {
		meta, ok := collect.Lookup(id)
		if !ok {
			t.Errorf("check %s not registered", id)
			continue
		}
		if meta.Collector != collectorID {
			t.Errorf("%s Collector = %q, want %q", id, meta.Collector, collectorID)
		}
		if meta.TokenScope == "" {
			t.Errorf("%s TokenScope is empty", id)
		}
	}
}

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce (see orgsecurity's own copy of this
// pattern for the full rationale). C10.vdp.intake-channel is the only
// check in this package with a partial branch; the other three are
// plain pass/fail/not-checkable.
var checkWantStatuses = map[string][]model.Status{
	securityMDID:        {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	intakeChannelID:     {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	privateReportingID:  {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	securityPolicyOrgID: {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) /`)

// TestCollect_RegisteredMetadataCompleteForChecksReference is
// orgsecurity's TestCollect_RegisteredMetadataCompleteForChecksReference,
// replicated per the pattern that PR validated: see that test's own doc
// comment for the full rationale (exact Rubric key-set equality per check,
// GET/HEAD-only Endpoints enforcing ADR-0004, orphaned-key detection).
func TestCollect_RegisteredMetadataCompleteForChecksReference(t *testing.T) {
	if len(checkRubrics) != len(checkTitles) {
		t.Errorf("checkRubrics has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRubrics), len(checkTitles))
	}
	if len(checkEndpoints) != len(checkTitles) {
		t.Errorf("checkEndpoints has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkEndpoints), len(checkTitles))
	}

	for id := range checkTitles {
		meta, ok := collect.Lookup(id)
		if !ok {
			t.Fatalf("check %q not found in the collect.CheckMeta registry", id)
		}

		want, ok := checkWantStatuses[id]
		if !ok {
			t.Fatalf("checkWantStatuses is missing an entry for %q — add the statuses this check can actually produce", id)
		}
		wantSet := make(map[model.Status]bool, len(want))
		for _, s := range want {
			wantSet[s] = true
		}
		for s := range wantSet {
			if meta.Rubric[s] == "" {
				t.Errorf("%s: Rubric[%s] is empty, want a concrete explanation", id, s)
			}
		}
		for s := range meta.Rubric {
			if !wantSet[s] {
				t.Errorf("%s: Rubric has an entry for status %q, but checkWantStatuses says this check can't produce it — either the rubric is wrong or checkWantStatuses is stale", id, s)
			}
		}

		if len(meta.Endpoints) == 0 {
			t.Errorf("%s: Endpoints is empty, want at least one", id)
		}
		for _, e := range meta.Endpoints {
			if !endpointVerbRE.MatchString(e) {
				t.Errorf("%s: Endpoints entry %q isn't GET/HEAD — this project is read-only forever (ADR-0004)", id, e)
			}
		}

		if meta.FixtureRef == "" {
			t.Errorf("%s: FixtureRef is empty", id)
		}
	}
}

// TestPrivateReportingRemediationUsesCurrentSettingsPath locks in the
// current GitHub Settings navigation ("Security" sidebar section ->
// "Advanced Security", not the pre-GHAS-unbundling "Code security"
// label) for enabling private vulnerability reporting. Verified against
// docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository.
func TestPrivateReportingRemediationUsesCurrentSettingsPath(t *testing.T) {
	remediation := checkRemediations[privateReportingID]
	if strings.Contains(remediation, "Code security ->") {
		t.Errorf("C10.vdp.private-reporting remediation uses the stale pre-GHAS-unbundling \"Code security\" settings path: %q", remediation)
	}
	if !strings.Contains(remediation, "Advanced Security") {
		t.Errorf("C10.vdp.private-reporting remediation should name the current \"Advanced Security\" settings section: %q", remediation)
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue
// #10). Unlike the gogs and Azure DevOps twins, all four checks here are
// real — GitHub genuinely has both private vulnerability reporting and a
// ".github"-repo org-wide-default fallback — so the state matrix must reach
// thirteen distinct (check, status) pairs across four checks: security-md
// {pass, fail, not-checkable}, intake-channel {pass, partial, fail,
// not-checkable}, private-reporting {pass, fail, not-checkable}, and
// security-policy-org {pass, fail, not-checkable} — not just two.
// (An earlier draft of this comment, and the commit that introduced it,
// both miscounted this — nine and ten respectively; found in review.)
// Every state below reuses an existing test's exact mux setup rather than
// inventing new fixtures, so it is testing the same server responses this
// file's own TestCollect_* functions already individually verified produce
// the status named.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	pass, fail, partial, nc := model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable

	states := []struct {
		name      string
		org, repo string
		mux       func(t *testing.T, org, repo string) *http.ServeMux
		want      map[string]model.Status
	}{
		{"repo-root pass, private-reporting enabled, no org fallback", "acme", "widgets",
			func(t *testing.T, org, repo string) *http.ServeMux {
				mux := http.NewServeMux()
				registerSecurityMDLookup(t, mux, org, repo, map[string]string{repo + ":SECURITY.md": goodSecurityMD})
				registerPrivateReporting(t, mux, org, repo, true)
				registerDotGithubRepoMissing(t, mux, org)
				return mux
			}, map[string]model.Status{securityMDID: pass, intakeChannelID: pass, privateReportingID: pass, securityPolicyOrgID: nc}},

		{"org .github fallback has SECURITY.md", "acme", "widgets",
			func(t *testing.T, org, repo string) *http.ServeMux {
				mux := http.NewServeMux()
				registerSecurityMDLookup(t, mux, org, repo, map[string]string{".github:SECURITY.md": goodSecurityMD})
				registerPrivateReporting(t, mux, org, repo, false)
				registerDotGithubRepoExists(t, mux, org)
				return mux
			}, map[string]model.Status{securityMDID: pass, intakeChannelID: pass, privateReportingID: fail, securityPolicyOrgID: pass}},

		{"resolved but vague", "acme", "widgets",
			func(t *testing.T, org, repo string) *http.ServeMux {
				mux := http.NewServeMux()
				registerSecurityMDLookup(t, mux, org, repo, map[string]string{repo + ":SECURITY.md": vagueSecurityMD})
				registerPrivateReporting(t, mux, org, repo, false)
				registerDotGithubRepoMissing(t, mux, org)
				return mux
			}, map[string]model.Status{securityMDID: pass, intakeChannelID: partial, privateReportingID: fail, securityPolicyOrgID: nc}},

		{"absent everywhere, .github missing", "acme", "widgets",
			func(t *testing.T, org, repo string) *http.ServeMux {
				mux := http.NewServeMux()
				registerSecurityMDLookup(t, mux, org, repo, nil)
				registerPrivateReporting(t, mux, org, repo, false)
				registerDotGithubRepoMissing(t, mux, org)
				return mux
			}, map[string]model.Status{securityMDID: fail, intakeChannelID: fail, privateReportingID: fail, securityPolicyOrgID: nc}},

		{".github exists but has no SECURITY.md", "acme", "widgets",
			func(t *testing.T, org, repo string) *http.ServeMux {
				mux := http.NewServeMux()
				registerSecurityMDLookup(t, mux, org, repo, nil)
				registerPrivateReporting(t, mux, org, repo, false)
				registerDotGithubRepoExists(t, mux, org)
				return mux
			}, map[string]model.Status{securityMDID: fail, intakeChannelID: fail, privateReportingID: fail, securityPolicyOrgID: fail}},

		{"private-reporting plan-gated 404", "acme", "private-repo",
			func(t *testing.T, org, repo string) *http.ServeMux {
				mux := http.NewServeMux()
				registerSecurityMDLookup(t, mux, org, repo, map[string]string{repo + ":SECURITY.md": goodSecurityMD})
				registerPrivateReportingStatus(t, mux, org, repo, http.StatusNotFound)
				registerDotGithubRepoMissing(t, mux, org)
				return mux
			}, map[string]model.Status{securityMDID: pass, intakeChannelID: pass, privateReportingID: nc, securityPolicyOrgID: nc}},

		{"security-md resolve failure (403)", "acme", "forbidden-repo",
			func(t *testing.T, org, repo string) *http.ServeMux {
				mux := http.NewServeMux()
				mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/SECURITY.md", func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
				})
				registerPrivateReporting(t, mux, org, repo, true)
				registerDotGithubRepoMissing(t, mux, org)
				return mux
			}, map[string]model.Status{securityMDID: nc, intakeChannelID: nc, privateReportingID: pass, securityPolicyOrgID: nc}},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			c := newCollectorForServer(t, newTestServer(t, st.mux(t, st.org, st.repo)))
			results, err := c.Collect(context.Background(), collect.Scope{Org: st.org, Repos: []string{st.repo}})
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			got := map[string]model.Status{}
			for _, r := range results {
				got[r.CheckID] = r.Status
			}
			if len(got) != len(st.want) {
				t.Fatalf("got %d results, want %d", len(got), len(st.want))
			}
			for id, want := range st.want {
				if got[id] != want {
					t.Errorf("%s = %q, want %q", id, got[id], want)
				}
			}
			all = append(all, results...)
		})
	}

	collecttest.AssertRubricsMatchObservedBehaviour(t, "github", collectorID, all)
}
