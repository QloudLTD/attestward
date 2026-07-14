package vdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
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
	c := New("ghp_test-token")
	c.newClientForTest = func(token string) *ghcollect.Client {
		client := ghcollect.NewClient(token)
		baseURL, err := url.Parse(server.URL + "/")
		if err != nil {
			t.Fatalf("parse test server URL: %v", err)
		}
		client.REST.BaseURL = baseURL
		return client
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
