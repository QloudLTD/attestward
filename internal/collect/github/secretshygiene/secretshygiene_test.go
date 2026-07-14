package secretshygiene

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

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

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

func newCollectorForServer(t *testing.T, server *httptest.Server) *Collector {
	t.Helper()
	c := New("ghp_test-token")
	c.newClientForTest = func(token string) *ghcollect.Client {
		client := ghcollect.NewClient(token)
		baseURL, err := url.Parse(server.URL + "/")
		if err != nil {
			t.Errorf("parse test server URL: %v", err)
			return client
		}
		client.REST.BaseURL = baseURL
		return client
	}
	return c
}

// orgHandler registers a bare, no-permission-fields org response so tests
// focused on repo-level checks don't also need to reason about the
// org-level check's own not-checkable path.
func orgHandler(t *testing.T, mux *http.ServeMux, org string) {
	t.Helper()
	mux.HandleFunc("/orgs/"+org, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"login": org})
	})
}

func byID(results []model.CheckResult) map[string]model.CheckResult {
	m := map[string]model.CheckResult{}
	for _, r := range results {
		m[r.CheckID] = r
	}
	return m
}

func TestCollect_PublicRepoFullyEnabled(t *testing.T) {
	mux := http.NewServeMux()
	orgHandler(t, mux, "attestor-demo")
	mux.HandleFunc("/repos/attestor-demo/good-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": false,
			"security_and_analysis": map[string]any{
				"secret_scanning":                 map[string]any{"status": "enabled"},
				"secret_scanning_push_protection": map[string]any{"status": "enabled"},
			},
		})
	})
	mux.HandleFunc("/repos/attestor-demo/good-repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: []string{"good-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range []string{"C04.secrets.scanning-enabled", "C04.secrets.push-protection", "C04.deps.dependabot-alerts"} {
		if got := m[id].Status; got != model.StatusVerifiedPass {
			t.Errorf("%s status = %q, want verified-pass; reason=%q", id, got, m[id].Reason)
		}
	}
	if got := m["C04.secrets.advanced-security"].Status; got != model.StatusNotCheckable {
		t.Errorf("advanced-security status = %q, want not-checkable (not applicable to public repos)", got)
	}
}

// TestCollect_ProvenanceSplitByAPICall pins the two-independent-calls
// provenance attribution: scanning/push-protection/advanced-security depend
// only on Repositories.Get, and dependabot-alerts depends only on the
// separate GetVulnerabilityAlerts call — each result's provenance must name
// the endpoint that actually backs it, not the other call's. Without this,
// a swapped or combined provenance list would still make every other test
// in this file pass.
func TestCollect_ProvenanceSplitByAPICall(t *testing.T) {
	mux := http.NewServeMux()
	orgHandler(t, mux, "attestor-demo")
	mux.HandleFunc("/repos/attestor-demo/good-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": false,
			"security_and_analysis": map[string]any{
				"secret_scanning":                 map[string]any{"status": "enabled"},
				"secret_scanning_push_protection": map[string]any{"status": "enabled"},
			},
		})
	})
	mux.HandleFunc("/repos/attestor-demo/good-repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: []string{"good-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	for _, id := range []string{"C04.secrets.scanning-enabled", "C04.secrets.push-protection", "C04.secrets.advanced-security"} {
		prov := m[id].Provenance
		if len(prov) != 1 {
			t.Fatalf("%s Provenance = %v, want exactly 1 entry (the repo fetch)", id, prov)
		}
		if !strings.HasSuffix(prov[0].Endpoint, "/repos/attestor-demo/good-repo") {
			t.Errorf("%s Provenance[0].Endpoint = %q, want the repo-fetch endpoint", id, prov[0].Endpoint)
		}
	}

	depProv := m["C04.deps.dependabot-alerts"].Provenance
	if len(depProv) != 1 {
		t.Fatalf("dependabot-alerts Provenance = %v, want exactly 1 entry (the vulnerability-alerts call)", depProv)
	}
	if !strings.HasSuffix(depProv[0].Endpoint, "/vulnerability-alerts") {
		t.Errorf("dependabot-alerts Provenance[0].Endpoint = %q, want the vulnerability-alerts endpoint", depProv[0].Endpoint)
	}
}

func TestCollect_PublicRepoSecretScanningOffIsRealFail(t *testing.T) {
	mux := http.NewServeMux()
	orgHandler(t, mux, "attestor-demo")
	mux.HandleFunc("/repos/attestor-demo/bad-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": false,
			"security_and_analysis": map[string]any{
				"secret_scanning":                 map[string]any{"status": "disabled"},
				"secret_scanning_push_protection": map[string]any{"status": "disabled"},
			},
		})
	})
	mux.HandleFunc("/repos/attestor-demo/bad-repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: []string{"bad-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m["C04.secrets.scanning-enabled"].Status; got != model.StatusVerifiedFail {
		t.Errorf("scanning-enabled status = %q, want verified-fail — public repos get this free, no plan excuse", got)
	}
	if got := m["C04.secrets.push-protection"].Status; got != model.StatusVerifiedFail {
		t.Errorf("push-protection status = %q, want verified-fail", got)
	}
}

func TestCollect_PrivateRepoNoGHASNotCheckableNotFail(t *testing.T) {
	mux := http.NewServeMux()
	orgHandler(t, mux, "attestor-demo")
	mux.HandleFunc("/repos/attestor-demo/private-no-ghas", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": true,
			"security_and_analysis": map[string]any{
				"advanced_security":               map[string]any{"status": "disabled"},
				"secret_scanning":                 map[string]any{"status": "disabled"},
				"secret_scanning_push_protection": map[string]any{"status": "disabled"},
			},
		})
	})
	mux.HandleFunc("/repos/attestor-demo/private-no-ghas/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: []string{"private-no-ghas"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range []string{"C04.secrets.scanning-enabled", "C04.secrets.push-protection"} {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable — can't fault an unlicensed feature; reason=%q", id, got, m[id].Reason)
		}
		if !strings.Contains(m[id].Reason, "Advanced Security") {
			t.Errorf("%s Reason = %q, want it to mention Advanced Security licensing", id, m[id].Reason)
		}
	}
	// advanced-security itself is a real, directly answerable question
	// regardless of its own value — this must be a genuine fail, not
	// not-checkable, or the org would never see that it's missing GHAS.
	if got := m["C04.secrets.advanced-security"].Status; got != model.StatusVerifiedFail {
		t.Errorf("advanced-security status = %q, want verified-fail (GHAS itself is directly observable and off)", got)
	}
}

func TestCollect_PrivateRepoWithGHASRealFailWhenFeatureOff(t *testing.T) {
	mux := http.NewServeMux()
	orgHandler(t, mux, "attestor-demo")
	mux.HandleFunc("/repos/attestor-demo/private-ghas-partial", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": true,
			"security_and_analysis": map[string]any{
				"advanced_security":               map[string]any{"status": "enabled"},
				"secret_scanning":                 map[string]any{"status": "disabled"},
				"secret_scanning_push_protection": map[string]any{"status": "enabled"},
			},
		})
	})
	mux.HandleFunc("/repos/attestor-demo/private-ghas-partial/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: []string{"private-ghas-partial"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m["C04.secrets.scanning-enabled"].Status; got != model.StatusVerifiedFail {
		t.Errorf("scanning-enabled status = %q, want verified-fail — GHAS is licensed, so \"off\" is a real gap now", got)
	}
	if got := m["C04.secrets.push-protection"].Status; got != model.StatusVerifiedPass {
		t.Errorf("push-protection status = %q, want verified-pass", got)
	}
	if got := m["C04.secrets.advanced-security"].Status; got != model.StatusVerifiedPass {
		t.Errorf("advanced-security status = %q, want verified-pass", got)
	}
}

func TestCollect_SecurityAndAnalysisAbsentNotCheckableNeverAssumedOff(t *testing.T) {
	mux := http.NewServeMux()
	orgHandler(t, mux, "attestor-demo")
	mux.HandleFunc("/repos/attestor-demo/old-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"private": true})
	})
	mux.HandleFunc("/repos/attestor-demo/old-repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: []string{"old-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range []string{"C04.secrets.scanning-enabled", "C04.secrets.push-protection", "C04.secrets.advanced-security"} {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable (security_and_analysis absent)", id, got)
		}
	}
	// Dependabot alerts don't depend on security_and_analysis at all — a
	// separate endpoint, still evaluates normally.
	if got := m["C04.deps.dependabot-alerts"].Status; got != model.StatusVerifiedPass {
		t.Errorf("dependabot-alerts status = %q, want verified-pass (independent of security_and_analysis)", got)
	}
}

// TestCollect_DependabotAlerts404IsRealFailNot403IsNotCheckable is the
// issue's own explicit acceptance criterion: 403 and 404 on
// vulnerability-alerts must yield different statuses — 404 means "disabled"
// (a real, meaningful state GitHub represents via status code, not an
// error), 403 means "no permission to know" (an honest unknown).
func TestCollect_DependabotAlerts404IsRealFailNot403IsNotCheckable(t *testing.T) {
	t.Run("404_disabled_is_verified_fail", func(t *testing.T) {
		mux := http.NewServeMux()
		orgHandler(t, mux, "attestor-demo")
		mux.HandleFunc("/repos/attestor-demo/repo", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{"private": false})
		})
		mux.HandleFunc("/repos/attestor-demo/repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
		})
		c := newCollectorForServer(t, newTestServer(t, mux))
		results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: []string{"repo"}})
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		if got := byID(results)["C04.deps.dependabot-alerts"].Status; got != model.StatusVerifiedFail {
			t.Errorf("status = %q, want verified-fail (404 means disabled, not an error)", got)
		}
	})

	t.Run("403_permission_denied_is_not_checkable", func(t *testing.T) {
		mux := http.NewServeMux()
		orgHandler(t, mux, "attestor-demo")
		mux.HandleFunc("/repos/attestor-demo/repo", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{"private": false})
		})
		mux.HandleFunc("/repos/attestor-demo/repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
		})
		c := newCollectorForServer(t, newTestServer(t, mux))
		results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: []string{"repo"}})
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		r := byID(results)["C04.deps.dependabot-alerts"]
		if r.Status != model.StatusNotCheckable {
			t.Errorf("status = %q, want not-checkable (403 means unknown, not disabled)", r.Status)
		}
		// The repo fetch (a separate call) already succeeded by this
		// point, so the reason must be specific to the vulnerability-
		// alerts call — a generic "token lacks permission to read
		// org/repo" would be misleading (the token demonstrably can read
		// the repo).
		if !strings.Contains(r.Reason, "vulnerability-alerts") || !strings.Contains(r.Reason, "admin") {
			t.Errorf("Reason = %q, want it to specifically mention vulnerability-alerts and admin-level access, not the generic repo-read message", r.Reason)
		}
	})
}

func TestCollect_RepoFetchFailure403AllRepoChecksNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	orgHandler(t, mux, "attestor-demo")
	mux.HandleFunc("/repos/attestor-demo/secret-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: []string{"secret-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range repoCheckIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, got)
		}
	}
}

func TestCollect_OrgSecurityDefaultsAllEnabledPass(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"login": "attestor-demo",
			"secret_scanning_enabled_for_new_repositories":                 true,
			"secret_scanning_push_protection_enabled_for_new_repositories": true,
			"dependabot_alerts_enabled_for_new_repositories":               true,
			"advanced_security_enabled_for_new_repositories":               true,
		})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: nil})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	r, ok := m["C04.org.security-defaults"]
	if !ok {
		t.Fatal("missing C04.org.security-defaults result")
	}
	if r.Status != model.StatusVerifiedPass {
		t.Errorf("status = %q, want verified-pass; reason=%q", r.Status, r.Reason)
	}
	if r.Scope.Repo != "" {
		t.Errorf("Scope.Repo = %q, want empty (org-scoped check)", r.Scope.Repo)
	}
}

func TestCollect_OrgSecurityDefaultsSomeDisabledFail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"login": "attestor-demo",
			"secret_scanning_enabled_for_new_repositories":                 true,
			"secret_scanning_push_protection_enabled_for_new_repositories": false,
			"dependabot_alerts_enabled_for_new_repositories":               true,
			"advanced_security_enabled_for_new_repositories":               false,
		})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: nil})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := byID(results)["C04.org.security-defaults"]
	if r.Status != model.StatusVerifiedFail {
		t.Errorf("status = %q, want verified-fail", r.Status)
	}
}

func TestCollect_OrgSecurityDefaultsAllNilNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"login": "attestor-demo"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: nil})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := byID(results)["C04.org.security-defaults"]
	if r.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable (fields absent, needs org owner/security manager)", r.Status)
	}
}

func TestCollect_OrgFetchFailure403NotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: nil})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := byID(results)["C04.org.security-defaults"]
	if r.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", r.Status)
	}
	if !strings.Contains(r.Reason, "permission") {
		t.Errorf("Reason = %q, want it to mention permission", r.Reason)
	}
}

func TestCollect_OrgFetchFailure404NotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/some-user", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "some-user", Repos: nil})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := byID(results)["C04.org.security-defaults"]
	if r.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", r.Status)
	}
}

func TestCollect_MultiRepoScanIncludesOneOrgResultAndFourPerRepo(t *testing.T) {
	mux := http.NewServeMux()
	orgHandler(t, mux, "attestor-demo")
	for _, repo := range []string{"repo-a", "repo-b"} {
		mux.HandleFunc("/repos/attestor-demo/"+repo, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{"private": false})
		})
		mux.HandleFunc("/repos/attestor-demo/"+repo+"/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
		})
	}

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestor-demo", Repos: []string{"repo-a", "repo-b"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 org-level + 4 per repo x 2 repos = 9
	if len(results) != 9 {
		t.Fatalf("len(results) = %d, want 9", len(results))
	}
	orgCount, repoCounts := 0, map[string]int{}
	for _, r := range results {
		if r.Scope.Repo == "" {
			orgCount++
			continue
		}
		repoCounts[r.Scope.Repo]++
	}
	if orgCount != 1 {
		t.Errorf("org-scoped result count = %d, want 1", orgCount)
	}
	if repoCounts["repo-a"] != 4 || repoCounts["repo-b"] != 4 {
		t.Errorf("repoCounts = %v, want 4 each", repoCounts)
	}
}

func TestCollect_PreCanceledContextProducesNotCheckableNotPanic(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/attestor-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"login": "attestor-demo"})
	})
	c := newCollectorForServer(t, newTestServer(t, mux))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := c.Collect(ctx, collect.Scope{Org: "attestor-demo", Repos: []string{"repo-a"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range repoCheckIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, got)
		}
	}
	// The org-level check has no ForEachRepo dispatch to cancel — its own
	// single call still runs and, against a pre-canceled ctx, fails via the
	// normal API-error path (the http.Client itself respects ctx).
	if got := m["C04.org.security-defaults"].Status; got != model.StatusNotCheckable {
		t.Errorf("org.security-defaults status = %q, want not-checkable", got)
	}
}

func TestChecksRegistered(t *testing.T) {
	if len(checkTitles) != 5 {
		t.Fatalf("len(checkTitles) = %d, want 5", len(checkTitles))
	}
	for id := range checkTitles {
		if _, ok := collect.Lookup(id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry", id)
		}
	}
}

// TestOrgSecurityDefaultsRemediationNamesAllFourSettings locks in that the
// remediation text matches checkOrgSecurityDefaults' actual pass condition
// — secretScanning && pushProtection && dependabot && advancedSecurity all
// true — not just two of the four. Following advice that only names two
// settings would leave a reader at verified-fail forever.
func TestOrgSecurityDefaultsRemediationNamesAllFourSettings(t *testing.T) {
	remediation := checkRemediations["C04.org.security-defaults"]
	for _, want := range []string{"secret scanning", "push protection", "dependabot", "advanced security"} {
		if !strings.Contains(strings.ToLower(remediation), want) {
			t.Errorf("C04.org.security-defaults remediation missing %q — the check requires all four org-default settings, not a subset: %q", want, remediation)
		}
	}
}

// TestGHASRemediationsDontOverclaimLicensingPrerequisite locks in that the
// GHAS-related remediation text doesn't assert a strict "license required
// before X" prerequisite that evalGHASGatedFeature's own doc comment says
// no longer holds since GitHub's 2025 GHAS unbundling (a private repo can
// have standalone Secret Protection licensed and secret scanning enabled
// while the legacy combined advanced_security flag still reads disabled).
// Also: scanning-enabled's only reachable private-repo verified-fail case
// (evalGHASGatedFeature's isPrivate && ghasStatus==enabled && status!=enabled
// branch) already has GHAS licensed, so "need a license first" misdescribes
// exactly the fail case the remediation is shown for.
func TestGHASRemediationsDontOverclaimLicensingPrerequisite(t *testing.T) {
	forbidden := "before secret scanning/push protection can be turned on"
	if strings.Contains(checkRemediations["C04.secrets.advanced-security"], forbidden) {
		t.Errorf("C04.secrets.advanced-security remediation claims GHAS is a strict prerequisite for secret scanning/push protection, contradicting evalGHASGatedFeature's documented standalone-Secret-Protection nuance")
	}
	if strings.Contains(checkRemediations["C04.secrets.scanning-enabled"], "license first") {
		t.Errorf("C04.secrets.scanning-enabled remediation says a GHAS license is needed \"first\" — but the only reachable private-repo fail case already has GHAS licensed (evalGHASGatedFeature requires ghasStatus==enabled to reach verified-fail rather than not-checkable)")
	}
}
