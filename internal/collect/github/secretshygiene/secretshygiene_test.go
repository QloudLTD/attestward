package secretshygiene

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
	c := New("ghp_test-token", ghcollect.ClientConfig{})
	c.newClientForTest = func(token string) *ghcollect.Client {
		client := ghcollect.NewClient(token, ghcollect.ClientConfig{})
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
	orgHandler(t, mux, "attestward-demo")
	mux.HandleFunc("/repos/attestward-demo/good-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": false,
			"security_and_analysis": map[string]any{
				"secret_scanning":                 map[string]any{"status": "enabled"},
				"secret_scanning_push_protection": map[string]any{"status": "enabled"},
			},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/good-repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"good-repo"}})
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
	orgHandler(t, mux, "attestward-demo")
	mux.HandleFunc("/repos/attestward-demo/good-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": false,
			"security_and_analysis": map[string]any{
				"secret_scanning":                 map[string]any{"status": "enabled"},
				"secret_scanning_push_protection": map[string]any{"status": "enabled"},
			},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/good-repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"good-repo"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	for _, id := range []string{"C04.secrets.scanning-enabled", "C04.secrets.push-protection", "C04.secrets.advanced-security"} {
		prov := m[id].Provenance
		if len(prov) != 1 {
			t.Fatalf("%s Provenance = %v, want exactly 1 entry (the repo fetch)", id, prov)
		}
		if !strings.HasSuffix(prov[0].Endpoint, "/repos/attestward-demo/good-repo") {
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
	orgHandler(t, mux, "attestward-demo")
	mux.HandleFunc("/repos/attestward-demo/bad-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": false,
			"security_and_analysis": map[string]any{
				"secret_scanning":                 map[string]any{"status": "disabled"},
				"secret_scanning_push_protection": map[string]any{"status": "disabled"},
			},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/bad-repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"bad-repo"}})
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
	orgHandler(t, mux, "attestward-demo")
	mux.HandleFunc("/repos/attestward-demo/private-no-ghas", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": true,
			"security_and_analysis": map[string]any{
				"advanced_security":               map[string]any{"status": "disabled"},
				"secret_scanning":                 map[string]any{"status": "disabled"},
				"secret_scanning_push_protection": map[string]any{"status": "disabled"},
			},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/private-no-ghas/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"private-no-ghas"}})
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
	orgHandler(t, mux, "attestward-demo")
	mux.HandleFunc("/repos/attestward-demo/private-ghas-partial", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"private": true,
			"security_and_analysis": map[string]any{
				"advanced_security":               map[string]any{"status": "enabled"},
				"secret_scanning":                 map[string]any{"status": "disabled"},
				"secret_scanning_push_protection": map[string]any{"status": "enabled"},
			},
		})
	})
	mux.HandleFunc("/repos/attestward-demo/private-ghas-partial/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"private-ghas-partial"}})
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
	orgHandler(t, mux, "attestward-demo")
	mux.HandleFunc("/repos/attestward-demo/old-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"private": true})
	})
	mux.HandleFunc("/repos/attestward-demo/old-repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNoContent, nil)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"old-repo"}})
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
		orgHandler(t, mux, "attestward-demo")
		mux.HandleFunc("/repos/attestward-demo/repo", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{"private": false})
		})
		mux.HandleFunc("/repos/attestward-demo/repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
		})
		c := newCollectorForServer(t, newTestServer(t, mux))
		results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"repo"}})
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		if got := byID(results)["C04.deps.dependabot-alerts"].Status; got != model.StatusVerifiedFail {
			t.Errorf("status = %q, want verified-fail (404 means disabled, not an error)", got)
		}
	})

	t.Run("403_permission_denied_is_not_checkable", func(t *testing.T) {
		mux := http.NewServeMux()
		orgHandler(t, mux, "attestward-demo")
		mux.HandleFunc("/repos/attestward-demo/repo", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{"private": false})
		})
		mux.HandleFunc("/repos/attestward-demo/repo/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
		})
		c := newCollectorForServer(t, newTestServer(t, mux))
		results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"repo"}})
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
	orgHandler(t, mux, "attestward-demo")
	mux.HandleFunc("/repos/attestward-demo/secret-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"secret-repo"}})
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
	mux.HandleFunc("/orgs/attestward-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"login": "attestward-demo",
			"secret_scanning_enabled_for_new_repositories":                 true,
			"secret_scanning_push_protection_enabled_for_new_repositories": true,
			"dependabot_alerts_enabled_for_new_repositories":               true,
			"advanced_security_enabled_for_new_repositories":               true,
		})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: nil})
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
	mux.HandleFunc("/orgs/attestward-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"login": "attestward-demo",
			"secret_scanning_enabled_for_new_repositories":                 true,
			"secret_scanning_push_protection_enabled_for_new_repositories": false,
			"dependabot_alerts_enabled_for_new_repositories":               true,
			"advanced_security_enabled_for_new_repositories":               false,
		})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: nil})
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
	mux.HandleFunc("/orgs/attestward-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"login": "attestward-demo"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: nil})
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
	mux.HandleFunc("/orgs/attestward-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: nil})
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

// TestCollect_KnownUserAccountSkipsOrgAPICallEntirely proves the issue #102
// short-circuit: when scope.AccountType is collect.AccountTypeUser,
// checkOrgSecurityDefaults must not attempt Organizations.Get at all — a
// handler that fails the test if hit is the only way to prove that, versus
// TestCollect_OrgFetchFailure404NotCheckable above, which proves the older
// fallback for an unknown account type where the call is attempted and
// 404s.
func TestCollect_KnownUserAccountSkipsOrgAPICallEntirely(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected API call %s %s — a known user-account target must short-circuit before any org-scoped call", r.Method, r.URL.Path)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "sioakim", AccountType: collect.AccountTypeUser, Repos: nil})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := byID(results)["C04.org.security-defaults"]
	if r.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", r.Status)
	}
	if !strings.Contains(r.Reason, "sioakim") || !strings.Contains(r.Reason, "personal") || !strings.Contains(r.Reason, "not an organization") {
		t.Errorf("Reason = %q, want it to name the account and explain it's personal, not an organization", r.Reason)
	}
	// model.CheckResult.Provenance is `json:"provenance"` with no
	// omitempty, and the evidence-pack schema requires it as an array —
	// a nil slice marshals to JSON null and fails pre-write schema
	// validation, aborting attestward scan entirely for any user-account
	// target (found in Fable review of PR #103).
	if r.Provenance == nil {
		t.Errorf("Provenance is nil, want a non-nil (possibly empty) slice — a nil Provenance marshals to JSON null and fails the evidence-pack schema's required array type")
	}
}

func TestCollect_MultiRepoScanIncludesOneOrgResultAndFourPerRepo(t *testing.T) {
	mux := http.NewServeMux()
	orgHandler(t, mux, "attestward-demo")
	for _, repo := range []string{"repo-a", "repo-b"} {
		mux.HandleFunc("/repos/attestward-demo/"+repo, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusOK, map[string]any{"private": false})
		})
		mux.HandleFunc("/repos/attestward-demo/"+repo+"/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
		})
	}

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "attestward-demo", Repos: []string{"repo-a", "repo-b"}})
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
	mux.HandleFunc("/orgs/attestward-demo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"login": "attestward-demo"})
	})
	c := newCollectorForServer(t, newTestServer(t, mux))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := c.Collect(ctx, collect.Scope{Org: "attestward-demo", Repos: []string{"repo-a"}})
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

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce (see orgsecurity's own copy of this
// pattern for the full rationale). Unlike C02/C03, none of C04's five
// checks can ever produce partial — every one bottoms out at pass, fail,
// or not-checkable (see checks.go's evalGHASGatedFeature and
// checkOrgSecurityDefaults).
var checkWantStatuses = map[string][]model.Status{
	"C04.secrets.scanning-enabled":  {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C04.secrets.push-protection":   {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C04.deps.dependabot-alerts":    {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C04.secrets.advanced-security": {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C04.org.security-defaults":     {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
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

// TestPerRepoNotCheckableRubricsCoverRepoFetchFailure locks in that all
// four per-repo checks' not-checkable rubric mentions the repo-fetch-
// failure path — collectRepo (secretshygiene.go) returns
// allRepoNotCheckable for every one of these checks when
// Repositories.Get itself fails (403/404/other API error), before any
// check-specific logic ever runs. Every other check-specific
// not-checkable reason (security_and_analysis absent, GHAS unlicensed,
// GetVulnerabilityAlerts erroring) is downstream of that same fetch
// already having succeeded, so omitting it would leave a real,
// frequently-hit not-checkable path undocumented.
func TestPerRepoNotCheckableRubricsCoverRepoFetchFailure(t *testing.T) {
	for _, id := range repoCheckIDs {
		rubric := checkRubrics[id][model.StatusNotCheckable]
		if !strings.Contains(rubric, "fetch itself failed") {
			t.Errorf("%s: not-checkable rubric doesn't mention the repo-fetch-itself-failed path, but collectRepo routes that failure to every per-repo check: %q", id, rubric)
		}
	}
}

// TestAdvancedSecurityNotCheckableRubricNotGarbled locks in that the
// public-repo not-applicable sentence reads grammatically — it was
// missing a preposition ("doesn't apply the same way public repos get…"
// instead of "…the same way to a public repo, which gets…").
func TestAdvancedSecurityNotCheckableRubricNotGarbled(t *testing.T) {
	rubric := checkRubrics["C04.secrets.advanced-security"][model.StatusNotCheckable]
	if !strings.Contains(rubric, "the same way to") {
		t.Errorf("C04.secrets.advanced-security not-checkable rubric reads as garbled prose: %q", rubric)
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

// rubricState is one org+repo configuration for the matrix below, and its
// expected result for every check this collector registers.
type rubricState struct {
	name string
	// repoStatus and repoBody are what GET /repos/{org}/{repo} returns. A
	// non-200 repoStatus is the repo-fetch-failed path, where the
	// vulnerability-alerts call never happens at all.
	repoStatus int
	repoBody   map[string]any
	// vulnAlertsStatus is GET .../vulnerability-alerts. GitHub carries this
	// endpoint's boolean in the status code: 204 enabled, 404 disabled (an
	// honest "off", not an error), anything else undeterminable.
	vulnAlertsStatus int
	orgBody          map[string]any
	want             map[string]model.Status
}

func (st rubricState) mux(t *testing.T, org, repo string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/"+org, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, st.orgBody)
	})
	mux.HandleFunc("/repos/"+org+"/"+repo, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, st.repoStatus, st.repoBody)
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/vulnerability-alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, st.vulnAlertsStatus, nil)
	})
	return mux
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// Four states reach all fifteen (five checks × three statuses) combinations
// this collector can emit. Two of the checks need a state nothing else in this
// file's matrix would have produced, which is why the states are shaped the way
// they are:
//
//   - advanced-security is not-checkable on a PUBLIC repo, so its
//     verified-pass and verified-fail both need private repos, and its
//     not-checkable is reached here through the repo-fetch failure rather
//     than through visibility.
//   - scanning-enabled and push-protection are not-checkable only in the
//     private + feature-off + GHAS-unlicensed corner, which is also the one
//     state where advanced-security is a verified-fail. That coincidence is
//     GitHub's licensing model showing through, not a coincidence of the
//     fixtures.
//
// A fifth state reaches no status the four miss, and is here anyway. Three of
// the five checks read the same repo response, and with the four states alone
// scanning-enabled, push-protection and org.security-defaults agree in every
// one — so a defect reading the wrong field was invisible. Verified rather
// than assumed: pointing checkPushProtection at sa.SecretScanning instead of
// sa.SecretScanningPushProtection passed the four-state matrix cleanly. The
// fifth state turns one feature on and the other off, which separates all
// three, and every pair of the five checks then disagrees somewhere.
//
// Each state pins the whole result map rather than a count — a count would
// show none of this.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	const org, repo = "attestward-demo", "subject"

	orgAllDefaultsOn := map[string]any{
		"login": org,
		"secret_scanning_enabled_for_new_repositories":                 true,
		"secret_scanning_push_protection_enabled_for_new_repositories": true,
		"dependabot_alerts_enabled_for_new_repositories":               true,
		"advanced_security_enabled_for_new_repositories":               true,
	}
	orgSomeDefaultsOff := map[string]any{
		"login": org,
		"secret_scanning_enabled_for_new_repositories":                 true,
		"secret_scanning_push_protection_enabled_for_new_repositories": false,
		"dependabot_alerts_enabled_for_new_repositories":               true,
		"advanced_security_enabled_for_new_repositories":               false,
	}
	// The permission-gated shape: a token without org owner or security
	// manager gets the org object back with all four fields simply absent.
	orgDefaultsInvisible := map[string]any{"login": org}

	privateRepo := func(secretScanning, pushProtection, advancedSecurity string) map[string]any {
		return map[string]any{
			"private": true,
			"security_and_analysis": map[string]any{
				"secret_scanning":                 map[string]any{"status": secretScanning},
				"secret_scanning_push_protection": map[string]any{"status": pushProtection},
				"advanced_security":               map[string]any{"status": advancedSecurity},
			},
		}
	}

	states := []rubricState{
		{
			name:       "private repo, GHAS licensed, every feature on, org defaults all on",
			repoStatus: http.StatusOK, repoBody: privateRepo("enabled", "enabled", "enabled"),
			vulnAlertsStatus: http.StatusNoContent,
			orgBody:          orgAllDefaultsOn,
			want: map[string]model.Status{
				"C04.secrets.scanning-enabled":  model.StatusVerifiedPass,
				"C04.secrets.push-protection":   model.StatusVerifiedPass,
				"C04.secrets.advanced-security": model.StatusVerifiedPass,
				"C04.deps.dependabot-alerts":    model.StatusVerifiedPass,
				"C04.org.security-defaults":     model.StatusVerifiedPass,
			},
		},
		{
			// GHAS licensed is what makes the two feature checks a real gap
			// rather than not-checkable — an unlicensed feature can't be
			// faulted, so this state has to license it to reach the fails.
			name:       "private repo, GHAS licensed, features off, org defaults incomplete",
			repoStatus: http.StatusOK, repoBody: privateRepo("disabled", "disabled", "enabled"),
			vulnAlertsStatus: http.StatusNotFound,
			orgBody:          orgSomeDefaultsOff,
			want: map[string]model.Status{
				"C04.secrets.scanning-enabled":  model.StatusVerifiedFail,
				"C04.secrets.push-protection":   model.StatusVerifiedFail,
				"C04.secrets.advanced-security": model.StatusVerifiedPass,
				"C04.deps.dependabot-alerts":    model.StatusVerifiedFail,
				"C04.org.security-defaults":     model.StatusVerifiedFail,
			},
		},
		{
			name:       "private repo, GHAS unlicensed, org defaults not visible to this token",
			repoStatus: http.StatusOK, repoBody: privateRepo("disabled", "disabled", "disabled"),
			vulnAlertsStatus: http.StatusNoContent,
			orgBody:          orgDefaultsInvisible,
			want: map[string]model.Status{
				"C04.secrets.scanning-enabled":  model.StatusNotCheckable,
				"C04.secrets.push-protection":   model.StatusNotCheckable,
				"C04.secrets.advanced-security": model.StatusVerifiedFail,
				"C04.deps.dependabot-alerts":    model.StatusVerifiedPass,
				"C04.org.security-defaults":     model.StatusNotCheckable,
			},
		},
		{
			// One feature on, the other off — the state that stops
			// scanning-enabled, push-protection and org.security-defaults
			// from being indistinguishable from each other.
			name:       "private repo, GHAS licensed, scanning on but push protection off",
			repoStatus: http.StatusOK, repoBody: privateRepo("enabled", "disabled", "enabled"),
			vulnAlertsStatus: http.StatusNotFound,
			orgBody:          orgDefaultsInvisible,
			want: map[string]model.Status{
				"C04.secrets.scanning-enabled":  model.StatusVerifiedPass,
				"C04.secrets.push-protection":   model.StatusVerifiedFail,
				"C04.secrets.advanced-security": model.StatusVerifiedPass,
				"C04.deps.dependabot-alerts":    model.StatusVerifiedFail,
				"C04.org.security-defaults":     model.StatusNotCheckable,
			},
		},
		{
			// The repo fetch fails before any check-specific logic runs, so
			// all four per-repo checks degrade together. This is the only
			// route to not-checkable for advanced-security and
			// dependabot-alerts.
			name:       "repo unreadable",
			repoStatus: http.StatusForbidden, repoBody: map[string]any{"message": "Forbidden"},
			vulnAlertsStatus: http.StatusNoContent,
			orgBody:          orgDefaultsInvisible,
			want: map[string]model.Status{
				"C04.secrets.scanning-enabled":  model.StatusNotCheckable,
				"C04.secrets.push-protection":   model.StatusNotCheckable,
				"C04.secrets.advanced-security": model.StatusNotCheckable,
				"C04.deps.dependabot-alerts":    model.StatusNotCheckable,
				"C04.org.security-defaults":     model.StatusNotCheckable,
			},
		},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			c := newCollectorForServer(t, newTestServer(t, st.mux(t, org, repo)))
			results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}

			got := map[string]model.Status{}
			for _, r := range results {
				if _, dup := got[r.CheckID]; dup {
					t.Errorf("%s emitted twice", r.CheckID)
				}
				got[r.CheckID] = r.Status
			}
			// Compared whole, in both directions: a missing key is as much a
			// defect as a wrong one, and a row count would show neither.
			for id, want := range st.want {
				if got[id] != want {
					t.Errorf("%s = %q, want %q", id, got[id], want)
				}
			}
			for id, status := range got {
				if _, expected := st.want[id]; !expected {
					t.Errorf("%s = %q, but this state expects no result for it", id, status)
				}
			}
			all = append(all, results...)
		})
	}

	collecttest.AssertRubricsMatchObservedBehaviour(t, "github", collectorID, all)
}
