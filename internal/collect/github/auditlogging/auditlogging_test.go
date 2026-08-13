package auditlogging

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

func registerOrgPlan(t *testing.T, mux *http.ServeMux, org, planName string) {
	t.Helper()
	mux.HandleFunc("/orgs/"+org, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/"+org {
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"login": org, "plan": map[string]any{"name": planName}})
	})
}

func registerAuditLogAvailable(t *testing.T, mux *http.ServeMux, org string) {
	t.Helper()
	mux.HandleFunc("/orgs/"+org+"/audit-log", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{{"action": "org.update_member", "actor": "someone"}})
	})
}

func registerAuditLogStatus(t *testing.T, mux *http.ServeMux, org string, status int) {
	t.Helper()
	mux.HandleFunc("/orgs/"+org+"/audit-log", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, status, map[string]any{"message": "not found"})
	})
}

func registerWebhooks(t *testing.T, mux *http.ServeMux, org, repo string, hooks []map[string]any) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/hooks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, hooks)
	})
}

func TestCollect_AuditLogAvailable_VerifiedPass(t *testing.T) {
	org := "acme"
	mux := http.NewServeMux()
	registerAuditLogAvailable(t, mux, org)
	registerOrgPlan(t, mux, org, "enterprise")
	registerWebhooks(t, mux, org, "widgets", nil)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{"widgets"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[orgLogAvailableID].Status; got != model.StatusVerifiedPass {
		t.Errorf("org-log-available = %q, want verified-pass; reason=%q", got, m[orgLogAvailableID].Reason)
	}
	if got := m[orgLogAvailableID].Facts["org_plan"]; got != "enterprise" {
		t.Errorf("org_plan fact = %v, want %q", got, "enterprise")
	}
}

func TestCollect_AuditLogNotFound_NotCheckableNamesPlanAndScope(t *testing.T) {
	org := "acme"
	mux := http.NewServeMux()
	registerAuditLogStatus(t, mux, org, http.StatusNotFound)
	registerOrgPlan(t, mux, org, "free")
	registerWebhooks(t, mux, org, "widgets", nil)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{"widgets"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[orgLogAvailableID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("org-log-available = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if got.Facts["org_plan"] != "free" {
		t.Errorf("org_plan fact = %v, want %q", got.Facts["org_plan"], "free")
	}
}

func TestCollect_AuditLogForbidden_NotCheckablePermissionReason(t *testing.T) {
	org := "acme"
	mux := http.NewServeMux()
	registerAuditLogStatus(t, mux, org, http.StatusForbidden)
	registerOrgPlan(t, mux, org, "enterprise")
	registerWebhooks(t, mux, org, "widgets", nil)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{"widgets"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[orgLogAvailableID].Status; got != model.StatusNotCheckable {
		t.Errorf("org-log-available = %q, want not-checkable", got)
	}
}

// TestCollect_KnownUserAccountSkipsOrgLogAPICallEntirely proves the issue
// #102 short-circuit: when scope.AccountType is collect.AccountTypeUser,
// checkOrgLogAvailable must not attempt Organizations.GetAuditLog (or the
// Facts-only org-plan lookup) at all — a handler that fails the test if hit
// is the only way to prove that, versus
// TestCollect_AuditLogNotFound_NotCheckableNamesPlanAndScope above, which
// proves the older fallback for an unknown account type where the call is
// attempted and 404s.
func TestCollect_KnownUserAccountSkipsOrgLogAPICallEntirely(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected API call %s %s — a known user-account target must short-circuit before any org-scoped call", r.Method, r.URL.Path)
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: "sioakim", AccountType: collect.AccountTypeUser, Repos: nil})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[orgLogAvailableID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("org-log-available = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "sioakim") || !strings.Contains(got.Reason, "personal") || !strings.Contains(got.Reason, "not an organization") {
		t.Errorf("Reason = %q, want it to name the account and explain it's personal, not an organization", got.Reason)
	}
	if got.Facts["org_plan"] != nil {
		t.Errorf("Facts[org_plan] = %v, want absent — no API call (including the plan lookup) should have been made", got.Facts["org_plan"])
	}
	// model.CheckResult.Provenance is `json:"provenance"` with no
	// omitempty, and the evidence-pack schema requires it as an array —
	// a nil slice marshals to JSON null and fails pre-write schema
	// validation, aborting attestward scan entirely for any user-account
	// target (found in Fable review of PR #103).
	if got.Provenance == nil {
		t.Errorf("Provenance is nil, want a non-nil (possibly empty) slice — a nil Provenance marshals to JSON null and fails the evidence-pack schema's required array type")
	}
}

func TestCollect_LogStreamingAndRetentionAwareness_AlwaysNotCheckableNoAPICall(t *testing.T) {
	org := "acme"
	mux := http.NewServeMux()
	registerAuditLogAvailable(t, mux, org)
	registerOrgPlan(t, mux, org, "enterprise")
	registerWebhooks(t, mux, org, "widgets", nil)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{"widgets"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[logStreamingID]; got.Status != model.StatusNotCheckable || len(got.Provenance) != 0 {
		t.Errorf("log-streaming = %+v, want not-checkable with zero provenance (no API surface exists to call)", got)
	}
	if got := m[retentionAwarenessID]; got.Status != model.StatusNotCheckable {
		t.Errorf("retention-awareness = %q, want not-checkable", got.Status)
	}
	if got := m[retentionAwarenessID].Facts["documented_retention_days"]; got != float64(180) && got != 180 {
		t.Errorf("documented_retention_days fact = %v, want 180", got)
	}
}

func TestCollect_WebhookCoversPushEvent_VerifiedPass(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerAuditLogAvailable(t, mux, org)
	registerOrgPlan(t, mux, org, "enterprise")
	registerWebhooks(t, mux, org, repo, []map[string]any{
		{
			"active": true,
			"events": []string{"push", "issues"},
			"config": map[string]any{"url": "https://hooks.example.com/webhook?token=super-secret-abc123"},
		},
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[webhooksID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("webhooks = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}
	webhookFacts, ok := got.Facts["webhooks"].([]map[string]any)
	if !ok || len(webhookFacts) != 1 {
		t.Fatalf("webhooks facts = %#v, want one entry", got.Facts["webhooks"])
	}
	if webhookFacts[0]["hostname"] != "hooks.example.com" {
		t.Errorf("hostname fact = %v, want %q", webhookFacts[0]["hostname"], "hooks.example.com")
	}
}

// TestCollect_WebhookFactsNeverContainTokenOrQueryString is the fixture
// issue #21's own acceptance criteria calls for: a token-bearing webhook
// URL proves the fact extraction strips it, not just that a downstream
// scrubber happens to catch it.
func TestCollect_WebhookFactsNeverContainTokenOrQueryString(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerAuditLogAvailable(t, mux, org)
	registerOrgPlan(t, mux, org, "enterprise")
	registerWebhooks(t, mux, org, repo, []map[string]any{
		{
			"active": true,
			"events": []string{"push"},
			"config": map[string]any{"url": "https://hooks.example.com/deploy/abc123?token=super-secret-abc123&signing_key=zzz"},
		},
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	raw, err := json.Marshal(m[webhooksID].Facts)
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	rawStr := string(raw)
	for _, sensitive := range []string{"super-secret-abc123", "signing_key", "zzz", "/deploy/abc123", "?token="} {
		if containsSubstring(rawStr, sensitive) {
			t.Errorf("marshaled webhook facts %s contain sensitive substring %q — the raw URL leaked into Facts", rawStr, sensitive)
		}
	}
	webhookFacts, ok := m[webhooksID].Facts["webhooks"].([]map[string]any)
	if !ok || len(webhookFacts) != 1 || webhookFacts[0]["hostname"] != "hooks.example.com" {
		t.Fatalf("webhooks facts = %#v, want exactly one entry with hostname %q", m[webhooksID].Facts["webhooks"], "hooks.example.com")
	}
}

func containsSubstring(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestCollect_NoActiveWebhooks_VerifiedFail(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerAuditLogAvailable(t, mux, org)
	registerOrgPlan(t, mux, org, "enterprise")
	registerWebhooks(t, mux, org, repo, nil)

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[webhooksID].Status; got != model.StatusVerifiedFail {
		t.Errorf("webhooks = %q, want verified-fail; reason=%q", got, m[webhooksID].Reason)
	}

	// Facts["webhooks"] must marshal to "[]", not "null" — a nil Go slice
	// and an empty one are both zero-length but marshal differently
	// (encoding/json turns nil into JSON null), and this is the common,
	// in-practice case (both live demo repos currently have zero
	// webhooks) — a consuming report/schema shouldn't have to special-case
	// null vs [] for the same "no webhooks" fact.
	raw, err := json.Marshal(m[webhooksID].Facts)
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	if got := string(raw); got != `{"webhooks":[]}` {
		t.Errorf("marshaled facts = %s, want {\"webhooks\":[]} (not null)", got)
	}
}

func TestCollect_InactiveWebhookOnly_VerifiedFail(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerAuditLogAvailable(t, mux, org)
	registerOrgPlan(t, mux, org, "enterprise")
	registerWebhooks(t, mux, org, repo, []map[string]any{
		{"active": false, "events": []string{"push"}, "config": map[string]any{"url": "https://hooks.example.com/x"}},
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[webhooksID]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("webhooks = %q, want verified-fail (only webhook is inactive); reason=%q", got.Status, got.Reason)
	}
}

func TestCollect_WebhookCoversUnrelatedEventsOnly_VerifiedFail(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerAuditLogAvailable(t, mux, org)
	registerOrgPlan(t, mux, org, "enterprise")
	registerWebhooks(t, mux, org, repo, []map[string]any{
		{"active": true, "events": []string{"issues", "pull_request"}, "config": map[string]any{"url": "https://hooks.example.com/x"}},
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[webhooksID].Status; got != model.StatusVerifiedFail {
		t.Errorf("webhooks = %q, want verified-fail (no push/release/deployment coverage); reason=%q", got, m[webhooksID].Reason)
	}
}

func TestCollect_WebhookWildcardEvent_VerifiedPass(t *testing.T) {
	org, repo := "acme", "widgets"
	mux := http.NewServeMux()
	registerAuditLogAvailable(t, mux, org)
	registerOrgPlan(t, mux, org, "enterprise")
	registerWebhooks(t, mux, org, repo, []map[string]any{
		{"active": true, "events": []string{"*"}, "config": map[string]any{"url": "https://hooks.example.com/x"}},
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[webhooksID].Status; got != model.StatusVerifiedPass {
		t.Errorf("webhooks = %q, want verified-pass (wildcard covers push/release/deployment too); reason=%q", got, m[webhooksID].Reason)
	}
}

func TestCollect_WebhooksListFailure403_NotCheckable(t *testing.T) {
	org, repo := "acme", "forbidden-repo"
	mux := http.NewServeMux()
	registerAuditLogAvailable(t, mux, org)
	registerOrgPlan(t, mux, org, "enterprise")
	mux.HandleFunc("/repos/"+org+"/"+repo+"/hooks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[webhooksID].Status; got != model.StatusNotCheckable {
		t.Errorf("webhooks = %q, want not-checkable", got)
	}
}

func TestCollect_PreCanceledContextProducesNotCheckableNotPanic(t *testing.T) {
	org, repo := "acme", "canceled-repo"
	mux := http.NewServeMux()
	registerAuditLogStatus(t, mux, org, http.StatusForbidden)
	registerOrgPlan(t, mux, org, "free")

	c := newCollectorForServer(t, newTestServer(t, mux))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := c.Collect(ctx, collect.Scope{Org: org, Repos: []string{repo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[webhooksID].Status; got != model.StatusNotCheckable {
		t.Errorf("webhooks = %q, want not-checkable for a pre-canceled context", got)
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

// checksWithNoEndpoint are the checks whose Endpoints is legitimately
// empty: neither makes any API call at all, so nothing backs their
// (permanently fixed) not-checkable status — see checkRubrics' own doc
// comment in auditlogging.go. Every other check in this codebase's
// checks-reference backfill has at least one endpoint, so this
// completeness test deviates from the shared C01-C08 pattern here on
// purpose, not by oversight.
var checksWithNoEndpoint = map[string]bool{
	logStreamingID:       true,
	retentionAwarenessID: true,
}

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce (see orgsecurity's own copy of this
// pattern for the full rationale). logStreamingID and retentionAwarenessID
// are the first checks across the whole checks-reference backfill that
// can produce ONLY not-checkable — never pass, fail, or partial — by
// design, since neither makes any API call at all.
var checkWantStatuses = map[string][]model.Status{
	orgLogAvailableID:    {model.StatusVerifiedPass, model.StatusNotCheckable},
	logStreamingID:       {model.StatusNotCheckable},
	retentionAwarenessID: {model.StatusNotCheckable},
	webhooksID:           {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) /`)

// TestCollect_RegisteredMetadataCompleteForChecksReference is
// orgsecurity's TestCollect_RegisteredMetadataCompleteForChecksReference,
// replicated per the pattern that PR validated: see that test's own doc
// comment for the full rationale (exact Rubric key-set equality per check,
// GET/HEAD-only Endpoints enforcing ADR-0004, orphaned-key detection) —
// except the Endpoints-non-empty assertion, which this package's two
// permanently-evidence-free checks are deliberately exempt from (see
// checksWithNoEndpoint).
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

		if len(meta.Endpoints) == 0 && !checksWithNoEndpoint[id] {
			t.Errorf("%s: Endpoints is empty, want at least one (or add it to checksWithNoEndpoint with a reason)", id)
		}
		if len(meta.Endpoints) > 0 && checksWithNoEndpoint[id] {
			t.Errorf("%s: checksWithNoEndpoint says this check should have zero Endpoints, but it has %v", id, meta.Endpoints)
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

func TestHostnameOf(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"strips path and query", "https://hooks.example.com/deploy/x?token=abc", "hooks.example.com"},
		{"strips port", "https://hooks.example.com:8443/x", "hooks.example.com"},
		{"empty input", "", ""},
		{"unparseable input", "://not a url", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hostnameOf(tt.in); got != tt.want {
				t.Errorf("hostnameOf(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// rubricState is one fixture world for TestRubricsMatchObservedBehaviour:
// the two API responses this collector's two API-backed checks read, plus
// the whole result map that world must produce.
type rubricState struct {
	name string
	// auditLogStatus is what GET /orgs/{org}/audit-log returns. 200 is the
	// only reachable pass; every other code is not-checkable, and the
	// plan-gated ones (402/404) are indistinguishable from a missing scope.
	auditLogStatus int
	// hooksStatus and hooks are GET /repos/{org}/{repo}/hooks. A non-200
	// hooksStatus is the listing-failed path; 200 with an empty or
	// non-matching list is a definitive fail, not a gap.
	hooksStatus int
	hooks       []map[string]any
	want        map[string]model.Status
}

func (st rubricState) mux(t *testing.T, org, repo string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	registerOrgPlan(t, mux, org, "enterprise")
	mux.HandleFunc("/orgs/"+org+"/audit-log", func(w http.ResponseWriter, _ *http.Request) {
		if st.auditLogStatus == http.StatusOK {
			writeJSON(t, w, http.StatusOK, []map[string]any{{"action": "org.update_member"}})
			return
		}
		writeJSON(t, w, st.auditLogStatus, map[string]any{"message": "nope"})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/hooks", func(w http.ResponseWriter, _ *http.Request) {
		if st.hooksStatus == http.StatusOK {
			writeJSON(t, w, http.StatusOK, st.hooks)
			return
		}
		writeJSON(t, w, st.hooksStatus, map[string]any{"message": "nope"})
	})
	return mux
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// Only two of C09's four checks make an API call at all: log-streaming and
// retention-awareness are constants that return not-checkable with no request
// (there is no org-scoped endpoint for either — see their doc comments), so
// every state below emits not-checkable for them and no state could ever do
// otherwise. That is the documented behaviour, and the guard's
// documented-but-unreachable direction is what pins it: if either check ever
// grew a second status without a rubric entry, or a rubric entry appeared for
// a status it cannot reach, this fails.
//
// The two real checks read different responses — org-log-available reads
// /orgs/{org}/audit-log, webhooks reads /repos/{org}/{repo}/hooks — so no
// shared-field swap is possible between them. What IS possible is the weaker
// lockstep failure: a matrix where both move together in every state proves
// nothing about which response drives which check. States 2 and 3 break that
// in both directions (pass/fail and fail/pass respectively), so no single
// upstream failure explains both results.
//
// State 2 also carries an INACTIVE webhook subscribed to `push` alongside an
// active one subscribed to nothing relevant. That is the state that pins the
// active-only filter: dropping the h.GetActive() guard in checkRepoWebhooks
// turns this state's verified-fail into a verified-pass, and no other state
// here notices.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	const org, repo = "acme", "widgets"

	states := []rubricState{
		{
			name:           "audit log reachable, an active webhook exports push",
			auditLogStatus: http.StatusOK,
			hooksStatus:    http.StatusOK,
			hooks: []map[string]any{
				{"active": true, "events": []string{"push"}, "config": map[string]any{"url": "https://siem.example.com/in"}},
			},
			want: map[string]model.Status{
				orgLogAvailableID:    model.StatusVerifiedPass,
				logStreamingID:       model.StatusNotCheckable,
				retentionAwarenessID: model.StatusNotCheckable,
				webhooksID:           model.StatusVerifiedPass,
			},
		},
		{
			// Plan-gated audit log AND a repo whose only push subscriber is
			// switched off: the two API-backed checks disagree, and the
			// inactive hook is what makes the fail meaningful rather than
			// trivially empty.
			name:           "audit log plan-gated, only an inactive hook covers push",
			auditLogStatus: http.StatusNotFound,
			hooksStatus:    http.StatusOK,
			hooks: []map[string]any{
				{"active": false, "events": []string{"push"}, "config": map[string]any{"url": "https://siem.example.com/in"}},
				{"active": true, "events": []string{"issues"}, "config": map[string]any{"url": "https://tickets.example.com/in"}},
			},
			want: map[string]model.Status{
				orgLogAvailableID:    model.StatusNotCheckable,
				logStreamingID:       model.StatusNotCheckable,
				retentionAwarenessID: model.StatusNotCheckable,
				webhooksID:           model.StatusVerifiedFail,
			},
		},
		{
			// The other direction: the org call succeeds while the repo call
			// is refused. webhooks' not-checkable is reachable only here.
			name:           "audit log reachable, webhook listing forbidden",
			auditLogStatus: http.StatusOK,
			hooksStatus:    http.StatusForbidden,
			want: map[string]model.Status{
				orgLogAvailableID:    model.StatusVerifiedPass,
				logStreamingID:       model.StatusNotCheckable,
				retentionAwarenessID: model.StatusNotCheckable,
				webhooksID:           model.StatusNotCheckable,
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
