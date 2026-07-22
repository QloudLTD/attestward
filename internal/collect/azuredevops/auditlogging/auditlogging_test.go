package auditlogging

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/collect/azuredevops/adofixture"
	"github.com/sioakim/attestward/internal/model"
)

const (
	testOrg     = "acme-ado"
	testProject = "WidgetsApp"
	testPAT     = "ado-test-pat"
)

func newCollector(fx *adofixture.Transport) *Collector {
	return New(azuredevops.NewClientForTest(testOrg, testPAT, fx))
}

func byID(results []model.CheckResult) map[string]model.CheckResult {
	m := map[string]model.CheckResult{}
	for _, r := range results {
		m[r.CheckID] = r
	}
	return m
}

func auditLogPath() string      { return "/" + testOrg + "/_apis/audit/auditlog" }
func streamsPath() string       { return "/" + testOrg + "/_apis/audit/streams" }
func subscriptionsPath() string { return "/" + testOrg + "/_apis/hooks/subscriptions" }
func projectPath(project string) string {
	return "/" + testOrg + "/_apis/projects/" + project
}

// happyPathFixture registers a passing response for every endpoint this
// collector calls, so a test focused on one check doesn't have to know
// about (or fail on) the other three.
func happyPathFixture() *adofixture.Transport {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostAudit, auditLogPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"value": map[string]any{"decoratedAuditLogEntries": []any{}, "hasMore": false}},
	})
	fx.Set("GET", azuredevops.HostAudit, streamsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   []map[string]any{{"id": 1, "consumerType": "Splunk", "status": "enabled"}},
	})
	fx.Set("GET", azuredevops.HostCore, projectPath(testProject), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"id": "proj-guid-123", "name": testProject},
	})
	fx.Set("GET", azuredevops.HostCore, subscriptionsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{"count": 1, "value": []map[string]any{
			{"eventType": "git.push", "status": "enabled", "publisherInputs": map[string]any{"projectId": "proj-guid-123"}},
		}},
	})
	return fx
}

// --- org-log-available ---

func TestCollect_OrgLogAvailable_VerifiedPass(t *testing.T) {
	c := newCollector(happyPathFixture())
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[orgLogAvailableID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("org-log-available = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}
	if len(got.Provenance) != 1 {
		t.Errorf("org-log-available Provenance = %d entries, want exactly 1 (only its own call, none of the other three checks')", len(got.Provenance))
	}
}

func TestCollect_OrgLogAvailable_SendsBatchSizeOne(t *testing.T) {
	fx := happyPathFixture()
	capture := &queryCapturingTransport{base: fx}
	c := New(azuredevops.NewClientForTest(testOrg, testPAT, capture))

	if _, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject}); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	q := capture.queries[auditLogPath()]
	if q == nil {
		t.Fatal("no request captured for the auditlog path")
	}
	if got := q.Get("batchSize"); got != "1" {
		t.Errorf("batchSize = %q, want \"1\"", got)
	}
	if got := q.Get("api-version"); got != "7.1-preview.1" {
		t.Errorf("api-version = %q, want 7.1-preview.1", got)
	}
}

// TestCollect_OrgLogAvailable_Gated404_ThreeWayHonestReason proves the
// three-way indistinguishable not-checkable reason (org not Entra-backed /
// "Log Audit Events" policy off / token lacks scope or permission) is
// actually present in the Reason text, not just described in a comment.
func TestCollect_OrgLogAvailable_Gated404_ThreeWayHonestReason(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostAudit, auditLogPath(), adofixture.Response{
		Status: http.StatusNotFound,
		Body:   map[string]any{"message": "not found"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[orgLogAvailableID]

	if got.Status != model.StatusNotCheckable {
		t.Errorf("org-log-available = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	for _, want := range []string{"Entra", "Log Audit Events", "vso.auditlog", "can't be told apart"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("Reason = %q, want it to contain %q (the three-way honest hedge)", got.Reason, want)
		}
	}
}

func TestCollect_OrgLogAvailable_Forbidden403_AlsoGated(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostAudit, auditLogPath(), adofixture.Response{
		Status: http.StatusForbidden,
		Body:   map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[orgLogAvailableID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("org-log-available = %q, want not-checkable", got.Status)
	}
	if !strings.Contains(got.Reason, "Entra") {
		t.Errorf("Reason = %q, want the same three-way hedge for 403 as for 404", got.Reason)
	}
}

func TestCollect_OrgLogAvailable_ServerError_GenericReason(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostAudit, auditLogPath(), adofixture.Response{
		Status: http.StatusInternalServerError,
		Body:   map[string]any{"message": "boom"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[orgLogAvailableID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("org-log-available = %q, want not-checkable", got.Status)
	}
	if strings.Contains(got.Reason, "Entra") {
		t.Errorf("Reason = %q, want the generic error message, not the gated three-way hedge, for a 500", got.Reason)
	}
}

// --- log-streaming ---

func TestCollect_LogStreaming_EnabledStream_VerifiedPass(t *testing.T) {
	c := newCollector(happyPathFixture())
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[logStreamingID]

	if got.Status != model.StatusVerifiedPass {
		t.Errorf("log-streaming = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}
	if len(got.Provenance) != 1 {
		t.Errorf("log-streaming Provenance = %d entries, want exactly 1", len(got.Provenance))
	}
	if got.Facts["enabled_count"] != 1 {
		t.Errorf("enabled_count = %v, want 1", got.Facts["enabled_count"])
	}
}

// TestCollect_LogStreaming_ConsumerInputsNeverInFacts is the CRITICAL
// security test the story calls for: a stream fixture whose consumerInputs
// carries a sentinel SIEM secret must never surface it anywhere in this
// check's Facts, not even indirectly, no matter how Facts is marshaled.
func TestCollect_LogStreaming_ConsumerInputsNeverInFacts(t *testing.T) {
	const sentinel = "SENTINEL-SIEM-TOKEN-do-not-leak-9f8e7d"
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostAudit, streamsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: []map[string]any{
			{
				"id":           1,
				"consumerType": "Splunk",
				"status":       "enabled",
				"displayName":  "https://input-prd-p.cloud.splunk.com:8088",
				"consumerInputs": map[string]any{
					"SplunkUrl":                 "https://input-prd-p.cloud.splunk.com:8088",
					"SplunkEventCollectorToken": sentinel,
				},
			},
		},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[logStreamingID]
	if got.Status != model.StatusVerifiedPass {
		t.Fatalf("log-streaming = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}

	raw, err := json.Marshal(got.Facts)
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	rawStr := string(raw)
	for _, sensitive := range []string{sentinel, "SplunkEventCollectorToken", "SplunkUrl", "consumerInputs", "input-prd-p.cloud.splunk.com"} {
		if strings.Contains(rawStr, sensitive) {
			t.Errorf("marshaled Facts %s contain %q — consumerInputs (or a value from it) leaked into Facts", rawStr, sensitive)
		}
	}
	// consumer_types is the only shape Facts should carry from a stream
	// beyond the bare counts.
	types, ok := got.Facts["consumer_types"].(map[string]int)
	if !ok || types["Splunk"] != 1 {
		t.Errorf("consumer_types = %#v, want {\"Splunk\":1}", got.Facts["consumer_types"])
	}
}

func TestCollect_LogStreaming_ZeroStreams_VerifiedFail(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostAudit, streamsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   []map[string]any{},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[logStreamingID]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("log-streaming = %q, want verified-fail; reason=%q", got.Status, got.Reason)
	}
}

func TestCollect_LogStreaming_AllDisabled_VerifiedFail(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostAudit, streamsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: []map[string]any{
			{"id": 1, "consumerType": "Splunk", "status": "disabledBySystem"},
			{"id": 2, "consumerType": "AzureEventGrid", "status": "disabledByUser"},
		},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[logStreamingID]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("log-streaming = %q, want verified-fail; reason=%q", got.Status, got.Reason)
	}
	if got.Facts["enabled_count"] != 0 {
		t.Errorf("enabled_count = %v, want 0", got.Facts["enabled_count"])
	}
}

// TestCollect_LogStreaming_NumericStatus_DecodesAsEnabled proves the
// tolerant auditStreamStatus decode (see its own doc comment): Microsoft's
// own reference page's sample response shows "status": 1 verbatim even
// though the enum's documented values are strings, and this check must not
// error out (turning a real pass into a false not-checkable) if a live org
// really does serialize it that way.
func TestCollect_LogStreaming_NumericStatus_DecodesAsEnabled(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostAudit, streamsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   []map[string]any{{"id": 1, "consumerType": "Splunk", "status": 1}},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[logStreamingID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("log-streaming = %q, want verified-pass (numeric status 1 == enabled); reason=%q", got.Status, got.Reason)
	}
}

func TestCollect_LogStreaming_Gated_NotCheckable(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostAudit, streamsPath(), adofixture.Response{
		Status: http.StatusForbidden,
		Body:   map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[logStreamingID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("log-streaming = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "Entra") {
		t.Errorf("Reason = %q, want the gated hedge naming Entra-backing", got.Reason)
	}
}

// TestCollect_LogStreaming_MixedCaseEnabled_VerifiedPass is the regression
// case a case-sensitive comparison would get wrong: the audit service
// demonstrably doesn't always match its own documented casing, so a live
// "Enabled" (capital E) must still produce verified-pass, not a false
// verified-fail.
func TestCollect_LogStreaming_MixedCaseEnabled_VerifiedPass(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostAudit, streamsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   []map[string]any{{"id": 1, "consumerType": "Splunk", "status": "Enabled"}},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[logStreamingID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("log-streaming = %q, want verified-pass (mixed-case \"Enabled\" must still count); reason=%q", got.Status, got.Reason)
	}
}

// TestAuditStreamStatus_UnmarshalJSON exercises the decode helper directly,
// independent of the wider check, for both accepted shapes and the
// rejected shape.
func TestAuditStreamStatus_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    auditStreamStatus
		wantErr bool
	}{
		{"string form", `"enabled"`, "enabled", false},
		{"string form disabled", `"disabledBySystem"`, "disabledbysystem", false}, // lowercased on decode — see auditStreamStatus's own doc comment
		{"string form mixed case", `"Enabled"`, "enabled", false},                 // case-insensitive: a live "Enabled" must decode the same as "enabled"
		{"numeric form enabled", `1`, "enabled", false},
		{"numeric form unknown", `0`, "unknown", false},
		{"numeric form out of range", `99`, "unknown", false},
		{"neither string nor number", `true`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s auditStreamStatus
			err := json.Unmarshal([]byte(tt.json), &s)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Unmarshal(%s) = nil error, want an error", tt.json)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unmarshal(%s): %v", tt.json, err)
			}
			if s != tt.want {
				t.Errorf("Unmarshal(%s) = %q, want %q", tt.json, s, tt.want)
			}
		})
	}
}

// --- retention-awareness ---

func TestCollect_RetentionAwareness_AlwaysNotCheckableNoAPICall(t *testing.T) {
	// An empty adofixture.Transport errors on ANY request — if
	// checkRetentionAwareness ever made a call, this test would fail with
	// a wrapped adofixture.ErrNoFixture-derived reason instead of the
	// fixed informational text asserted below.
	fx := adofixture.New()
	c := newCollector(fx)

	got := c.checkRetentionAwareness(testOrg)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("retention-awareness = %q, want not-checkable", got.Status)
	}
	if !strings.Contains(got.Reason, "informational only") {
		t.Errorf("Reason = %q, want the fixed informational text (proves no API call was attempted)", got.Reason)
	}
	if got.Facts["documented_retention_days"] != 90 {
		t.Errorf("documented_retention_days = %v, want 90", got.Facts["documented_retention_days"])
	}
	if len(got.Provenance) != 0 {
		t.Errorf("Provenance = %v, want empty (no API call)", got.Provenance)
	}
	if got.Provenance == nil {
		t.Error("Provenance is nil, want a non-nil empty slice (a nil Provenance marshals to JSON null and fails the evidence-pack schema's required array type)")
	}
}

// --- repo.webhooks (org-level service hook subscriptions) ---

// TestCollect_Webhooks_ProjectIDFilterMatrix is the acceptance-criterion
// test: one subscription matches the scanned project by id, one is scoped
// to all projects (empty publisherInputs.projectId), and one is scoped to
// a different project — only the first two should count.
func TestCollect_Webhooks_ProjectIDFilterMatrix(t *testing.T) {
	const sentinel = "SENTINEL-HOOK-SECRET-do-not-leak-1a2b3c"
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostCore, subscriptionsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{"count": 4, "value": []map[string]any{
			{
				"eventType":       "git.push",
				"status":          "enabled",
				"publisherInputs": map[string]any{"projectId": "proj-guid-123"},
				"consumerInputs":  map[string]any{"apiToken": sentinel},
			},
			{
				"eventType":       "build.complete",
				"publisherInputs": map[string]any{}, // status omitted -> active; no projectId -> all-projects
			},
			{
				"eventType":       "git.push",
				"status":          "enabled",
				"publisherInputs": map[string]any{"projectId": "some-other-project-guid"},
			},
			{
				"eventType":       "workitem.created", // wrong event type, otherwise matching
				"status":          "enabled",
				"publisherInputs": map[string]any{"projectId": "proj-guid-123"},
			},
		}},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[webhooksID]

	if got.Status != model.StatusVerifiedPass {
		t.Fatalf("webhooks = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}
	matches, ok := got.Facts["matching_subscriptions"].([]map[string]any)
	if !ok || len(matches) != 2 {
		t.Fatalf("matching_subscriptions = %#v, want exactly 2 entries (own-project git.push + all-projects build.complete)", got.Facts["matching_subscriptions"])
	}

	raw, err := json.Marshal(got.Facts)
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	if strings.Contains(string(raw), sentinel) || strings.Contains(string(raw), "consumerInputs") || strings.Contains(string(raw), "apiToken") {
		t.Errorf("marshaled Facts %s contain consumerInputs data — must never leak", string(raw))
	}
}

func TestCollect_Webhooks_OtherProjectOnly_VerifiedFail(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostCore, subscriptionsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{"count": 1, "value": []map[string]any{
			{"eventType": "git.push", "status": "enabled", "publisherInputs": map[string]any{"projectId": "some-other-project-guid"}},
		}},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[webhooksID]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("webhooks = %q, want verified-fail (subscription scoped to a different project); reason=%q", got.Status, got.Reason)
	}
}

// TestCollect_Webhooks_MixedCaseStatus_VerifiedPass is isSubscriptionActive's
// own case-insensitivity regression case, mirroring
// TestCollect_LogStreaming_MixedCaseEnabled_VerifiedPass: a live "ENABLED"
// must still count, not produce a false verified-fail.
func TestCollect_Webhooks_MixedCaseStatus_VerifiedPass(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostCore, subscriptionsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{"count": 1, "value": []map[string]any{
			{"eventType": "git.push", "status": "ENABLED", "publisherInputs": map[string]any{"projectId": "proj-guid-123"}},
		}},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[webhooksID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("webhooks = %q, want verified-pass (mixed-case \"ENABLED\" must still count); reason=%q", got.Status, got.Reason)
	}
}

// TestCollect_Webhooks_ZeroSubscriptions_VerifiedFail_FactsNotNull proves
// the fail path's Facts marshal to a JSON array, not null, mirroring the
// GitHub twin's identical nil-vs-[] care.
func TestCollect_Webhooks_ZeroSubscriptions_VerifiedFail_FactsNotNull(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostCore, subscriptionsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": 0, "value": []map[string]any{}},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[webhooksID]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("webhooks = %q, want verified-fail; reason=%q", got.Status, got.Reason)
	}
	raw, err := json.Marshal(got.Facts)
	if err != nil {
		t.Fatalf("marshal facts: %v", err)
	}
	if got := string(raw); got != `{"matching_subscriptions":[]}` {
		t.Errorf("marshaled facts = %s, want {\"matching_subscriptions\":[]} (not null)", got)
	}
}

func TestCollect_Webhooks_ProjectResolutionFails_NotCheckable(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostCore, projectPath(testProject), adofixture.Response{
		Status: http.StatusNotFound,
		Body:   map[string]any{"message": "project not found"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[webhooksID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("webhooks = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, testProject) {
		t.Errorf("Reason = %q, want it to name the project that failed to resolve", got.Reason)
	}
}

func TestCollect_Webhooks_SubscriptionsListFails_NotCheckable(t *testing.T) {
	fx := happyPathFixture()
	fx.Set("GET", azuredevops.HostCore, subscriptionsPath(), adofixture.Response{
		Status: http.StatusForbidden,
		Body:   map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[webhooksID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("webhooks = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
}

func TestCollect_Webhooks_ProvenanceCoversBothCalls(t *testing.T) {
	c := newCollector(happyPathFixture())
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[webhooksID]
	if len(got.Provenance) != 2 {
		t.Errorf("webhooks Provenance = %d entries, want exactly 2 (project resolve + subscriptions list)", len(got.Provenance))
	}
}

// --- full-Collect wiring / registry completeness ---

func TestCollect_AllFourChecksReturned(t *testing.T) {
	c := newCollector(happyPathFixture())
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != len(checkIDs) {
		t.Fatalf("Collect returned %d results, want %d", len(results), len(checkIDs))
	}
	m := byID(results)
	for _, id := range checkIDs {
		if _, ok := m[id]; !ok {
			t.Errorf("Collect result missing check %s", id)
		}
	}
}

func TestChecksRegistered(t *testing.T) {
	for _, id := range checkIDs {
		meta, ok := collect.LookupPlatform("azuredevops", id)
		if !ok {
			t.Errorf("check %s not registered under platform azuredevops", id)
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

var checksWithNoEndpoint = map[string]bool{
	retentionAwarenessID: true,
}

var checkWantStatuses = map[string][]model.Status{
	orgLogAvailableID:    {model.StatusVerifiedPass, model.StatusNotCheckable},
	logStreamingID:       {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	retentionAwarenessID: {model.StatusNotCheckable},
	webhooksID:           {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) /`)

// TestCollect_RegisteredMetadataCompleteForChecksReference mirrors the
// GitHub twin's identical test (see its own doc comment for the full
// rationale): exact Rubric key-set equality per check, GET/HEAD-only
// Endpoints enforcing ADR-0004, orphaned-key detection, and the
// Endpoints-non-empty exemption for retentionAwarenessID (checksWithNoEndpoint).
func TestCollect_RegisteredMetadataCompleteForChecksReference(t *testing.T) {
	if len(checkRubrics) != len(checkTitles) {
		t.Errorf("checkRubrics has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRubrics), len(checkTitles))
	}
	if len(checkEndpoints) != len(checkTitles) {
		t.Errorf("checkEndpoints has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkEndpoints), len(checkTitles))
	}

	for id := range checkTitles {
		meta, ok := collect.LookupPlatform("azuredevops", id)
		if !ok {
			t.Fatalf("check %q not found in the collect.CheckMeta registry under platform azuredevops", id)
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

// queryCapturingTransport records the query parameters of every request
// keyed by path, mirroring pipelinehistory's identical helper.
type queryCapturingTransport struct {
	base    http.RoundTripper
	queries map[string]url.Values
}

func (c *queryCapturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if c.queries == nil {
		c.queries = map[string]url.Values{}
	}
	c.queries[req.URL.Path] = req.URL.Query()
	return c.base.RoundTrip(req)
}
