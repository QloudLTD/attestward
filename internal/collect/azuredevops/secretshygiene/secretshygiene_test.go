package secretshygiene

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
	testOrg     = "attestward-demo"
	testProject = "demo-project"
	testRepo    = "demo-repo"
)

func repoEnablementPath(repo string) string {
	return "/" + testOrg + "/" + testProject + "/_apis/management/repositories/" + repo + "/enablement"
}

func orgEnablementPath() string {
	return "/" + testOrg + "/_apis/management/enablement"
}

func variableGroupsPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/distributedtask/variablegroups"
}

// newTestCollector wires a Collector against fx via a newClientForTest
// override — the same cross-package testing seam vdp's own tests use,
// since this collector (like vdp) takes (org, pat) rather than a
// pre-built Client.
func newTestCollector(fx http.RoundTripper) *Collector {
	c := New(testOrg, "ado-test-pat")
	c.newClientForTest = func(org, pat string) *azuredevops.Client {
		return azuredevops.NewClientForTest(org, pat, fx)
	}
	return c
}

func resultByID(results []model.CheckResult, id string) model.CheckResult {
	for _, r := range results {
		if r.CheckID == id {
			return r
		}
	}
	return model.CheckResult{}
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// repoEnablementBody builds a Repo Enablement - Get response body.
// blockPushes is *bool so tests can exercise the null (includeAllProperties
// not honored) case explicitly.
func repoEnablementBody(codeSecurityEnabled, codeQLEnabled, depScanEnabled, secretProtectionEnabled bool, blockPushes *bool) map[string]any {
	spf := map[string]any{"secretProtectionEnabled": secretProtectionEnabled}
	if blockPushes != nil {
		spf["blockPushes"] = *blockPushes
	} else {
		spf["blockPushes"] = nil
	}
	return map[string]any{
		"codeSecurityFeatures": map[string]any{
			"codeSecurityEnabled":                codeSecurityEnabled,
			"codeQLEnabled":                      codeQLEnabled,
			"dependencyScanningInjectionEnabled": depScanEnabled,
		},
		"secretProtectionFeatures": spf,
	}
}

func boolPtr(b bool) *bool { return &b }

func fullyEnabledRepoBody() map[string]any {
	return repoEnablementBody(true, true, true, true, boolPtr(true))
}

func fullyDisabledRepoBody() map[string]any {
	return repoEnablementBody(false, false, false, false, boolPtr(false))
}

func TestCollect_RepoFullyEnabled_AllPass(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, repoEnablementPath(testRepo), adofixture.Response{
		Status: http.StatusOK, Body: fullyEnabledRepoBody(),
	})
	fx.Set("GET", azuredevops.HostAdvSec, orgEnablementPath(), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{"enablementOnCreateSettings": map[string]any{}},
	})
	fx.Set("GET", azuredevops.HostCore, variableGroupsPath(), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{"count": 0, "value": []map[string]any{}},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, id := range []string{idScanningEnabled, idPushProtection, idAdvancedSecurity, idDependabotAlerts} {
		r := resultByID(results, id)
		if r.Status != model.StatusVerifiedPass {
			t.Errorf("%s status = %q, want verified-pass; reason=%q", id, r.Status, r.Reason)
		}
		if r.Scope.Repo != testRepo || r.Scope.Project != testProject {
			t.Errorf("%s Scope = %+v, want Repo=%q Project=%q", id, r.Scope, testRepo, testProject)
		}
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance", id)
		}
	}
}

func TestCollect_RepoFullyDisabled_AllFail(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, repoEnablementPath(testRepo), adofixture.Response{
		Status: http.StatusOK, Body: fullyDisabledRepoBody(),
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, id := range []string{idScanningEnabled, idPushProtection, idAdvancedSecurity, idDependabotAlerts} {
		if got := resultByID(results, id).Status; got != model.StatusVerifiedFail {
			t.Errorf("%s status = %q, want verified-fail", id, got)
		}
	}
}

// TestCollect_AdvancedSecurity_RequiresBothPlans proves the AND rule: code
// security alone (dependency scanning) isn't enough, and secret
// protection alone isn't enough — both must be true.
func TestCollect_AdvancedSecurity_RequiresBothPlans(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, repoEnablementPath(testRepo), adofixture.Response{
		Status: http.StatusOK, Body: repoEnablementBody(true, false, false, false, boolPtr(false)),
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := resultByID(results, idAdvancedSecurity).Status; got != model.StatusVerifiedFail {
		t.Errorf("advanced-security = %q, want verified-fail (codeSecurityEnabled alone isn't enough)", got)
	}
	if got := resultByID(results, idDependabotAlerts).Status; got != model.StatusVerifiedPass {
		t.Errorf("dependabot-alerts = %q, want verified-pass (codeSecurityEnabled alone is enough for this check)", got)
	}
}

// TestCollect_PushProtection_NullBlockPushesIsNotCheckable is the
// regression test issue #151 asks for: blockPushes coming back null must
// never be silently read as false, even though this collector always
// requests includeAllProperties=true. The other three repo checks are
// unaffected, since none of them read blockPushes.
func TestCollect_PushProtection_NullBlockPushesIsNotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, repoEnablementPath(testRepo), adofixture.Response{
		Status: http.StatusOK, Body: repoEnablementBody(true, true, true, true, nil),
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	pp := resultByID(results, idPushProtection)
	if pp.Status != model.StatusNotCheckable {
		t.Errorf("push-protection = %q, want not-checkable (null blockPushes must never be read as false); reason=%q", pp.Status, pp.Reason)
	}
	if !containsFold(pp.Reason, "null") {
		t.Errorf("reason = %q, want it to mention the null value", pp.Reason)
	}

	// The other three checks never read blockPushes, so they're unaffected.
	if got := resultByID(results, idScanningEnabled).Status; got != model.StatusVerifiedPass {
		t.Errorf("scanning-enabled = %q, want verified-pass (unaffected by blockPushes)", got)
	}
}

// TestCollect_ScanningEnabledAndAdvancedSecurity_NullSecretProtectionEnabledIsNotCheckable
// is TestCollect_PushProtection_NullBlockPushesIsNotCheckable's twin for
// the other field pipelinehistory.RepoEnablementInfo decodes as *bool:
// secretProtectionEnabled coming back null must never be silently read as
// false by either check that depends on it. This collector no longer
// fetches Repo Enablement itself (it shares
// pipelinehistory.FetchRepoEnablement with C05 sast-history — see the
// package doc comment), so this test exercises the null-vs-false
// distinction end to end through Collect rather than against a
// package-local fetch function.
func TestCollect_ScanningEnabledAndAdvancedSecurity_NullSecretProtectionEnabledIsNotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, repoEnablementPath(testRepo), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{
			"codeSecurityFeatures": map[string]any{
				"codeSecurityEnabled":                true,
				"codeQLEnabled":                      true,
				"dependencyScanningInjectionEnabled": true,
			},
			"secretProtectionFeatures": map[string]any{
				"secretProtectionEnabled": nil,
				"blockPushes":             true,
			},
		},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	se := resultByID(results, idScanningEnabled)
	if se.Status != model.StatusNotCheckable {
		t.Errorf("scanning-enabled = %q, want not-checkable (null secretProtectionEnabled must never be read as false); reason=%q", se.Status, se.Reason)
	}
	if !containsFold(se.Reason, "null") {
		t.Errorf("scanning-enabled reason = %q, want it to mention the null value", se.Reason)
	}

	as := resultByID(results, idAdvancedSecurity)
	if as.Status != model.StatusNotCheckable {
		t.Errorf("advanced-security = %q, want not-checkable (null secretProtectionEnabled must never be read as false); reason=%q", as.Status, as.Reason)
	}

	// push-protection and dependabot-alerts don't read secretProtectionEnabled,
	// so they're unaffected.
	if got := resultByID(results, idPushProtection).Status; got != model.StatusVerifiedPass {
		t.Errorf("push-protection = %q, want verified-pass (unaffected by secretProtectionEnabled)", got)
	}
	if got := resultByID(results, idDependabotAlerts).Status; got != model.StatusVerifiedPass {
		t.Errorf("dependabot-alerts = %q, want verified-pass (unaffected by secretProtectionEnabled)", got)
	}
}

// TestFetchOrgEnablement_SendsIncludeAllPropertiesTrue regression-guards
// the load-bearing query parameter for the org-level enablement fetch —
// issue #151's literal org enablement URL also names this parameter. The
// repo-level fetch has its own equivalent guard in
// pipelinehistory's own tests (TestFetchRepoEnablement_SendsIncludeAllProperties),
// since that fetch is no longer this package's own code — see the package
// doc comment.
func TestFetchOrgEnablement_SendsIncludeAllPropertiesTrue(t *testing.T) {
	capture := &queryCapturingTransport{base: adofixture.New().Set("GET", azuredevops.HostAdvSec, orgEnablementPath(), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{"enablementOnCreateSettings": map[string]any{}},
	})}
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", capture)

	if _, err := fetchOrgEnablement(context.Background(), client); err != nil {
		t.Fatalf("fetchOrgEnablement: %v", err)
	}
	if got := capture.lastQuery.Get("includeAllProperties"); got != "true" {
		t.Errorf("includeAllProperties = %q, want \"true\"", got)
	}
}

type queryCapturingTransport struct {
	base      http.RoundTripper
	lastQuery url.Values
}

func (c *queryCapturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.lastQuery = req.URL.Query()
	return c.base.RoundTrip(req)
}

// TestCollect_RepoEnablement_AdvSecGated_NotCheckable covers the
// advsec-unavailable licensing path via a 404 (one of the two codes
// azuredevops.IsAdvSecGated treats as gated).
func TestCollect_RepoEnablement_AdvSecGated_NotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, repoEnablementPath(testRepo), adofixture.Response{
		Status: http.StatusNotFound, Body: map[string]any{"message": "Not Found"},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, id := range []string{idScanningEnabled, idPushProtection, idAdvancedSecurity, idDependabotAlerts} {
		r := resultByID(results, id)
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if !containsFold(r.Reason, "licensed") && !containsFold(r.Reason, "GHAzDO") {
			t.Errorf("%s reason = %q, want it to mention GHAzDO licensing", id, r.Reason)
		}
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance", id)
		}
	}
}

// TestCollect_RepoEnablement_GenericAPIError_NotCheckable covers a
// non-advsec-gated failure (500), distinct from the licensing path above —
// different Reason wording, same Status.
func TestCollect_RepoEnablement_GenericAPIError_NotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, repoEnablementPath(testRepo), adofixture.Response{
		Status: http.StatusInternalServerError, Body: map[string]any{"message": "Internal Server Error"},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := resultByID(results, idScanningEnabled)
	if r.Status != model.StatusNotCheckable {
		t.Errorf("scanning-enabled status = %q, want not-checkable", r.Status)
	}
	if containsFold(r.Reason, "licensed") {
		t.Errorf("reason = %q, want it NOT to claim a licensing gap for a generic 500", r.Reason)
	}
}

func TestCollect_MultiRepoScanProducesFourResultsEach(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostAdvSec, repoEnablementPath("repo-a"), adofixture.Response{Status: http.StatusOK, Body: fullyEnabledRepoBody()})
	fx.Set("GET", azuredevops.HostAdvSec, repoEnablementPath("repo-b"), adofixture.Response{Status: http.StatusOK, Body: fullyDisabledRepoBody()})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{"repo-a", "repo-b"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byRepo := map[string]int{}
	for _, r := range results {
		if r.Scope.Repo != "" {
			byRepo[r.Scope.Repo]++
		}
	}
	if byRepo["repo-a"] != 4 || byRepo["repo-b"] != 4 {
		t.Errorf("byRepo = %v, want 4 each", byRepo)
	}
}

// --- C04.org.security-defaults ---

func orgEnablementBody(codeSec, secretProt, blockPushes, depScan, codeQL, dependabot bool) map[string]any {
	return map[string]any{
		"enablementOnCreateSettings": map[string]any{
			"enableCodeSecurityOnCreate":                codeSec,
			"enableSecretProtectionOnCreate":            secretProt,
			"enableBlockPushesOnCreate":                 blockPushes,
			"enableDependencyScanningInjectionOnCreate": depScan,
			"enableCodeQLOnCreate":                      codeQL,
			"enableDependabotOnCreate":                  dependabot,
		},
	}
}

func TestCollect_OrgSecurityDefaults_AllFourTrue_Pass(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, orgEnablementPath(), adofixture.Response{
		Status: http.StatusOK, Body: orgEnablementBody(true, true, true, true, false, false),
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := resultByID(results, idOrgSecurityDefaults)
	if r.Status != model.StatusVerifiedPass {
		t.Errorf("org.security-defaults = %q, want verified-pass; reason=%q", r.Status, r.Reason)
	}
	if r.Scope.Org != testOrg || r.Scope.Repo != "" {
		t.Errorf("Scope = %+v, want Org=%q Repo empty", r.Scope, testOrg)
	}
	if r.Facts["enable_codeql_on_create"] != false || r.Facts["enable_dependabot_on_create"] != false {
		t.Errorf("Facts = %v, want enable_codeql_on_create/enable_dependabot_on_create present as context", r.Facts)
	}
}

func TestCollect_OrgSecurityDefaults_OneFalse_Fail(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, orgEnablementPath(), adofixture.Response{
		Status: http.StatusOK, Body: orgEnablementBody(true, true, true, false, true, true),
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := resultByID(results, idOrgSecurityDefaults).Status; got != model.StatusVerifiedFail {
		t.Errorf("org.security-defaults = %q, want verified-fail (enableDependencyScanningInjectionOnCreate is false)", got)
	}
}

func TestCollect_OrgSecurityDefaults_AdvSecGated_NotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, orgEnablementPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "Forbidden"},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := resultByID(results, idOrgSecurityDefaults)
	if r.Status != model.StatusNotCheckable {
		t.Errorf("org.security-defaults = %q, want not-checkable", r.Status)
	}
	if !containsFold(r.Reason, "GHAzDO") {
		t.Errorf("reason = %q, want it to mention GHAzDO licensing", r.Reason)
	}
}

// TestCollect_OrgSecurityDefaults_MissingSettingsObject_NotCheckable is the
// regression test for the review finding on this PR: a 200 response whose
// body omits enablementOnCreateSettings entirely (as opposed to including
// it with every flag genuinely false) must report not-checkable, never a
// fabricated verified-fail against zero actual evidence.
func TestCollect_OrgSecurityDefaults_MissingSettingsObject_NotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, orgEnablementPath(), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := resultByID(results, idOrgSecurityDefaults)
	if r.Status != model.StatusNotCheckable {
		t.Errorf("org.security-defaults = %q, want not-checkable (enablementOnCreateSettings absent must never be read as all-false); reason=%q", r.Status, r.Reason)
	}
	if containsFold(r.Reason, "not every security feature") {
		t.Errorf("reason = %q, must never claim a fabricated fail when the settings object itself is absent", r.Reason)
	}
}

// --- C04.vars.secret-hygiene ---

func varGroup(name string, variables map[string]any) map[string]any {
	return map[string]any{"name": name, "variables": variables}
}

// TestSensitiveVariableNameRE pins the v2 pattern (issue #181) form by
// form: every v1 form must still match (so this can't silently narrow
// coverage), every newly-added form must now match, and the accepted
// false-positive class (tokenizer_config-shaped names) must still match
// too — that is the documented trade, not an oversight.
func TestSensitiveVariableNameRE(t *testing.T) {
	tests := []struct {
		name  string
		match bool
	}{
		// v1 forms — must still match.
		{"password", true},
		{"PASSWORD", true},
		{"passwd", true},
		{"secret", true},
		{"token", true},
		{"api_key", true},
		{"api-key", true},
		{"apiKey", true},
		{"connectionstring", true},

		// v2 new/newly-covered forms — the point of issue #181.
		{"CONNECTION_STRING", true},
		{"connection-string", true},
		{"connString", true},
		{"connStr", true},
		{"PWD", true},
		{"pwd", true},
		{"credential", true},
		{"credentials", true},
		{"CREDENTIALS", true},

		// accepted false-positive class — documented trade, pinned here.
		{"tokenizer_config", true},

		// unrelated names must still not match.
		{"buildConfiguration", false},
		{"environment", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SensitiveVariableNameRE.MatchString(tt.name); got != tt.match {
				t.Errorf("SensitiveVariableNameRE.MatchString(%q) = %v, want %v", tt.name, got, tt.match)
			}
		})
	}
}

// TestCollect_SecretHygiene_V2FormsFlagged proves the v2 pattern (issue
// #181) end to end through Collect, not just via MatchString: names using
// the newly-covered conventions (uniform separator tolerance, pwd,
// credential(s), connstr) move Status to verified-fail exactly as the v1
// forms already did.
func TestCollect_SecretHygiene_V2FormsFlagged(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, variableGroupsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				varGroup("db-vars", map[string]any{
					"CONNECTION_STRING": map[string]any{"value": "Server=prod;User=app"},
					"connection-string": map[string]any{"value": "Server=prod;User=app"},
					"connStr":           map[string]any{"value": "Server=prod;User=app"},
					"PWD":               map[string]any{"value": "hunter2"},
					"credentials":       map[string]any{"value": "user:pass"},
				}),
			},
		},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := resultByID(results, idSecretHygiene)
	if r.Status != model.StatusVerifiedFail {
		t.Fatalf("secret-hygiene = %q, want verified-fail; reason=%q", r.Status, r.Reason)
	}
	offending, ok := r.Facts["offending_variables"].([]map[string]any)
	if !ok {
		t.Fatalf("offending_variables = %v, want a []map[string]any", r.Facts["offending_variables"])
	}
	got := make(map[string]bool, len(offending))
	for _, o := range offending {
		got[o["variable_name"].(string)] = true
	}
	for _, want := range []string{"CONNECTION_STRING", "connection-string", "connStr", "PWD", "credentials"} {
		if !got[want] {
			t.Errorf("offending_variables missing %q — want every v2-covered form flagged; got %v", want, offending)
		}
	}
}

// TestCollect_SecretHygiene_TokenizerConfigClassStillFlagged pins the
// accepted false-positive trade documented on SensitiveVariableNameRE and in
// this check's own rubric/remediation text: a name shaped like
// tokenizer_config still matches (it contains "token") and is meant to —
// coverage over precision, with the exact name recorded in Facts so a false
// positive is trivial to triage.
func TestCollect_SecretHygiene_TokenizerConfigClassStillFlagged(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, variableGroupsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				varGroup("ml-vars", map[string]any{
					"tokenizer_config": map[string]any{"value": "bpe-v3"},
				}),
			},
		},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := resultByID(results, idSecretHygiene)
	if r.Status != model.StatusVerifiedFail {
		t.Fatalf("secret-hygiene = %q, want verified-fail (tokenizer_config is the documented false-positive trade, not a bug)", r.Status)
	}
	offending, ok := r.Facts["offending_variables"].([]map[string]any)
	if !ok || len(offending) != 1 || offending[0]["variable_name"] != "tokenizer_config" {
		t.Errorf("offending_variables = %v, want exactly tokenizer_config", r.Facts["offending_variables"])
	}
}

func TestCollect_SecretHygiene_NoOffendingVariables_Pass(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, variableGroupsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				varGroup("build-vars", map[string]any{
					"buildConfiguration": map[string]any{"value": "Release"},
					"apiKey":             map[string]any{"value": "sekret", "isSecret": true},
				}),
			},
		},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := resultByID(results, idSecretHygiene)
	if r.Status != model.StatusVerifiedPass {
		t.Errorf("secret-hygiene = %q, want verified-pass (apiKey is properly marked isSecret); reason=%q", r.Status, r.Reason)
	}
	if r.Scope.Project != testProject || r.Scope.Repo != "" {
		t.Errorf("Scope = %+v, want Project=%q Repo empty (project-scoped, no repo dimension)", r.Scope, testProject)
	}
}

func TestCollect_SecretHygiene_PlaintextSensitiveVariable_Fail(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, variableGroupsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				varGroup("db-vars", map[string]any{
					"DB_CONNECTIONSTRING": map[string]any{"value": "Server=prod;Password=hunter2"},
				}),
			},
		},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := resultByID(results, idSecretHygiene)
	if r.Status != model.StatusVerifiedFail {
		t.Errorf("secret-hygiene = %q, want verified-fail; reason=%q", r.Status, r.Reason)
	}
	offending, ok := r.Facts["offending_variables"].([]map[string]any)
	if !ok || len(offending) != 1 {
		t.Fatalf("offending_variables = %v, want exactly one entry", r.Facts["offending_variables"])
	}
	if offending[0]["group_name"] != "db-vars" || offending[0]["variable_name"] != "DB_CONNECTIONSTRING" {
		t.Errorf("offending_variables[0] = %v, want group_name=db-vars variable_name=DB_CONNECTIONSTRING", offending[0])
	}
}

// TestCollect_SecretHygiene_EmptyValueDoesNotCount proves a sensitive-named
// variable with no stored value at all isn't flagged — nothing is actually
// exposed in plaintext.
func TestCollect_SecretHygiene_EmptyValueDoesNotCount(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, variableGroupsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				varGroup("placeholder-vars", map[string]any{
					"API_TOKEN": map[string]any{"value": ""},
				}),
			},
		},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := resultByID(results, idSecretHygiene).Status; got != model.StatusVerifiedPass {
		t.Errorf("secret-hygiene = %q, want verified-pass (empty value stores nothing to flag)", got)
	}
}

// TestCollect_SecretHygiene_NonSensitiveNamePlaintextDoesNotCount proves a
// plaintext variable whose name doesn't match the sensitive-name pattern
// is never flagged, regardless of its value.
func TestCollect_SecretHygiene_NonSensitiveNamePlaintextDoesNotCount(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, variableGroupsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				varGroup("build-vars", map[string]any{
					"buildConfiguration": map[string]any{"value": "Release"},
				}),
			},
		},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := resultByID(results, idSecretHygiene).Status; got != model.StatusVerifiedPass {
		t.Errorf("secret-hygiene = %q, want verified-pass", got)
	}
}

func TestCollect_SecretHygiene_APIFailure_NotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, variableGroupsPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "Forbidden"},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := resultByID(results, idSecretHygiene)
	if r.Status != model.StatusNotCheckable {
		t.Errorf("secret-hygiene = %q, want not-checkable", r.Status)
	}
	if !containsFold(r.Reason, "permission") {
		t.Errorf("reason = %q, want it to mention the permission problem", r.Reason)
	}
}

// TestCollect_SecretHygiene_NeverLeaksVariableValues is the sentinel test
// issue #151 asks for, mirroring C09 audit-logging's consumerInputs
// discipline: a distinctive, unmistakable secret value must never appear
// anywhere in the marshaled CheckResult — proving Facts really does carry
// only names, not just that this function's own code path doesn't
// reference Value.
func TestCollect_SecretHygiene_NeverLeaksVariableValues(t *testing.T) {
	const sentinelSecret = "ZzZ-do-not-leak-this-exact-sentinel-value-ZzZ"
	fx := adofixture.New().Set("GET", azuredevops.HostCore, variableGroupsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				varGroup("secret-group-name-should-appear", map[string]any{
					"SECRET_TOKEN": map[string]any{"value": sentinelSecret},
				}),
			},
		},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	r := resultByID(results, idSecretHygiene)
	if r.Status != model.StatusVerifiedFail {
		t.Fatalf("secret-hygiene = %q, want verified-fail (fixture setup sanity check)", r.Status)
	}

	marshaled, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal(result): %v", err)
	}
	if strings.Contains(string(marshaled), sentinelSecret) {
		t.Fatalf("marshaled CheckResult contains the sentinel secret value verbatim — Facts must carry only variable/group names, never values: %s", marshaled)
	}
	// The group name (not a secret) is expected to appear, confirming the
	// test actually exercised the offending-variable path rather than
	// vacuously passing on an empty Facts map.
	if !strings.Contains(string(marshaled), "secret-group-name-should-appear") {
		t.Fatalf("marshaled CheckResult is missing the expected group name — Facts may not have recorded the offending variable at all")
	}
}

// TestCollect_NoReposInScopeStillProducesOrgAndProjectResults proves the
// org-level and project-level checks run regardless of scope.Repos.
func TestCollect_NoReposInScopeStillProducesOrgAndProjectResults(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostAdvSec, orgEnablementPath(), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{"enablementOnCreateSettings": map[string]any{}},
	})
	fx.Set("GET", azuredevops.HostCore, variableGroupsPath(), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{"count": 0, "value": []map[string]any{}},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2 (org + project checks only, no repos in scope)", len(results))
	}
	for _, r := range results {
		if r.Provenance == nil {
			t.Errorf("%s Provenance is nil, want a non-nil (possibly empty) slice", r.CheckID)
		}
	}
}

// --- Registry / metadata tests ---

func TestChecksRegistered(t *testing.T) {
	allIDs := append(append([]string{}, mirroredCheckIDs...), idSecretHygiene)
	if len(allIDs) != 6 {
		t.Fatalf("len(allIDs) = %d, want 6", len(allIDs))
	}
	for _, id := range allIDs {
		if _, ok := collect.LookupPlatform("azuredevops", id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry for platform azuredevops", id)
		}
	}
}

// TestCollect_SecretHygieneHasNoGitHubTwin proves idSecretHygiene really is
// azuredevops-only — it must not resolve under platform "github" at all,
// the structural reason it never needs cross-platform Collector-string
// consistency.
func TestCollect_SecretHygieneHasNoGitHubTwin(t *testing.T) {
	if _, ok := collect.LookupPlatform("github", idSecretHygiene); ok {
		t.Errorf("idSecretHygiene (%q) unexpectedly registered under platform github — it's meant to be azuredevops-only", idSecretHygiene)
	}
}

// TestCollect_CollectorIDMatchesGitHubTwin proves this package registers
// under the exact same Collector string as
// internal/collect/github/secretshygiene.
func TestCollect_CollectorIDMatchesGitHubTwin(t *testing.T) {
	if collectorID != "C04.secrets-hygiene" {
		t.Errorf("collectorID = %q, want \"C04.secrets-hygiene\" (must match the GitHub twin's exactly)", collectorID)
	}
}

var checkWantStatuses = map[string][]model.Status{
	idScanningEnabled:     {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	idPushProtection:      {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	idAdvancedSecurity:    {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	idDependabotAlerts:    {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	idOrgSecurityDefaults: {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	idSecretHygiene:       {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) (advsec\.dev\.azure\.com|dev\.azure\.com)/`)

// TestCollect_RegisteredMetadataCompleteForChecksReference mirrors the
// pattern established by every other ADO collector package's test of the
// same name.
func TestCollect_RegisteredMetadataCompleteForChecksReference(t *testing.T) {
	allIDs := append(append([]string{}, mirroredCheckIDs...), idSecretHygiene)

	for _, id := range allIDs {
		meta, ok := collect.LookupPlatform("azuredevops", id)
		if !ok {
			t.Fatalf("check %q not found in the collect.CheckMeta registry", id)
		}
		if meta.Collector != collectorID {
			t.Errorf("%s Collector = %q, want %q", id, meta.Collector, collectorID)
		}
		if meta.TokenScope == "" {
			t.Errorf("%s TokenScope is empty", id)
		}
		if meta.Remediation == "" {
			t.Errorf("%s Remediation is empty", id)
		}
		if meta.FixtureRef == "" {
			t.Errorf("%s FixtureRef is empty", id)
		}

		want, ok := checkWantStatuses[id]
		if !ok {
			t.Fatalf("checkWantStatuses is missing an entry for %q", id)
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
				t.Errorf("%s: Rubric has an entry for status %q, but checkWantStatuses says this check can't produce it", id, s)
			}
		}

		if len(meta.Endpoints) == 0 {
			t.Errorf("%s: Endpoints is empty, want at least one", id)
		}
		for _, e := range meta.Endpoints {
			if !endpointVerbRE.MatchString(e) {
				t.Errorf("%s: Endpoints entry %q isn't GET/HEAD against a known ADO host — this project is read-only forever (ADR-0004)", id, e)
			}
		}
	}
}
