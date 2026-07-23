package pipelinesecurity

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
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
)

func newCollector(fx *adofixture.Transport) *Collector {
	return New(azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx))
}

func byID(results []model.CheckResult) map[string]model.CheckResult {
	m := map[string]model.CheckResult{}
	for _, r := range results {
		m[r.CheckID] = r
	}
	return m
}

func generalSettingsPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/build/generalsettings"
}
func serviceEndpointsPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/serviceendpoint/endpoints"
}
func pipelinesPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/pipelines"
}
func definitionPath(id int) string {
	return "/" + testOrg + "/" + testProject + "/_apis/build/definitions/" + strconv.Itoa(id)
}
func projectPath() string {
	return "/" + testOrg + "/_apis/projects/" + testProject
}

func registerGeneralSettings(fx *adofixture.Transport, body map[string]any) {
	fx.Set("GET", azuredevops.HostCore, generalSettingsPath(), adofixture.Response{
		Status: http.StatusOK, Body: body,
	})
}

func fullGeneralSettings(overrides map[string]any) map[string]any {
	body := map[string]any{
		"enforceJobAuthScope":               false,
		"enforceJobAuthScopeForReleases":    false,
		"enforceReferencedRepoScopedToken":  false,
		"enforceSettableVar":                false,
		"disableClassicPipelineCreation":    false,
		"buildsEnabledForForks":             false,
		"forkProtectionEnabled":             false,
		"enforceNoAccessToSecretsFromForks": false,
		"enforceJobAuthScopeForForks":       false,
	}
	for k, v := range overrides {
		body[k] = v
	}
	return body
}

func registerServiceEndpoints(fx *adofixture.Transport, endpoints ...map[string]any) {
	fx.Set("GET", azuredevops.HostCore, serviceEndpointsPath(), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{"count": len(endpoints), "value": endpoints},
	})
}

func registerPipelines(fx *adofixture.Transport, pipelines ...map[string]any) {
	fx.Set("GET", azuredevops.HostCore, pipelinesPath(), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{"count": len(pipelines), "value": pipelines},
	})
}

func registerDefinitionPool(fx *adofixture.Transport, id int, name string, queue map[string]any) {
	body := map[string]any{"id": id, "name": name}
	if queue != nil {
		body["queue"] = queue
	}
	fx.Set("GET", azuredevops.HostCore, definitionPath(id), adofixture.Response{
		Status: http.StatusOK, Body: body,
	})
}

func hostedQueue() map[string]any {
	return map[string]any{"pool": map[string]any{"id": 1, "name": "Azure Pipelines", "isHosted": true}}
}
func selfHostedQueue() map[string]any {
	return map[string]any{"pool": map[string]any{"id": 2, "name": "MyPool", "isHosted": false}}
}

func registerProjectVisibility(fx *adofixture.Transport, visibility string) {
	fx.Set("GET", azuredevops.HostCore, projectPath(), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{"id": "proj-1", "name": testProject, "visibility": visibility},
	})
}

func defaultScope() collect.Scope {
	return collect.Scope{Org: testOrg, Project: testProject}
}

// baselineFixture registers a fully-innocuous baseline for every evidence
// source this package reads, so a test exercising ONE check doesn't need
// to worry about the other three's own upstream calls returning "no route
// registered" errors — mirrors this epic's established convention.
func baselineFixture() *adofixture.Transport {
	fx := adofixture.New()
	registerGeneralSettings(fx, fullGeneralSettings(nil))
	registerServiceEndpoints(fx)
	registerPipelines(fx)
	registerProjectVisibility(fx, "private")
	return fx
}

func assertAlwaysNotCheckable(t *testing.T, m map[string]model.CheckResult) {
	t.Helper()
	for _, id := range alwaysNotCheckableIDs {
		r, ok := m[id]
		if !ok {
			t.Errorf("%s: missing from results", id)
			continue
		}
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if len(r.Provenance) != 0 {
			t.Errorf("%s Provenance = %+v, want empty (no API call)", id, r.Provenance)
		}
		if r.Reason == "" {
			t.Errorf("%s Reason is empty", id)
		}
	}
}

// --- always-not-checkable checks ---

func TestCollect_AlwaysNotCheckableChecksAreFixedRegardlessOfEvidence(t *testing.T) {
	fx := baselineFixture()
	registerGeneralSettings(fx, fullGeneralSettings(map[string]any{
		"enforceJobAuthScope": true, "enforceJobAuthScopeForReleases": true, "enforceReferencedRepoScopedToken": true,
	}))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertAlwaysNotCheckable(t, byID(results))
}

func TestCollect_AlwaysNotCheckableChecksSurviveUpstreamFailure(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, generalSettingsPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})
	fx.Set("GET", azuredevops.HostCore, serviceEndpointsPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})
	fx.Set("GET", azuredevops.HostCore, pipelinesPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})
	fx.Set("GET", azuredevops.HostCore, projectPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertAlwaysNotCheckable(t, byID(results))
}

// --- token-permissions ---

func TestCollect_TokenPermissions_AllThreeEnforced_VerifiedPass(t *testing.T) {
	fx := baselineFixture()
	registerGeneralSettings(fx, fullGeneralSettings(map[string]any{
		"enforceJobAuthScope": true, "enforceJobAuthScopeForReleases": true, "enforceReferencedRepoScopedToken": true,
	}))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idTokenPermissions].Status; got != model.StatusVerifiedPass {
		t.Errorf("token-permissions = %q, want verified-pass; reason=%q", got, m[idTokenPermissions].Reason)
	}
}

// TestCollect_TokenPermissions_TwoOfThree_Partial also proves the LOW
// finding in review: the partial Reason must name the specific missing
// flag, not just a count — an operator's first question is which one.
func TestCollect_TokenPermissions_TwoOfThree_Partial(t *testing.T) {
	fx := baselineFixture()
	registerGeneralSettings(fx, fullGeneralSettings(map[string]any{
		"enforceJobAuthScope": true, "enforceJobAuthScopeForReleases": true, "enforceReferencedRepoScopedToken": false,
	}))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idTokenPermissions]
	if got.Status != model.StatusPartial {
		t.Errorf("token-permissions = %q, want partial; reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "missing: enforceReferencedRepoScopedToken") {
		t.Errorf("Reason = %q, want it to name exactly the one missing flag (enforceReferencedRepoScopedToken), not the two already-enabled ones", got.Reason)
	}
}

func TestCollect_TokenPermissions_NoneEnforced_VerifiedFail(t *testing.T) {
	fx := baselineFixture()

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idTokenPermissions].Status; got != model.StatusVerifiedFail {
		t.Errorf("token-permissions = %q, want verified-fail; reason=%q", got, m[idTokenPermissions].Reason)
	}
	if got, ok := m[idTokenPermissions].Facts["enforce_settable_var"].(bool); !ok || got {
		t.Errorf("enforce_settable_var fact = %v, want false (Facts-only, not a verdict driver)", m[idTokenPermissions].Facts["enforce_settable_var"])
	}
}

func TestCollect_GeneralSettingsFetchFails_TokenPermissionsAndForkProtectionNotCheckable(t *testing.T) {
	fx := baselineFixture()
	fx.Set("GET", azuredevops.HostCore, generalSettingsPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idTokenPermissions].Status; got != model.StatusNotCheckable {
		t.Errorf("token-permissions = %q, want not-checkable; reason=%q", got, m[idTokenPermissions].Reason)
	}
	if got := m[idForkProtection].Status; got != model.StatusNotCheckable {
		t.Errorf("fork-protection = %q, want not-checkable; reason=%q", got, m[idForkProtection].Reason)
	}
	if !strings.Contains(m[idTokenPermissions].Reason, "permission") {
		t.Errorf("Reason = %q, want it to mention permission for a 403", m[idTokenPermissions].Reason)
	}
}

// --- fork-protection ---

func TestCollect_ForkProtection_ForksDisabled_VerifiedPass(t *testing.T) {
	fx := baselineFixture() // buildsEnabledForForks defaults false

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idForkProtection].Status; got != model.StatusVerifiedPass {
		t.Errorf("fork-protection = %q, want verified-pass (vector absent); reason=%q", got, m[idForkProtection].Reason)
	}
}

func TestCollect_ForkProtection_BothEnforced_VerifiedPass(t *testing.T) {
	fx := baselineFixture()
	registerGeneralSettings(fx, fullGeneralSettings(map[string]any{
		"buildsEnabledForForks": true, "forkProtectionEnabled": true, "enforceNoAccessToSecretsFromForks": true,
	}))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idForkProtection].Status; got != model.StatusVerifiedPass {
		t.Errorf("fork-protection = %q, want verified-pass; reason=%q", got, m[idForkProtection].Reason)
	}
}

// TestCollect_ForkProtection_OneOfTwoEnforced_Partial also proves the LOW
// finding in review: the partial Reason must name which specific setting
// is still off, not just say "one of two."
func TestCollect_ForkProtection_OneOfTwoEnforced_Partial(t *testing.T) {
	fx := baselineFixture()
	registerGeneralSettings(fx, fullGeneralSettings(map[string]any{
		"buildsEnabledForForks": true, "forkProtectionEnabled": true, "enforceNoAccessToSecretsFromForks": false,
	}))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idForkProtection]
	if got.Status != model.StatusPartial {
		t.Errorf("fork-protection = %q, want partial (mixed); reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "enforceNoAccessToSecretsFromForks is still off") {
		t.Errorf("Reason = %q, want it to name enforceNoAccessToSecretsFromForks as the specific setting still off (forkProtectionEnabled is already on in this scenario)", got.Reason)
	}
}

// TestCollect_ForkProtection_OtherOneOfTwoEnforced_Partial covers the
// opposite mixed combination, proving the missing-flag naming picks the
// correct one regardless of which of the two is the one left off.
func TestCollect_ForkProtection_OtherOneOfTwoEnforced_Partial(t *testing.T) {
	fx := baselineFixture()
	registerGeneralSettings(fx, fullGeneralSettings(map[string]any{
		"buildsEnabledForForks": true, "forkProtectionEnabled": false, "enforceNoAccessToSecretsFromForks": true,
	}))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idForkProtection]
	if got.Status != model.StatusPartial {
		t.Errorf("fork-protection = %q, want partial (mixed); reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "forkProtectionEnabled is still off") {
		t.Errorf("Reason = %q, want it to name forkProtectionEnabled as the specific setting still off (enforceNoAccessToSecretsFromForks is already on in this scenario)", got.Reason)
	}
}

func TestCollect_ForkProtection_NeitherEnforced_VerifiedFail(t *testing.T) {
	fx := baselineFixture()
	registerGeneralSettings(fx, fullGeneralSettings(map[string]any{"buildsEnabledForForks": true}))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idForkProtection].Status; got != model.StatusVerifiedFail {
		t.Errorf("fork-protection = %q, want verified-fail (fork builds enabled, no protection at all); reason=%q", got, m[idForkProtection].Reason)
	}
}

// --- self-hosted ---

func TestCollect_SelfHosted_PrivateProjectWithNonHostedPool_VerifiedPass(t *testing.T) {
	fx := baselineFixture()
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinitionPool(fx, 1, "CI", selfHostedQueue())
	registerProjectVisibility(fx, "private")

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idSelfHosted].Status; got != model.StatusVerifiedPass {
		t.Errorf("self-hosted = %q, want verified-pass (private project, attack vector doesn't apply); reason=%q", got, m[idSelfHosted].Reason)
	}
}

func TestCollect_SelfHosted_PublicProjectAllHostedPools_VerifiedPass(t *testing.T) {
	fx := baselineFixture()
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinitionPool(fx, 1, "CI", hostedQueue())
	registerProjectVisibility(fx, "public")

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idSelfHosted].Status; got != model.StatusVerifiedPass {
		t.Errorf("self-hosted = %q, want verified-pass; reason=%q", got, m[idSelfHosted].Reason)
	}
}

// TestCollect_SelfHosted_PublicProjectNoBuildDefinitionsAtAll_VerifiedPass
// is the regression test for the MEDIUM finding in review: a public
// project with zero build definitions must get its own honest reason
// ("no build definitions exist"), not fall through to the "every
// definition resolved to a hosted pool" pass text (false as written when
// none exist). Also proves the stated divergence from the GitHub twin
// (which routes its own zero-workflow-evidence case to not-checkable):
// this collector treats an empty Pipelines - List as a definitive
// enumeration, so the result here is verified-pass, not not-checkable.
func TestCollect_SelfHosted_PublicProjectNoBuildDefinitionsAtAll_VerifiedPass(t *testing.T) {
	fx := baselineFixture() // registerPipelines(fx) with zero entries
	registerProjectVisibility(fx, "public")

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idSelfHosted]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("self-hosted = %q, want verified-pass (zero build definitions is a definitive enumeration); reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "no build definitions exist") {
		t.Errorf("Reason = %q, want it to say no build definitions exist, not the generic \"every definition resolved to a hosted pool\" text", got.Reason)
	}
}

func TestCollect_SelfHosted_PublicProjectNonHostedPool_Partial(t *testing.T) {
	fx := baselineFixture()
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinitionPool(fx, 1, "CI", selfHostedQueue())
	registerProjectVisibility(fx, "public")

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idSelfHosted]
	if got.Status != model.StatusPartial {
		t.Errorf("self-hosted = %q, want partial; reason=%q", got.Status, got.Reason)
	}
	nonHosted, ok := got.Facts["non_hosted_pool_definitions"].([]string)
	if !ok || len(nonHosted) != 1 || nonHosted[0] != "CI" {
		t.Errorf("non_hosted_pool_definitions = %#v, want [\"CI\"]", got.Facts["non_hosted_pool_definitions"])
	}
}

// TestCollect_SelfHosted_UnresolvedPoolOnPublicProject_Partial proves the
// absent-object guard: a definition whose queue/pool is missing from its
// own Definitions - Get response must never be silently read as
// IsHosted=false OR silently ignored — it caps the result at partial on a
// public project, the same as a confirmed non-hosted pool would.
func TestCollect_SelfHosted_UnresolvedPoolOnPublicProject_Partial(t *testing.T) {
	fx := baselineFixture()
	registerPipelines(fx, map[string]any{"id": 1, "name": "classic-pipeline"})
	registerDefinitionPool(fx, 1, "classic-pipeline", nil) // no "queue" field at all
	registerProjectVisibility(fx, "public")

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idSelfHosted]
	if got.Status != model.StatusPartial {
		t.Errorf("self-hosted = %q, want partial (unresolved pool must not be assumed hosted); reason=%q", got.Status, got.Reason)
	}
	unresolved, ok := got.Facts["unresolved_pool_definitions"].([]string)
	if !ok || len(unresolved) != 1 || unresolved[0] != "classic-pipeline" {
		t.Errorf("unresolved_pool_definitions = %#v, want [\"classic-pipeline\"]", got.Facts["unresolved_pool_definitions"])
	}
}

func TestCollect_SelfHosted_UnresolvedPoolOnPrivateProject_StillVerifiedPass(t *testing.T) {
	fx := baselineFixture()
	registerPipelines(fx, map[string]any{"id": 1, "name": "classic-pipeline"})
	registerDefinitionPool(fx, 1, "classic-pipeline", nil)
	registerProjectVisibility(fx, "private")

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idSelfHosted].Status; got != model.StatusVerifiedPass {
		t.Errorf("self-hosted = %q, want verified-pass (private project: an evidence gap can't weaken a pass); reason=%q", got, m[idSelfHosted].Reason)
	}
}

func TestCollect_SelfHosted_BuildDefinitionsFetchFails_NotCheckable(t *testing.T) {
	fx := baselineFixture()
	fx.Set("GET", azuredevops.HostCore, pipelinesPath(), adofixture.Response{
		Status: http.StatusInternalServerError, Body: map[string]any{"message": "boom"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idSelfHosted].Status; got != model.StatusNotCheckable {
		t.Errorf("self-hosted = %q, want not-checkable; reason=%q", got, m[idSelfHosted].Reason)
	}
}

func TestCollect_SelfHosted_ProjectVisibilityFetchFails_NotCheckable(t *testing.T) {
	fx := baselineFixture()
	fx.Set("GET", azuredevops.HostCore, projectPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idSelfHosted].Status; got != model.StatusNotCheckable {
		t.Errorf("self-hosted = %q, want not-checkable; reason=%q", got, m[idSelfHosted].Reason)
	}
}

// --- oidc-vs-secrets ---

func TestCollect_OIDCvsSecrets_AllModernAuth_VerifiedPass(t *testing.T) {
	fx := baselineFixture()
	registerServiceEndpoints(fx,
		map[string]any{"id": "ep-1", "name": "prod-arm", "type": "azurerm", "authorization": map[string]any{"scheme": "WorkloadIdentityFederation"}},
		map[string]any{"id": "ep-2", "name": "staging-arm", "type": "azurerm", "authorization": map[string]any{"scheme": "ManagedServiceIdentity"}},
	)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idOIDC].Status; got != model.StatusVerifiedPass {
		t.Errorf("oidc-vs-secrets = %q, want verified-pass; reason=%q", got, m[idOIDC].Reason)
	}
}

func TestCollect_OIDCvsSecrets_ServicePrincipalScheme_VerifiedFail(t *testing.T) {
	fx := baselineFixture()
	registerServiceEndpoints(fx,
		map[string]any{"id": "ep-1", "name": "legacy-arm", "type": "azurerm", "authorization": map[string]any{"scheme": "ServicePrincipal", "parameters": map[string]any{"serviceprincipalkey": "super-secret-value"}}},
	)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idOIDC]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("oidc-vs-secrets = %q, want verified-fail; reason=%q", got.Status, got.Reason)
	}
	staticSecret, ok := got.Facts["static_secret_connections"].([]string)
	if !ok || len(staticSecret) != 1 || staticSecret[0] != "legacy-arm" {
		t.Errorf("static_secret_connections = %#v, want [\"legacy-arm\"]", got.Facts["static_secret_connections"])
	}
}

func TestCollect_OIDCvsSecrets_UnknownSchemeOnly_Partial(t *testing.T) {
	fx := baselineFixture()
	registerServiceEndpoints(fx,
		map[string]any{"id": "ep-1", "name": "mystery-arm", "type": "azurerm", "authorization": map[string]any{"scheme": "SomethingElse"}},
	)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idOIDC].Status; got != model.StatusPartial {
		t.Errorf("oidc-vs-secrets = %q, want partial (unrecognized scheme, honest bucket); reason=%q", got, m[idOIDC].Reason)
	}
}

// TestCollect_OIDCvsSecrets_MissingAuthorization_Partial proves a nil
// Authorization (not just an unrecognized scheme string) also routes to
// the honest partial bucket, never silently assumed modern or fail.
func TestCollect_OIDCvsSecrets_MissingAuthorization_Partial(t *testing.T) {
	fx := baselineFixture()
	registerServiceEndpoints(fx,
		map[string]any{"id": "ep-1", "name": "no-auth-field", "type": "azurerm"},
	)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idOIDC].Status; got != model.StatusPartial {
		t.Errorf("oidc-vs-secrets = %q, want partial; reason=%q", got, m[idOIDC].Reason)
	}
}

func TestCollect_OIDCvsSecrets_NoAzureRMConnections_NotCheckable(t *testing.T) {
	fx := baselineFixture() // registerServiceEndpoints(fx) with zero entries

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idOIDC].Status; got != model.StatusNotCheckable {
		t.Errorf("oidc-vs-secrets = %q, want not-checkable; reason=%q", got, m[idOIDC].Reason)
	}
}

func TestCollect_OIDCvsSecrets_FetchFails_NotCheckable(t *testing.T) {
	fx := baselineFixture()
	fx.Set("GET", azuredevops.HostCore, serviceEndpointsPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idOIDC].Status; got != model.StatusNotCheckable {
		t.Errorf("oidc-vs-secrets = %q, want not-checkable; reason=%q", got, m[idOIDC].Reason)
	}
}

// TestCollect_OIDCvsSecrets_NeverLeaksAuthorizationParameters is the
// sentinel test: authorization.parameters can carry opaque, potentially
// sensitive per-scheme configuration — this package must never decode it
// into any Go value at all, so it's structurally impossible for it to
// reach a CheckResult's Facts (or anywhere else), not merely unused once
// decoded. Strengthened in review (NIT) to json.Marshal the entire
// CheckResult, mirroring secretshygiene's own
// TestCollect_SecretHygiene_NeverLeaksVariableValues precedent, rather
// than spot-checking only Reason and the string form of each Facts value
// — a marshal of the whole struct also catches a future field this test
// wasn't written with in mind.
func TestCollect_OIDCvsSecrets_NeverLeaksAuthorizationParameters(t *testing.T) {
	const sentinel = "TOTALLY-SECRET-CLIENT-SECRET-VALUE-4f8b2c"
	fx := baselineFixture()
	registerServiceEndpoints(fx,
		map[string]any{
			"id": "ep-1", "name": "legacy-arm", "type": "azurerm",
			"authorization": map[string]any{
				"scheme": "ServicePrincipal",
				"parameters": map[string]any{
					"serviceprincipalid":  "11111111-1111-1111-1111-111111111111",
					"serviceprincipalkey": sentinel,
					"tenantid":            "22222222-2222-2222-2222-222222222222",
				},
			},
		},
	)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := byID(results)[idOIDC]
	if got.Status != model.StatusVerifiedFail {
		t.Fatalf("oidc-vs-secrets = %q, want verified-fail (fixture setup sanity check)", got.Status)
	}

	marshaled, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("json.Marshal(results): %v", err)
	}
	if strings.Contains(string(marshaled), sentinel) {
		t.Fatalf("marshaled results contain the sentinel secret value verbatim — Facts must carry only connection names/schemes, never authorization.parameters: %s", marshaled)
	}
	// The connection name (not a secret) is expected to appear, confirming
	// the test actually exercised the offending-connection path rather than
	// vacuously passing on an empty Facts map.
	if !strings.Contains(string(marshaled), "legacy-arm") {
		t.Fatalf("marshaled results are missing the expected connection name — Facts may not have recorded the offending connection at all")
	}
}

// --- registry completeness ---

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

// TestCollect_CollectorIDMatchesGitHubTwin mirrors orgsecurity's identical
// pattern: pins the expected literal directly rather than a cross-package
// registry lookup, since a fresh test binary for this package alone never
// imports (and so never registers) the github twin's own init().
// collect.Register itself panics on any real cross-platform mismatch.
func TestCollect_CollectorIDMatchesGitHubTwin(t *testing.T) {
	if collectorID != "C08.actions-security" {
		t.Errorf("collectorID = %q, want \"C08.actions-security\" (must match the GitHub twin's exactly)", collectorID)
	}
}

var checkWantStatuses = map[string][]model.Status{
	idPinned:           {model.StatusNotCheckable},
	idTokenPermissions: {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idPRTarget:         {model.StatusNotCheckable},
	idForkProtection:   {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idOIDC:             {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idSelfHosted:       {model.StatusVerifiedPass, model.StatusPartial, model.StatusNotCheckable},
}

var checksWithNoEndpoint = map[string]bool{
	idPinned:   true,
	idPRTarget: true,
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) (dev\.azure\.com|advsec\.dev\.azure\.com)/`)

// TestCollect_RegisteredMetadataCompleteForChecksReference mirrors
// sasthistory's/provenance's identical test: exact Rubric key-set equality
// per check, GET/HEAD-only Endpoints enforcing ADR-0004, orphaned-key
// detection, and the Endpoints-non-empty exemption for the two
// permanently-evidence-free checks.
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
				t.Errorf("%s: Endpoints entry %q isn't GET/HEAD against a recognized host — this project is read-only forever (ADR-0004)", id, e)
			}
		}

		if meta.FixtureRef == "" {
			t.Errorf("%s: FixtureRef is empty", id)
		}
	}
}
