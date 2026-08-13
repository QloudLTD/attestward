package scahistory

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/adofixture"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const (
	testOrg     = "acme-ado"
	testProject = "WidgetsApp"
	testRepo    = "widgets"
	testRepoID  = "repo-1"
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

func repositoriesPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/git/repositories"
}
func pipelinesPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/pipelines"
}
func definitionPath(id int) string {
	return "/" + testOrg + "/" + testProject + "/_apis/build/definitions/" + strconv.Itoa(id)
}
func itemsPath(repositoryID string) string {
	return "/" + testOrg + "/" + testProject + "/_apis/git/repositories/" + repositoryID + "/items"
}
func refsPath(repositoryID string) string {
	return "/" + testOrg + "/" + testProject + "/_apis/git/repositories/" + repositoryID + "/refs"
}
func commitsPath(repositoryID, commitID string) string {
	return "/" + testOrg + "/" + testProject + "/_apis/git/repositories/" + repositoryID + "/commits/" + commitID
}
func buildsPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/build/builds"
}
func enablementPath(repositoryID string) string {
	return "/" + testOrg + "/" + testProject + "/_apis/management/repositories/" + repositoryID + "/enablement"
}
func alertsPath(repositoryID string) string {
	return "/" + testOrg + "/" + testProject + "/_apis/alert/repositories/" + repositoryID + "/alerts"
}

func registerRepositories(fx *adofixture.Transport, repos ...map[string]any) {
	fx.Set("GET", azuredevops.HostCore, repositoriesPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": len(repos), "value": repos},
	})
}

func registerPipelines(fx *adofixture.Transport, pipelines ...map[string]any) {
	fx.Set("GET", azuredevops.HostCore, pipelinesPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": len(pipelines), "value": pipelines},
	})
}

func registerDefinition(fx *adofixture.Transport, id int, process map[string]any, repositoryID, defaultBranch string) {
	fx.Set("GET", azuredevops.HostCore, definitionPath(id), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"id": id, "name": "pipeline",
			"process":    process,
			"repository": map[string]any{"id": repositoryID, "defaultBranch": defaultBranch},
		},
	})
}

func registerYAML(fx *adofixture.Transport, repositoryID, content string) {
	fx.Set("GET", azuredevops.HostCore, itemsPath(repositoryID), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"content": content},
	})
}

func registerLightweightTag(fx *adofixture.Transport, repositoryID, tagName, commitSHA string) {
	fx.Set("GET", azuredevops.HostCore, refsPath(repositoryID), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{"count": 1, "value": []map[string]any{
			{"name": "refs/tags/" + tagName, "objectId": commitSHA},
		}},
	})
}

func registerCommitDate(fx *adofixture.Transport, repositoryID, commitSHA string, date time.Time) {
	fx.Set("GET", azuredevops.HostCore, commitsPath(repositoryID, commitSHA), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"committer": map[string]any{"date": date.Format(time.RFC3339)}},
	})
}

func registerBuilds(fx *adofixture.Transport, builds ...map[string]any) {
	fx.Set("GET", azuredevops.HostCore, buildsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": len(builds), "value": builds},
	})
}

func registerEnablement(fx *adofixture.Transport, repositoryID string, dependencyScanningInjectionEnabled, codeSecurityEnabled bool) {
	fx.Set("GET", azuredevops.HostAdvSec, enablementPath(repositoryID), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{"codeSecurityFeatures": map[string]any{
			"dependencyScanningInjectionEnabled": dependencyScanningInjectionEnabled,
			"codeSecurityEnabled":                codeSecurityEnabled,
		}},
	})
}

func registerAlerts(fx *adofixture.Transport, repositoryID string, alerts ...map[string]any) {
	fx.Set("GET", azuredevops.HostAdvSec, alertsPath(repositoryID), adofixture.Response{
		Status: http.StatusOK,
		Body:   alerts,
	})
}

func defaultScope() collect.Scope {
	return collect.Scope{
		Org: testOrg, Project: testProject, Repos: []string{testRepo},
		ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12,
	}
}

// --- full happy-path / confidence-ladder scenarios ---

// TestCollect_HighConfidenceADOTaskMatch_AllChecksResolve exercises a
// high-confidence ado_task match (the real embedded "ghazdo-dependency-
// scanning" signature's AdvancedSecurity-Dependency-Scanning task) with a
// clean release build and no open alerts.
func TestCollect_HighConfidenceADOTaskMatch_AllChecksResolve(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - task: AdvancedSecurity-Dependency-Scanning@1\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass; reason=%q", got, m[idToolConfigured].Reason)
	}
	if got := m[idRanPerRelease].Status; got != model.StatusVerifiedPass {
		t.Errorf("ran-per-release = %q, want verified-pass; reason=%q", got, m[idRanPerRelease].Reason)
	}
	if got := m[idDependabotConfig].Status; got != model.StatusNotCheckable {
		t.Errorf("dependabot-config = %q, want not-checkable (always, no ADO evidence source); reason=%q", got, m[idDependabotConfig].Reason)
	}
	if got := m[idDependencyReview].Status; got != model.StatusNotCheckable {
		t.Errorf("dependency-review = %q, want not-checkable (always, no ADO evidence source); reason=%q", got, m[idDependencyReview].Reason)
	}
	if got := m[idAlertsTriaged].Status; got != model.StatusVerifiedPass {
		t.Errorf("alerts-triaged = %q, want verified-pass (zero open alerts); reason=%q", got, m[idAlertsTriaged].Reason)
	}

	perRelease, ok := m[idRanPerRelease].Facts["per_release"].([]map[string]any)
	if !ok || len(perRelease) != 1 || perRelease[0]["tag"] != "v1.0.0" || perRelease[0]["status"] != "ran" {
		t.Errorf("per_release facts = %v, want one entry tag=v1.0.0 status=ran", m[idRanPerRelease].Facts["per_release"])
	}
}

func TestCollect_NoSCAToolAtAll_ToolConfiguredAndRanPerReleaseFail(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusVerifiedFail {
		t.Errorf("tool-configured = %q, want verified-fail; reason=%q", got, m[idToolConfigured].Reason)
	}
	if got := m[idRanPerRelease].Status; got != model.StatusVerifiedFail {
		t.Errorf("ran-per-release = %q, want verified-fail (a real release with zero matched builds is a genuine gap even with no tool configured at all); reason=%q", got, m[idRanPerRelease].Reason)
	}
}

// TestCollect_LowConfidenceOnlyMatch_CapsToolConfiguredAtPartial uses
// snyk's workflow_name_patterns-only signal (a pipeline named after snyk,
// with no actual run-pattern/ado_task invocation) — the weakest tier,
// which must never alone justify verified-pass.
func TestCollect_LowConfidenceOnlyMatch_CapsToolConfiguredAtPartial(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "name: My Snyk Check\nsteps:\n  - script: echo hello\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idToolConfigured]
	if got.Status != model.StatusPartial {
		t.Errorf("tool-configured = %q, want partial; reason=%q", got.Status, got.Reason)
	}
	if got.Facts["low_confidence_match_only"] != true {
		t.Errorf("low_confidence_match_only = %v, want true", got.Facts["low_confidence_match_only"])
	}
}

// TestCollect_LowConfidenceMatchPlusEnablementFails_FactsOmitEnablementFields
// is the regression test for issue #258: a low-confidence-only pipeline
// match plus a failed GHAzDO repo-enablement query must not silently
// report Facts["dependency_scanning_injection_enabled"]=false,
// Facts["code_security_enabled"]=false, or
// Facts["low_confidence_match_only"]=true — all three derive from
// setupConfigured/codeSecurityEnabled, which collapse to false whenever
// enablementErr != nil, indistinguishable from a genuine, observed
// HTTP-200-false response. This combination is reachable in production:
// hasAny=true here bypasses checkToolConfigured's own not-checkable guard
// (line 189), which only fires when hasAny is false — every existing
// enablement-failure test (TestCollect_Enablement404_NoOtherEvidence_
// ToolConfiguredNotCheckable) registers no pipeline evidence at all, so it
// never exercises this Facts path. Before this fix, all three fields
// asserted a confirmed value from a query that merely failed. Same
// pipeline fixture as TestCollect_LowConfidenceOnlyMatch_
// CapsToolConfiguredAtPartial, but the enablement endpoint returns 403
// instead of a successful codeQLEnabled:false response.
func TestCollect_LowConfidenceMatchPlusEnablementFails_FactsOmitEnablementFields(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "name: My Snyk Check\nsteps:\n  - script: echo hello\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})
	fx.Set("GET", azuredevops.HostAdvSec, enablementPath(testRepoID), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idToolConfigured]
	if got.Status != model.StatusPartial {
		t.Errorf("tool-configured = %q, want partial (unaffected by this fix — only the Facts values change); reason=%q", got.Status, got.Reason)
	}
	if v, ok := got.Facts["dependency_scanning_injection_enabled"]; ok {
		t.Errorf("Facts[dependency_scanning_injection_enabled] = %v, want the key absent — the enablement query failed, so its value can't be reported as a confirmed fact", v)
	}
	if v, ok := got.Facts["code_security_enabled"]; ok {
		t.Errorf("Facts[code_security_enabled] = %v, want the key absent — the enablement query failed, so its value can't be reported as a confirmed fact", v)
	}
	if v, ok := got.Facts["low_confidence_match_only"]; ok {
		t.Errorf("Facts[low_confidence_match_only] = %v, want the key absent — its value depends on the same unconfirmed enablement query", v)
	}
}

// TestCollect_MediumConfidenceRunPatternMatch_VerifiedPass uses snyk's
// run_pattern signal (an actual `snyk test` invocation in a script step) —
// medium confidence, enough to pass on its own.
func TestCollect_MediumConfidenceRunPatternMatch_VerifiedPass(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - script: snyk test\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass; reason=%q", got, m[idToolConfigured].Reason)
	}
}

// TestCollect_DependencyScanningInjectionOnly_ToolConfiguredPasses is the
// acceptance test for this collector's key deviation (see the package doc
// comment's judgment call 2): GHAzDO dependency scanning injection alone
// makes tool-configured pass, with no matched pipeline at all. It also
// covers judgment call 7's fix (found in review): ran-per-release must NOT
// independently conclude verified-fail for the identical evidence — a
// self-contradictory pair the original design produced — since injected
// scanning runs invisibly to this collector's own build-matching.
func TestCollect_DependencyScanningInjectionOnly_ToolConfiguredPasses(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, true, true)
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass (dependency scanning injection alone is enough); reason=%q", got, m[idToolConfigured].Reason)
	}
	if m[idToolConfigured].Facts["code_security_enabled"] != true {
		t.Errorf("code_security_enabled fact = %v, want true (informational only, doesn't drive the verdict)", m[idToolConfigured].Facts["code_security_enabled"])
	}
	if got := m[idRanPerRelease].Status; got != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable (injection-only evidence can't be linked to a release — must not contradict tool-configured's own verified-pass); reason=%q", got, m[idRanPerRelease].Reason)
	}
	if !strings.Contains(m[idRanPerRelease].Reason, "no verified way to observe") {
		t.Errorf("ran-per-release Reason = %q, want it to explain this collector has no verified way to observe injected scanning per release", m[idRanPerRelease].Reason)
	}
}

// TestCollect_CodeSecurityEnabledAloneWithoutInjection_ToolConfiguredFails
// is the regression test for the judgment call itself (see the package
// doc comment's judgment call 2, citing Microsoft's own docs: "Enabling
// Advanced Security or Code Security doesn't execute dependency scanning
// automatically"): codeSecurityEnabled=true with
// dependencyScanningInjectionEnabled=false, and no matched pipeline, must
// NOT be read as "an SCA tool is configured."
func TestCollect_CodeSecurityEnabledAloneWithoutInjection_ToolConfiguredFails(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, true) // codeSecurityEnabled true, injection false
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusVerifiedFail {
		t.Errorf("tool-configured = %q, want verified-fail (codeSecurityEnabled alone, without injection, doesn't mean scanning actually runs); reason=%q", got, m[idToolConfigured].Reason)
	}
}

// TestCollect_ConfiguredButBuildNeverSucceeds_RanPerReleaseIsPartial proves
// "configured and attempted, but not clean" caps at partial, never
// verified-fail.
func TestCollect_ConfiguredButBuildNeverSucceeds_RanPerReleaseIsPartial(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - task: AdvancedSecurity-Dependency-Scanning@1\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "failed", "queueTime": releaseDate.Format(time.RFC3339)})
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idRanPerRelease].Status; got != model.StatusPartial {
		t.Errorf("ran-per-release = %q, want partial; reason=%q", got, m[idRanPerRelease].Reason)
	}
}

// TestCollect_AllReleaseTagsUnresolvable_RanPerReleasePartialWithDroppedNames
// exercises pipelinehistory.ResolveReleases' unconditional dropped-tag
// list.
func TestCollect_AllReleaseTagsUnresolvable_RanPerReleasePartialWithDroppedNames(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	fx.Set("GET", azuredevops.HostCore, refsPath(testRepoID), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{"count": 2, "value": []map[string]any{
			{"name": "refs/tags/v1.0.0", "objectId": "sha1"},
			{"name": "refs/tags/v2.0.0", "objectId": "sha2"},
		}},
	})
	notFound := adofixture.Response{Status: http.StatusNotFound, Body: map[string]any{"message": "not found"}}
	fx.Set("GET", azuredevops.HostCore, commitsPath(testRepoID, "sha1"), notFound)
	fx.Set("GET", azuredevops.HostCore, commitsPath(testRepoID, "sha2"), notFound)
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idRanPerRelease]
	if got.Status != model.StatusPartial {
		t.Errorf("ran-per-release = %q, want partial; reason=%q", got.Status, got.Reason)
	}
	dropped, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(dropped) != 2 {
		t.Fatalf("dropped_tags facts = %#v, want 2 entries", got.Facts["dropped_tags"])
	}
}

// --- issue #178: consuming same-repo skips from the start ---

// TestCollect_SameRepoSkip_ToolConfiguredNotCheckableNotFail is the
// end-to-end acceptance test for the package doc comment's judgment call
// 5: one pipeline in this repo resolves to a YAML pipeline but its
// yamlFilename is missing (YAMLPathUnknown), producing a SkippedPipeline;
// with zero matched pipelines and dependency scanning injection off, this
// must cap at not-checkable, not a confident verified-fail.
func TestCollect_SameRepoSkip_ToolConfiguredNotCheckableNotFail(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "unresolved-pipeline"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": ""}, testRepoID, "refs/heads/main")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idToolConfigured]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("tool-configured = %q, want not-checkable (a same-repo skip must cap what would otherwise be verified-fail); reason=%q", got.Status, got.Reason)
	}
	skipped, ok := got.Facts["skipped_pipelines"].([]map[string]any)
	if !ok || len(skipped) != 1 || skipped[0]["name"] != "unresolved-pipeline" {
		t.Errorf("skipped_pipelines facts = %#v, want one entry naming unresolved-pipeline", got.Facts["skipped_pipelines"])
	}
}

// --- issues #236/#244: GHAzDO repo-enablement gating ---

// TestCollect_Enablement404_NoOtherEvidence_ToolConfiguredNotCheckable is
// the regression test for issue #236, C06's twin of issue #226: a 404 used
// to produce a confirmed verified-fail here (treated as equivalent to
// "dependency scanning injection off" by deliberate policy) — this
// asserted more than the evidence supported. S9's live run (issue #190)
// established an unlicensed org/project reads HTTP 200 with every flag
// false/null, never 404, so a 404 no longer has any confirmed meaning
// here at all. A licensed org with GHAzDO dependency scanning injection
// genuinely ON, scanned when this endpoint's pinned preview API version
// is eventually retired or returns a 404 for any other reason, must never
// read as a confirmed fail just because this collector can't see the real
// state — a 404 now goes not-checkable, exactly like a 403 already did
// (see TestCollect_AlertsQuery403_AlertsTriagedNotCheckable for the
// analogous alerts-triaged case) and exactly like every other error this
// check's own guard already handled.
//
// C06.sca.ran-per-release had the identical sibling gap #235 fixed for C05
// (its own injectionOnly guard also required enablementErr == nil) —
// originally out of scope for #236 (tool-configured-only), but folded in
// here as #244 once independent review of the combined #235/#236 PR found
// that deferring it would ship exactly the "two panels of one pack,
// opposite claims" contradiction #236 exists to remove, one collector
// over. Asserted below alongside tool-configured, proving the two checks
// no longer disagree for the identical scenario.
func TestCollect_Enablement404_NoOtherEvidence_ToolConfiguredNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	fx.Set("GET", azuredevops.HostAdvSec, enablementPath(testRepoID), adofixture.Response{
		Status: http.StatusNotFound, Body: map[string]any{"message": "not licensed"},
	})
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusNotCheckable {
		t.Errorf("tool-configured = %q, want not-checkable (a 404's cause is genuinely unconfirmed — must never read as a confirmed fail); reason=%q", got, m[idToolConfigured].Reason)
	}
	if got := m[idRanPerRelease].Status; got != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable (same evidence gap as tool-configured — a 404 means whether dependency scanning injection covers this repo can't be confirmed, so a confirmed absence can't be asserted either); reason=%q", got, m[idRanPerRelease].Reason)
	}
}

// --- alerts-triaged ---

func TestCollect_NoOpenCriticalAlerts_AlertsTriagedVerifiedPass(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idAlertsTriaged].Status; got != model.StatusVerifiedPass {
		t.Errorf("alerts-triaged = %q, want verified-pass; reason=%q", got, m[idAlertsTriaged].Reason)
	}
}

func TestCollect_StaleCriticalAlert_AlertsTriagedPartial(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID, map[string]any{
		"firstSeenDate": time.Now().UTC().AddDate(0, 0, -45).Format(time.RFC3339),
		"severity":      "critical", "state": "active",
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idAlertsTriaged]
	if got.Status != model.StatusPartial {
		t.Errorf("alerts-triaged = %q, want partial; reason=%q", got.Status, got.Reason)
	}
	if got.Facts["open_critical_count"] != 1 {
		t.Errorf("open_critical_count = %v, want 1", got.Facts["open_critical_count"])
	}
}

// TestCollect_CriticalAlertUnparseableDate_AlertsTriagedPartial is the
// end-to-end acceptance test for judgment call 8 (found in review): a
// critical alert whose firstSeenDate can't be parsed must NOT read as
// verified-pass over an unknown age.
func TestCollect_CriticalAlertUnparseableDate_AlertsTriagedPartial(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID, map[string]any{
		"firstSeenDate": "not-a-real-date",
		"severity":      "critical", "state": "active",
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idAlertsTriaged]
	if got.Status != model.StatusPartial {
		t.Errorf("alerts-triaged = %q, want partial (an unparseable date is an unknown age, not evidence it's within the window); reason=%q", got.Status, got.Reason)
	}
	if got.Facts["oldest_critical_age_known"] != false {
		t.Errorf("oldest_critical_age_known fact = %v, want false", got.Facts["oldest_critical_age_known"])
	}
}

func TestCollect_FreshCriticalAlert_AlertsTriagedVerifiedPass(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID, map[string]any{
		"firstSeenDate": time.Now().UTC().AddDate(0, 0, -2).Format(time.RFC3339),
		"severity":      "critical", "state": "active",
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idAlertsTriaged].Status; got != model.StatusVerifiedPass {
		t.Errorf("alerts-triaged = %q, want verified-pass (within the triage window); reason=%q", got, m[idAlertsTriaged].Reason)
	}
}

// TestCollect_AlertsQuery400AdvSecNotEnabled_AlertsTriagedVerifiedFail is
// issue #190's own acceptance test: S9's live run (2026-07-23,
// dev.azure.com/seciq) recorded GHAzDO's actual "alerts not enabled"
// signal as HTTP 400 with typeKey AdvSecNotEnabledException — neither of
// the two codes (403/404) this check's own [fixture-verify] hedge
// previously considered. That response must now graduate to a confirmed
// verified-fail (a real compliance gap, mirroring the GitHub twin's
// identical treatment of its own confirmed-disabled signal), not fold
// into the generic "another API error" not-checkable case the way it did
// before this fix.
func TestCollect_AlertsQuery400AdvSecNotEnabled_AlertsTriagedVerifiedFail(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, false)
	fx.Set("GET", azuredevops.HostAdvSec, alertsPath(testRepoID), adofixture.Response{
		Status: http.StatusBadRequest,
		Body: map[string]any{
			"message": "VS2150009: Advanced Security is not enabled for this repository.",
			"typeKey": "AdvSecNotEnabledException",
		},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idAlertsTriaged]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("alerts-triaged = %q, want verified-fail (confirmed AdvSecNotEnabledException); reason=%q", got.Status, got.Reason)
	}
}

// TestCollect_AlertsQuery400OtherTypeKey_AlertsTriagedNotCheckable proves
// the typeKey match is exact, not "any HTTP 400" — a 400 with a different
// (or absent) typeKey must not be mistaken for the confirmed-not-enabled
// signal; it falls into the generic not-checkable case like any other
// unrecognized error.
func TestCollect_AlertsQuery400OtherTypeKey_AlertsTriagedNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, false)
	fx.Set("GET", azuredevops.HostAdvSec, alertsPath(testRepoID), adofixture.Response{
		Status: http.StatusBadRequest,
		Body:   map[string]any{"message": "some other bad request", "typeKey": "SomeOtherException"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idAlertsTriaged].Status; got != model.StatusNotCheckable {
		t.Errorf("alerts-triaged = %q, want not-checkable (a 400 with an unrecognized typeKey is not the confirmed signal); reason=%q", got, m[idAlertsTriaged].Reason)
	}
}

// TestCollect_AlertsQuery404_AlertsTriagedNotCheckable proves a 404 stays
// not-checkable even after issue #190's graduation of the CONFIRMED
// not-enabled signal (HTTP 400 + typeKey AdvSecNotEnabledException, see
// TestCollect_AlertsQuery400AdvSecNotEnabled_AlertsTriagedVerifiedFail) to
// verified-fail: no recorded response covers a 404 from this endpoint, so
// it stays an honest unknown rather than borrowing the 400 case's answer —
// see checkAlertsTriaged's own doc comment. The Reason itself must stay
// citation-free (issue #225 review): it lands in a customer's own
// evidence.json/report.md, and naming the S9 org/date there would leak an
// unrelated third party's org into a customer's signed pack — that
// citation belongs in the doc comment and generated rubric only, so this
// test asserts its ABSENCE from the Reason, not its presence.
func TestCollect_AlertsQuery404_AlertsTriagedNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, false)
	fx.Set("GET", azuredevops.HostAdvSec, alertsPath(testRepoID), adofixture.Response{
		Status: http.StatusNotFound, Body: map[string]any{"message": "not licensed"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	got := m[idAlertsTriaged]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("alerts-triaged = %q, want not-checkable (a 404 is only a LIKELY \"not licensed\" reading, unconfirmed); reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "AdvSecNotEnabledException") {
		t.Errorf("Reason = %q, want it to distinguish this 404 from the confirmed AdvSecNotEnabledException signal", got.Reason)
	}
	if strings.Contains(got.Reason, "dev.azure.com") || strings.Contains(got.Reason, "seciq") {
		t.Errorf("Reason = %q, must not leak the S9 recording org/date into a customer-facing Reason string", got.Reason)
	}
}

func TestCollect_AlertsQuery403_AlertsTriagedNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false, false)
	fx.Set("GET", azuredevops.HostAdvSec, alertsPath(testRepoID), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	if got := m[idAlertsTriaged].Status; got != model.StatusNotCheckable {
		t.Errorf("alerts-triaged = %q, want not-checkable (a 403 is ambiguous, must never read as confirmed); reason=%q", got, m[idAlertsTriaged].Reason)
	}
}

// --- shared vs. local upstream failures (package doc comment judgment call 6) ---

func TestCollect_RepoNotFoundInProject_AllNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": "other-repo", "defaultBranch": "refs/heads/main"})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range checkIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got)
		}
	}
	if !strings.Contains(m[idToolConfigured].Reason, testRepo) {
		t.Errorf("Reason = %q, want it to name the repo that wasn't found", m[idToolConfigured].Reason)
	}
}

func TestCollect_RepositoriesListFailure403_AllNotCheckable(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, repositoriesPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range checkIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got)
		}
	}
	if !strings.Contains(m[idToolConfigured].Reason, "permission") {
		t.Errorf("Reason = %q, want it to mention permission for a 403", m[idToolConfigured].Reason)
	}
}

func TestCollect_PipelinesListFailure_AllNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	fx.Set("GET", azuredevops.HostCore, pipelinesPath(), adofixture.Response{
		Status: http.StatusInternalServerError, Body: map[string]any{"message": "boom"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	for _, id := range checkIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got)
		}
	}
}

// TestCollect_ReleaseResolutionFailure_OnlyRanPerReleaseNotCheckable is the
// acceptance test distinguishing this package's architecture from C05's
// (see the package doc comment's judgment call 6): a release-tag
// resolution failure must NOT blanket tool-configured, dependabot-config,
// dependency-review, or alerts-triaged — only ran-per-release, the one
// check that actually consumes release data.
func TestCollect_ReleaseResolutionFailure_OnlyRanPerReleaseNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - task: AdvancedSecurity-Dependency-Scanning@1\n")
	fx.Set("GET", azuredevops.HostCore, refsPath(testRepoID), adofixture.Response{
		Status: http.StatusInternalServerError, Body: map[string]any{"message": "boom"},
	})
	registerEnablement(fx, testRepoID, false, false)
	registerAlerts(fx, testRepoID)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idRanPerRelease].Status; got != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable; reason=%q", got, m[idRanPerRelease].Reason)
	}
	if got := m[idToolConfigured].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass (unaffected by the release-resolution failure — it never consumes release data); reason=%q", got, m[idToolConfigured].Reason)
	}
	if got := m[idAlertsTriaged].Status; got != model.StatusVerifiedPass {
		t.Errorf("alerts-triaged = %q, want verified-pass (unaffected by the release-resolution failure); reason=%q", got, m[idAlertsTriaged].Reason)
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

var checksWithNoEndpoint = map[string]bool{
	idDependabotConfig: true,
	idDependencyReview: true,
}

var checkWantStatuses = map[string][]model.Status{
	idToolConfigured:   {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idRanPerRelease:    {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idDependabotConfig: {model.StatusNotCheckable},
	idDependencyReview: {model.StatusNotCheckable},
	idAlertsTriaged:    {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) (dev\.azure\.com|advsec\.dev\.azure\.com)/`)

// TestCollect_RegisteredMetadataCompleteForChecksReference mirrors C05's
// identical test, with the checksWithNoEndpoint exemption (mirroring
// auditlogging's own precedent for retentionAwarenessID) for
// dependabot-config/dependency-review, which have no ADO evidence source
// at all.
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

// rubricState is one fixture world for TestRubricsMatchObservedBehaviour.
// build is a function rather than data because these worlds differ in WHICH
// endpoints exist at all, not just in what they answer.
type rubricState struct {
	name  string
	build func(fx *adofixture.Transport)
	want  map[string]model.Status
	// wantReasonContains pins a check's Reason where the STATUS alone cannot
	// tell two causes apart. Only state 12 needs it: a release-resolution
	// failure and "no tag matched the pattern" both leave ran-per-release
	// not-checkable, so a mutation that stopped treating the failure as its
	// own case would be invisible to a status-only matrix.
	wantReasonContains map[string]string
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// Thirteen states reach every status this collector can emit. dependabot-config
// and dependency-review consume zero evidence and return not-checkable on every
// repo unconditionally (Azure DevOps has neither a dependabot.yml convention nor
// a PR dependency-review gate), so no fixture can move them; the guard's
// documented-but-unreachable direction is what pins their single-status rubrics.
//
// Three conflation risks, all real:
//
//  1. tool-configured and ran-per-release read the SAME matched-pipeline set and
//     the SAME enablement response, so a matrix that varies "is an SCA tool
//     configured" moves both together. They are split in every direction that
//     matters: state 2 (a build exists but covers no release) and state 3 (the
//     build covers the release but failed) both hold tool-configured at pass
//     while ran-per-release moves; state 4 reverses it, with ran-per-release
//     passing on a build that only a low-confidence match identified; state 5
//     splits them on the injection-only guard.
//
//  2. tool-configured and alerts-triaged BOTH depend on advsec.dev.azure.com,
//     and both go not-checkable when their advsec call fails. A matrix that only
//     ever gated that host as a whole would move them in lockstep and never test
//     that they read different endpoints. States 7 and 8 are the exact reverse of
//     each other — enablement denied while alerts answer, then alerts denied
//     while enablement answers — which is what pins each check to its own path
//     rather than to advsec reachability.
//
//  3. relErr is LOCAL to ran-per-release here, unlike C05 where a
//     release-resolution failure blankets every check (the package doc comment's
//     judgment call 6). State 11 is the only state that proves it: the refs
//     listing is denied and ONLY ran-per-release goes not-checkable.
//
// Verified by mutation rather than assumed — see the commit message for which
// states caught which.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	releaseDate := time.Now().UTC().AddDate(0, 0, -30)
	recent := time.Now().UTC().AddDate(0, 0, -5)

	repos := func(fx *adofixture.Transport) {
		registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	}
	// highConfPipeline is a real ado_task match against the embedded GHAzDO
	// dependency-scanning signature; lowConfPipeline matches snyk's
	// workflow_name_patterns only — a pipeline NAMED after a scanner with no
	// task or CLI invocation anywhere in it.
	highConfPipeline := func(fx *adofixture.Transport) {
		registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
		registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
		registerYAML(fx, testRepoID, "steps:\n  - task: AdvancedSecurity-Dependency-Scanning@1\n")
	}
	lowConfPipeline := func(fx *adofixture.Transport) {
		registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
		registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
		registerYAML(fx, testRepoID, "name: My Snyk Check\nsteps:\n  - script: echo hello\n")
	}
	oneRelease := func(fx *adofixture.Transport) {
		registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
		registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	}
	build := func(sha, result string, at time.Time) map[string]any {
		return map[string]any{
			"sourceVersion": sha, "sourceBranch": "refs/heads/main",
			"result": result, "queueTime": at.Format(time.RFC3339),
		}
	}
	criticalAlert := func(firstSeen string) map[string]any {
		return map[string]any{"firstSeenDate": firstSeen, "severity": "critical", "state": "active"}
	}
	// A critical alert that was already dealt with. It is old enough to push
	// the result past the triage window if it were ever counted, which is the
	// point: state 1 stays a pass only because the state filter excludes it.
	fixedOldCriticalAlert := map[string]any{
		"firstSeenDate": time.Now().UTC().AddDate(0, 0, -100).Format(time.RFC3339),
		"severity":      "critical", "state": "fixed",
	}
	denied := adofixture.Response{Status: http.StatusForbidden, Body: map[string]any{"message": "denied"}}

	states := []rubricState{
		{
			// The alerts fixture here is deliberately NOT an empty list: one
			// genuinely open critical alert well inside the triage window, and
			// one long-since-fixed critical alert old enough to fail the window
			// if it were counted. An empty list passes without exercising
			// either the age comparison or the state filter.
			name: "a dependency-scanning task, a successful release build, and one recent critical alert",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				highConfPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1", "succeeded", releaseDate))
				registerEnablement(fx, testRepoID, false, false)
				registerAlerts(fx, testRepoID, criticalAlert(recent.Format(time.RFC3339)), fixedOldCriticalAlert)
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedPass,
				idRanPerRelease:    model.StatusVerifiedPass,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusVerifiedPass,
			},
		},
		{
			// A build in the window that covers no release: the commit differs
			// and it was queued after the release it would have to cover.
			name: "a build in the lookback window that covers no release",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				highConfPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha-unrelated", "succeeded", recent))
				registerEnablement(fx, testRepoID, false, false)
				registerAlerts(fx, testRepoID)
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedPass,
				idRanPerRelease:    model.StatusVerifiedFail,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusVerifiedPass,
			},
		},
		{
			name: "the release's only build failed",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				highConfPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1", "failed", releaseDate))
				registerEnablement(fx, testRepoID, false, false)
				registerAlerts(fx, testRepoID)
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedPass,
				idRanPerRelease:    model.StatusPartial,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusVerifiedPass,
			},
		},
		{
			// The confidence cap, and the split in the other direction:
			// ran-per-release passes on a build that only a name-only match
			// identified, while tool-configured refuses to call that
			// configuration.
			name: "a pipeline whose NAME suggests SCA, with a successful release build",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				lowConfPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1", "succeeded", releaseDate))
				registerEnablement(fx, testRepoID, false, false)
				registerAlerts(fx, testRepoID)
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusPartial,
				idRanPerRelease:    model.StatusVerifiedPass,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusVerifiedPass,
			},
		},
		{
			// Injection is the ONLY evidence. tool-configured passes on it;
			// ran-per-release must not report a confident absence from a scan
			// history that runs invisibly to build-matching.
			// The two enablement flags are deliberately set to DISAGREE here
			// (injection on, codeSecurityEnabled off) and to disagree the
			// other way in state 6. Both checks that read enablement read
			// dependencyScanningInjectionEnabled specifically, and with the
			// two flags always equal a check reading the wrong one would be
			// invisible — found by mutation, which is why the flags differ.
			name: "dependency scanning injection enabled with no matched pipeline at all",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				registerPipelines(fx)
				oneRelease(fx)
				registerEnablement(fx, testRepoID, true, false)
				registerAlerts(fx, testRepoID)
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedPass,
				idRanPerRelease:    model.StatusNotCheckable,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusVerifiedPass,
			},
		},
		{
			// codeSecurityEnabled is ON here while injection is OFF — the
			// reverse of state 5. A check reading codeSecurityEnabled would
			// report this repo as configured; it is not.
			name: "no injected SCA scanning, though Advanced Security itself is on",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				registerPipelines(fx)
				oneRelease(fx)
				registerEnablement(fx, testRepoID, false, true)
				registerAlerts(fx, testRepoID)
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedFail,
				idRanPerRelease:    model.StatusVerifiedFail,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusVerifiedPass,
			},
		},
		{
			// Half of advsec denied: the enablement endpoint refuses while the
			// alerts endpoint answers. The two checks that live on that host
			// must not move together — this is the state a matrix that gated
			// advsec as a whole would never produce.
			name: "the enablement query is denied while the alerts query answers",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				registerPipelines(fx)
				oneRelease(fx)
				fx.Set("GET", azuredevops.HostAdvSec, enablementPath(testRepoID), denied)
				registerAlerts(fx, testRepoID)
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusNotCheckable,
				idRanPerRelease:    model.StatusNotCheckable,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusVerifiedPass,
			},
		},
		{
			// The exact reverse of state 7, and alerts-triaged's only
			// isolation: everything else resolves and only the alerts read is
			// denied.
			name: "the alerts query is denied while the enablement query answers",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				highConfPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1", "succeeded", releaseDate))
				registerEnablement(fx, testRepoID, false, false)
				fx.Set("GET", azuredevops.HostAdvSec, alertsPath(testRepoID), denied)
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedPass,
				idRanPerRelease:    model.StatusVerifiedPass,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusNotCheckable,
			},
		},
		{
			// alerts-triaged's only route to verified-fail, and the only
			// advsec error that is a confirmed answer rather than an unknown:
			// HTTP 400 carrying typeKey AdvSecNotEnabledException. State 8's
			// 403 on the same endpoint is not-checkable, so the pair together
			// prove this check reads the typeKey and not merely the failure.
			name: "the alerts query reports Advanced Security is not enabled",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				highConfPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1", "succeeded", releaseDate))
				registerEnablement(fx, testRepoID, false, false)
				fx.Set("GET", azuredevops.HostAdvSec, alertsPath(testRepoID), adofixture.Response{
					Status: http.StatusBadRequest,
					Body: map[string]any{
						"message": "VS2150009: Advanced Security is not enabled for this repository.",
						"typeKey": "AdvSecNotEnabledException",
					},
				})
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedPass,
				idRanPerRelease:    model.StatusVerifiedPass,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusVerifiedFail,
			},
		},
		{
			// alerts-triaged's age route to partial. Paired with state 1,
			// whose alert is the same shape and inside the window, this pins
			// the triage threshold rather than the mere presence of an alert.
			name: "one active critical alert open beyond the triage window",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				highConfPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1", "succeeded", releaseDate))
				registerEnablement(fx, testRepoID, false, false)
				registerAlerts(fx, testRepoID, criticalAlert(time.Now().UTC().AddDate(0, 0, -45).Format(time.RFC3339)))
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedPass,
				idRanPerRelease:    model.StatusVerifiedPass,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusPartial,
			},
		},
		{
			// alerts-triaged's second, distinct route to partial: an alert
			// that is genuinely open and whose age is genuinely unknown. An
			// earlier version read the zero-value age as "0 days old" and
			// reported a false pass, which is exactly what state 1 would look
			// like — so the two states together are what hold this apart.
			name: "one active critical alert whose firstSeenDate cannot be parsed",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				highConfPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1", "succeeded", releaseDate))
				registerEnablement(fx, testRepoID, false, false)
				registerAlerts(fx, testRepoID, criticalAlert("not-a-real-date"))
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedPass,
				idRanPerRelease:    model.StatusVerifiedPass,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusPartial,
			},
		},
		{
			// Judgment call 6: a release-resolution failure is LOCAL to
			// ran-per-release here, unlike C05 where it blankets every check.
			// The refs listing is denied and every other check resolves
			// normally — nothing else in the matrix would notice if that
			// locality were lost.
			name: "the release-tag listing is denied",
			wantReasonContains: map[string]string{
				idRanPerRelease: "could not resolve this repo's release tags",
			},
			build: func(fx *adofixture.Transport) {
				repos(fx)
				highConfPipeline(fx)
				fx.Set("GET", azuredevops.HostCore, refsPath(testRepoID), denied)
				registerEnablement(fx, testRepoID, false, false)
				registerAlerts(fx, testRepoID)
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedPass,
				idRanPerRelease:    model.StatusNotCheckable,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusVerifiedPass,
			},
		},
		{
			// ran-per-release's dropped-tag cap, inherited from C05: every
			// release that could be evaluated ran cleanly, and one undateable
			// tag matching the pattern still caps the result at partial.
			name: "every evaluated release ran cleanly but one release tag cannot be dated",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				highConfPipeline(fx)
				fx.Set("GET", azuredevops.HostCore, refsPath(testRepoID), adofixture.Response{
					Status: http.StatusOK,
					Body: map[string]any{"count": 2, "value": []map[string]any{
						{"name": "refs/tags/v1.0.0", "objectId": "sha1"},
						{"name": "refs/tags/v2.0.0", "objectId": "sha2"},
					}},
				})
				registerCommitDate(fx, testRepoID, "sha1", releaseDate)
				fx.Set("GET", azuredevops.HostCore, commitsPath(testRepoID, "sha2"), adofixture.Response{
					Status: http.StatusNotFound, Body: map[string]any{"message": "not found"},
				})
				registerBuilds(fx, build("sha1", "succeeded", releaseDate))
				registerEnablement(fx, testRepoID, false, false)
				registerAlerts(fx, testRepoID)
			},
			want: map[string]model.Status{
				idToolConfigured:   model.StatusVerifiedPass,
				idRanPerRelease:    model.StatusPartial,
				idDependabotConfig: model.StatusNotCheckable,
				idDependencyReview: model.StatusNotCheckable,
				idAlertsTriaged:    model.StatusVerifiedPass,
			},
		},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			fx := adofixture.New()
			st.build(fx)

			results, err := newCollector(fx).Collect(context.Background(), defaultScope())
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}

			got := map[string]model.Status{}
			for _, r := range results {
				if _, dup := got[r.CheckID]; dup {
					t.Errorf("%s emitted twice", r.CheckID)
				}
				got[r.CheckID] = r.Status
				if want, ok := st.wantReasonContains[r.CheckID]; ok && !strings.Contains(r.Reason, want) {
					t.Errorf("%s Reason = %q, want it to contain %q", r.CheckID, r.Reason, want)
				}
			}
			for id := range st.wantReasonContains {
				if _, ok := got[id]; !ok {
					t.Errorf("%s has a Reason expectation but emitted no result", id)
				}
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

	collecttest.AssertRubricsMatchObservedBehaviour(t, "azuredevops", collectorID, all)
}
