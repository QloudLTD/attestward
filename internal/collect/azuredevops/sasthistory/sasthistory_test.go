package sasthistory

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/collect/azuredevops/adofixture"
	"github.com/sioakim/attestward/internal/model"
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

// registerLightweightTag registers a single lightweight tag (objectId IS
// the commit SHA directly — no annotated-tag object to resolve first;
// pipelinehistory's own release_test.go already covers the
// annotated-vs-lightweight branching in full, so every scenario here uses
// the simpler lightweight form).
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

func registerEnablement(fx *adofixture.Transport, repositoryID string, codeQLEnabled bool) {
	fx.Set("GET", azuredevops.HostAdvSec, enablementPath(repositoryID), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"codeSecurityFeatures": map[string]any{"codeQLEnabled": codeQLEnabled}},
	})
}

func defaultScope() collect.Scope {
	return collect.Scope{
		Org: testOrg, Project: testProject, Repos: []string{testRepo},
		ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12,
	}
}

// --- full happy-path / confidence-ladder scenarios ---

// TestCollect_CodeQLTaskWithSuccessfulReleaseBuild_AllChecksResolve exercises
// a high-confidence ado_task match (the real embedded "codeql" signature's
// AdvancedSecurity-Codeql-Init/Analyze tasks — this collector loads the
// real mappings.FS registry directly, the same as the GitHub twin, so
// every scenario here uses real signature IDs, not a synthetic registry).
func TestCollect_CodeQLTaskWithSuccessfulReleaseBuild_AllChecksResolve(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - task: AdvancedSecurity-Codeql-Init@1\n  - task: AdvancedSecurity-Codeql-Analyze@1\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})
	registerEnablement(fx, testRepoID, false)

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
	if got := m[idCadence].Status; got != model.StatusVerifiedPass {
		t.Errorf("cadence = %q, want verified-pass; reason=%q", got, m[idCadence].Reason)
	}
	if got := m[idDefaultSetup].Status; got != model.StatusVerifiedFail {
		t.Errorf("default-setup = %q, want verified-fail (codeQLEnabled false is a real fail); reason=%q", got, m[idDefaultSetup].Reason)
	}

	perRelease, ok := m[idRanPerRelease].Facts["per_release"].([]map[string]any)
	if !ok || len(perRelease) != 1 || perRelease[0]["tag"] != "v1.0.0" || perRelease[0]["status"] != "ran" {
		t.Errorf("per_release facts = %v, want one entry tag=v1.0.0 status=ran", m[idRanPerRelease].Facts["per_release"])
	}
}

func TestCollect_NoSASTToolAtAll_ToolConfiguredFailsCadenceNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusVerifiedFail {
		t.Errorf("tool-configured = %q, want verified-fail; reason=%q", got, m[idToolConfigured].Reason)
	}
	if got := m[idCadence].Status; got != model.StatusNotCheckable {
		t.Errorf("cadence = %q, want not-checkable; reason=%q", got, m[idCadence].Reason)
	}
	if got := m[idRanPerRelease].Status; got != model.StatusVerifiedFail {
		t.Errorf("ran-per-release = %q, want verified-fail (a real release with zero matched builds is a genuine gap even with no tool configured at all); reason=%q", got, m[idRanPerRelease].Reason)
	}
}

// TestCollect_SameRepoSkip_ToolConfiguredNotCheckableNotFail is the C05
// twin of azuredevops/scahistory's identically-named test (issue #178):
// one pipeline in this repo resolves to a YAML pipeline but its
// yamlFilename is missing (YAMLPathUnknown), producing a SkippedPipeline;
// with zero matched pipelines and GHAzDO CodeQL default setup off, this
// must cap at not-checkable, not a confident verified-fail.
func TestCollect_SameRepoSkip_ToolConfiguredNotCheckableNotFail(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "unresolved-pipeline"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": ""}, testRepoID, "refs/heads/main")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false)

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

	// Review finding on #202: this fixture already has a real release
	// (v1.0.0) in scope, so it also exercises ran-per-release's own
	// coverage-computation path — previously that read verified-fail ("no
	// matched SAST build at all") in the same breath tool-configured read
	// not-checkable for the identical evidence. Both must now agree.
	ranPerRelease := m[idRanPerRelease]
	if ranPerRelease.Status != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable (must agree with tool-configured's not-checkable over the identical unresolved-pipeline evidence, not independently assert verified-fail); reason=%q", ranPerRelease.Status, ranPerRelease.Reason)
	}
}

// TestCollect_LowConfidenceOnlyMatch_CapsToolConfiguredAndCadenceAtPartial
// uses semgrep's workflow_name_patterns-only signal (a pipeline named after
// semgrep, with no actual run-pattern/ado_task invocation) — the weakest
// tier, which must never alone justify verified-pass.
func TestCollect_LowConfidenceOnlyMatch_CapsToolConfiguredAndCadenceAtPartial(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "name: My Semgrep Check\nsteps:\n  - script: echo hello\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})
	registerEnablement(fx, testRepoID, false)

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
	if gotCadence := m[idCadence].Status; gotCadence != model.StatusPartial {
		t.Errorf("cadence = %q, want partial (real build activity, but only a low-confidence match identified the tool); reason=%q", gotCadence, m[idCadence].Reason)
	}
}

// TestCollect_LowConfidenceMatchPlusCodeQLEnabled_CadenceStillPartial is
// the regression test for item 4 found in review: GHAzDO CodeQL default
// setup being enabled must NOT "rescue" a low-confidence-only pipeline
// match's cadence into verified-pass, even though tool-configured's own
// OR condition does let default setup alone justify a pass. Every build
// actually observed here comes from the low-confidence pipeline match —
// default setup itself contributes zero observable builds (see the
// package doc comment's deviation (b)) — so cadence must stay capped at
// partial regardless of enablement.CodeQLEnabled. This is a deliberate
// divergence from the GitHub twin's own identical-shaped formula, which
// DOES let a genuinely-configured default setup rescue this case, since
// GitHub's default setup contributes real, additional observable run
// history there.
func TestCollect_LowConfidenceMatchPlusCodeQLEnabled_CadenceStillPartial(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "name: My Semgrep Check\nsteps:\n  - script: echo hello\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})
	registerEnablement(fx, testRepoID, true) // GHAzDO default setup ALSO enabled

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	// tool-configured legitimately passes via the OR condition.
	if got := m[idToolConfigured].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass (GHAzDO default setup alone is enough); reason=%q", got, m[idToolConfigured].Reason)
	}
	// cadence must NOT be rescued by codeQLEnabled: the only observed
	// builds came from a low-confidence-only pipeline match.
	got := m[idCadence]
	if got.Status != model.StatusPartial {
		t.Errorf("cadence = %q, want partial (codeQLEnabled must not upgrade a low-confidence-only match's cadence to pass); reason=%q", got.Status, got.Reason)
	}
	if got.Facts["low_confidence_match_only"] != true {
		t.Errorf("low_confidence_match_only = %v, want true", got.Facts["low_confidence_match_only"])
	}
}

// TestCollect_MediumConfidenceRunPatternMatch_VerifiedPass uses semgrep's
// run_pattern signal (an actual `semgrep` invocation in a script step) —
// medium confidence, enough to pass on its own.
func TestCollect_MediumConfidenceRunPatternMatch_VerifiedPass(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - script: semgrep scan --config auto\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})
	registerEnablement(fx, testRepoID, false)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass; reason=%q", got, m[idToolConfigured].Reason)
	}
	if got := m[idCadence].Status; got != model.StatusVerifiedPass {
		t.Errorf("cadence = %q, want verified-pass; reason=%q", got, m[idCadence].Reason)
	}
}

// TestCollect_CodeQLDefaultSetupOnly_ToolConfiguredPassesCadenceNotCheckable
// is the acceptance test for this collector's key ADO-specific deviation
// (see the package doc comment): GHAzDO CodeQL default setup alone makes
// tool-configured pass, but cadence must NOT assert a run count it has no
// way to observe — this collector has no verified way to observe
// default-setup's own scan history via the Pipelines/Builds APIs it
// uses, unlike GitHub's own default setup (a real, queryable virtual
// workflow).
func TestCollect_CodeQLDefaultSetupOnly_ToolConfiguredPassesCadenceNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, true)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusVerifiedPass {
		t.Errorf("tool-configured = %q, want verified-pass (GHAzDO CodeQL default setup alone is enough); reason=%q", got, m[idToolConfigured].Reason)
	}
	got := m[idCadence]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("cadence = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "no verified way to observe") {
		t.Errorf("cadence Reason = %q, want it to explain this collector has no verified way to observe GHAzDO default setup's scan history", got.Reason)
	}
	if got := m[idDefaultSetup].Status; got != model.StatusVerifiedPass {
		t.Errorf("default-setup = %q, want verified-pass", got)
	}
	// Issue #184: a real release tag exists in scope with zero matched
	// pipelines and CodeQL default setup enabled — before the fix,
	// ran-per-release independently concluded verified-fail ("no matched
	// SAST run at all"), self-contradicting tool-configured's verified-pass
	// for the identical evidence.
	ranPerRelease := m[idRanPerRelease]
	if ranPerRelease.Status != model.StatusNotCheckable {
		t.Errorf("ran-per-release = %q, want not-checkable (default-setup-only evidence isn't observable per release); reason=%q", ranPerRelease.Status, ranPerRelease.Reason)
	}
}

// TestCollect_ConfiguredButBuildNeverSucceeds_RanPerReleaseIsPartial proves
// "configured and attempted, but not clean" caps at partial, never
// verified-fail (that status is reserved for a release with NO matched
// build at all).
func TestCollect_ConfiguredButBuildNeverSucceeds_RanPerReleaseIsPartial(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - task: AdvancedSecurity-Codeql-Init@1\n  - task: AdvancedSecurity-Codeql-Analyze@1\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "failed", "queueTime": releaseDate.Format(time.RFC3339)})
	registerEnablement(fx, testRepoID, false)

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
// list against this collector's own deliberate choice (see the package
// doc comment) to cap ran-per-release at partial and name the actual tags.
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
	registerEnablement(fx, testRepoID, false)

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

// TestCollect_CleanRunsCappedByOneDroppedTag_RanPerReleasePartial is the
// missing acceptance test (found in review) for the "allRan &&
// len(dropped) > 0" branch — the heart of deviation (a): every release
// that COULD be evaluated ran successfully, but a separate tag matching
// the pattern couldn't be dated, so the result is still capped at
// partial rather than a clean verified-pass.
func TestCollect_CleanRunsCappedByOneDroppedTag_RanPerReleasePartial(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - task: AdvancedSecurity-Codeql-Init@1\n  - task: AdvancedSecurity-Codeql-Analyze@1\n")
	fx.Set("GET", azuredevops.HostCore, refsPath(testRepoID), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{"count": 2, "value": []map[string]any{
			{"name": "refs/tags/v1.0.0", "objectId": "sha1"},
			{"name": "refs/tags/v2.0.0", "objectId": "sha2"},
		}},
	})
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	fx.Set("GET", azuredevops.HostCore, commitsPath(testRepoID, "sha2"), adofixture.Response{
		Status: http.StatusNotFound, Body: map[string]any{"message": "not found"},
	})
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})
	registerEnablement(fx, testRepoID, false)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idRanPerRelease]
	if got.Status != model.StatusPartial {
		t.Errorf("ran-per-release = %q, want partial (v1.0.0 ran cleanly, but v2.0.0 couldn't be dated, capping the result); reason=%q", got.Status, got.Reason)
	}
	if !strings.Contains(got.Reason, "1 release tag(s) could not be dated") {
		t.Errorf("Reason = %q, want it to name the one dropped tag and say \"could not be dated\" (not \"resolved to a commit\" — the commit is always already known)", got.Reason)
	}
	dropped, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(dropped) != 1 || dropped[0] != "v2.0.0" {
		t.Errorf("dropped_tags facts = %#v, want [\"v2.0.0\"]", got.Facts["dropped_tags"])
	}
	perRelease, ok := got.Facts["per_release"].([]map[string]any)
	if !ok || len(perRelease) != 1 || perRelease[0]["tag"] != "v1.0.0" || perRelease[0]["status"] != "ran" {
		t.Errorf("per_release facts = %v, want exactly one evaluated release (v1.0.0, ran)", got.Facts["per_release"])
	}
}

// --- GHAzDO repo-enablement gating ---

// TestCollect_Enablement404_ToolConfiguredStaysFail proves a 404 (treated
// as equivalent to "every enablement flag off" by deliberate policy, not
// because it's a confirmed fact about what causes it — see
// isAdvSecNotFoundErr's doc comment) still produces a real "not configured"
// verdict when there's no other evidence.
func TestCollect_Enablement404_ToolConfiguredStaysFail(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	fx.Set("GET", azuredevops.HostAdvSec, enablementPath(testRepoID), adofixture.Response{
		Status: http.StatusNotFound, Body: map[string]any{"message": "not licensed"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusVerifiedFail {
		t.Errorf("tool-configured = %q, want verified-fail (a 404 is a confirmed \"not configured\" fact); reason=%q", got, m[idToolConfigured].Reason)
	}
	if got := m[idDefaultSetup].Status; got != model.StatusNotCheckable {
		t.Errorf("default-setup = %q, want not-checkable (unlike tool-configured, default-setup's OWN result always goes not-checkable on any enablement error)", got)
	}
}

// TestCollect_Enablement403_NoOtherEvidence_ToolConfiguredNotCheckable is
// the regression test for the false-verified-fail bug found in review: a
// 403 most likely means the token lacks the vso.advsec scope, though other
// permission causes can't be excluded from the response alone (see
// sharedAdvSecGatedRubric) — a licensed org with default setup genuinely
// ON, scanned by a scope-less PAT, must never read as a confirmed fail
// here just because this collector can't see the real state. Only a 404
// is treated as equivalent to "off" (see TestCollect_Enablement404_...
// above); a 403 with no other evidence must go not-checkable instead,
// exactly like default-setup's own sibling result for the identical
// response.
func TestCollect_Enablement403_NoOtherEvidence_ToolConfiguredNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	fx.Set("GET", azuredevops.HostAdvSec, enablementPath(testRepoID), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusNotCheckable {
		t.Errorf("tool-configured = %q, want not-checkable (a 403 most likely means a missing token scope, but that can't be confirmed from the response alone — must never read as a confirmed fail); reason=%q", got, m[idToolConfigured].Reason)
	}
	if got := m[idDefaultSetup].Status; got != model.StatusNotCheckable {
		t.Errorf("default-setup = %q, want not-checkable", got)
	}
}

func TestCollect_EnablementGenericError_NoOtherEvidence_ToolConfiguredNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	fx.Set("GET", azuredevops.HostAdvSec, enablementPath(testRepoID), adofixture.Response{
		Status: http.StatusInternalServerError, Body: map[string]any{"message": "boom"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idToolConfigured].Status; got != model.StatusNotCheckable {
		t.Errorf("tool-configured = %q, want not-checkable (a genuine, non-gated error with no other evidence is an unknown, not a confirmed fail); reason=%q", got, m[idToolConfigured].Reason)
	}
}

// --- shared upstream failures ---

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

// --- provenance splitting ---

// TestCollect_DefaultSetupProvenanceIsolatedFromOtherThreeChecks proves the
// same asymmetric provenance split the GitHub twin's own collectRepo
// applies (see this package's collectRepo doc comment): default-setup's
// Provenance contains only the enablement call, while
// tool-configured/cadence/ran-per-release share everything else — the
// enablement call's own endpoint never appears in their Provenance.
func TestCollect_DefaultSetupProvenanceIsolatedFromOtherThreeChecks(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerEnablement(fx, testRepoID, false)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if len(m[idDefaultSetup].Provenance) != 1 {
		t.Fatalf("default-setup Provenance = %+v, want exactly 1 entry (just the enablement call)", m[idDefaultSetup].Provenance)
	}
	enablementEndpointHost := m[idDefaultSetup].Provenance[0].Endpoint
	for _, id := range []string{idToolConfigured, idRanPerRelease, idCadence} {
		for _, p := range m[id].Provenance {
			if p.Endpoint == enablementEndpointHost && p.Method == m[idDefaultSetup].Provenance[0].Method {
				t.Errorf("%s Provenance unexpectedly includes the enablement call's own endpoint %q — the GitHub twin's own collectRepo deliberately excludes it from these three checks' Provenance", id, enablementEndpointHost)
			}
		}
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

var checkWantStatuses = map[string][]model.Status{
	idToolConfigured: {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idRanPerRelease:  {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idCadence:        {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idDefaultSetup:   {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) (dev\.azure\.com|advsec\.dev\.azure\.com)/`)

// TestCollect_RegisteredMetadataCompleteForChecksReference mirrors the
// GitHub twin's identical test: exact Rubric key-set equality per check,
// GET/HEAD-only Endpoints enforcing ADR-0004, orphaned-key detection.
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

		if len(meta.Endpoints) == 0 {
			t.Errorf("%s: Endpoints is empty, want at least one", id)
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
