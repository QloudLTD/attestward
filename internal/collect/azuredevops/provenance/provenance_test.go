package provenance

import (
	"context"
	"net/http"
	"net/url"
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
// the commit SHA directly) — mirrors sasthistory_test.go's identical
// helper; pipelinehistory's own release_test.go already covers the
// annotated-vs-lightweight branching in full.
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

func defaultScope() collect.Scope {
	return collect.Scope{
		Org: testOrg, Project: testProject, Repos: []string{testRepo},
		ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12,
	}
}

// assertAlwaysNotCheckable checks the three evidence-free checks' fixed
// shape — every scenario in this file should call this, since they never
// vary regardless of what else is set up.
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
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - script: cosign sign-blob --bundle=out.bundle artifact.bin\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertAlwaysNotCheckable(t, byID(results))
}

func TestCollect_AlwaysNotCheckableChecksSurviveUpstreamFailure(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, repositoriesPath(), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	assertAlwaysNotCheckable(t, byID(results))
}

// --- provenance.workflow confidence ladder ---

// TestCollect_CosignRunPatternMatch_WorkflowVerifiedPass uses cosign's real
// embedded run_pattern signature (a medium-confidence match) — this
// collector loads the real mappings.FS registry directly, the same as
// sasthistory, so this test uses a real signature ID, not a synthetic one.
func TestCollect_CosignRunPatternMatch_WorkflowVerifiedPass(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - script: cosign sign-blob --bundle=out.bundle artifact.bin\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idWorkflow].Status; got != model.StatusVerifiedPass {
		t.Errorf("workflow = %q, want verified-pass; reason=%q", got, m[idWorkflow].Reason)
	}
	if got := m[idCommitLinkage].Status; got != model.StatusVerifiedPass {
		t.Errorf("commit-linkage = %q, want verified-pass; reason=%q", got, m[idCommitLinkage].Reason)
	}
}

// TestCollect_SLSANameOnlyMatch_WorkflowCapsAtPartial uses the SLSA
// generator signature's workflow_name_patterns-only signal — issue #153's
// own "no ADO-native attestation task exists" means this signature's
// action-slug (a GitHub reusable-workflow uses: call) never matches ADO
// YAML at all, so a low-confidence name match is the strongest evidence
// this signature can ever produce on this platform.
func TestCollect_SLSANameOnlyMatch_WorkflowCapsAtPartial(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "name: My SLSA Provenance Pipeline\nsteps:\n  - script: echo hello\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idWorkflow]
	if got.Status != model.StatusPartial {
		t.Errorf("workflow = %q, want partial; reason=%q", got.Status, got.Reason)
	}
	if got.Facts["low_confidence_match_only"] != true {
		t.Errorf("low_confidence_match_only = %v, want true", got.Facts["low_confidence_match_only"])
	}
}

func TestCollect_NoProvenanceToolAtAll_WorkflowVerifiedFail(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - script: echo hello\n")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idWorkflow].Status; got != model.StatusVerifiedFail {
		t.Errorf("workflow = %q, want verified-fail; reason=%q", got, m[idWorkflow].Reason)
	}
}

// --- issue #178: consuming same-repo skips from the start ---

// TestCollect_SameRepoSkip_WorkflowNotCheckableNotFail is the end-to-end
// acceptance test for the fix found in review (HIGH): the first version of
// this collector discarded pipelinehistory.MatchPipelines' skipped list
// entirely (matchedAll, _ = ...), so a repo whose only provenance pipeline
// couldn't be fully inspected got a confirmed verified-fail instead of an
// honest not-checkable. One pipeline here resolves to a YAML pipeline but
// its yamlFilename is missing (YAMLPathUnknown), producing a
// SkippedPipeline — mirrors C06 sca-history's own
// TestCollect_SameRepoSkip_ToolConfiguredNotCheckableNotFail exactly.
func TestCollect_SameRepoSkip_WorkflowNotCheckableNotFail(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "unresolved-pipeline"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": ""}, testRepoID, "refs/heads/main")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerBuilds(fx)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idWorkflow]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("workflow = %q, want not-checkable (a same-repo skip must cap what would otherwise be verified-fail); reason=%q", got.Status, got.Reason)
	}
	skipped, ok := got.Facts["skipped_pipelines"].([]map[string]any)
	if !ok || len(skipped) != 1 || skipped[0]["name"] != "unresolved-pipeline" {
		t.Errorf("skipped_pipelines facts = %#v, want one entry naming unresolved-pipeline", got.Facts["skipped_pipelines"])
	}
}

// TestCollect_SameRepoSkipAlongsideRealMatch_WorkflowStillVerifiedPass
// proves the skip fix never suppresses a genuine pass: a real
// medium-confidence match elsewhere in the repo must still win, with the
// skip still surfaced in Facts for visibility.
func TestCollect_SameRepoSkipAlongsideRealMatch_WorkflowStillVerifiedPass(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx,
		map[string]any{"id": 1, "name": "cosign-pipeline"},
		map[string]any{"id": 2, "name": "unresolved-pipeline"},
	)
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - script: cosign sign-blob --bundle=out.bundle artifact.bin\n")
	registerDefinition(fx, 2, map[string]any{"type": 2, "yamlFilename": ""}, testRepoID, "refs/heads/main")
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idWorkflow]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("workflow = %q, want verified-pass (a real match must not be suppressed by an unrelated same-repo skip); reason=%q", got.Status, got.Reason)
	}
	skipped, ok := got.Facts["skipped_pipelines"].([]map[string]any)
	if !ok || len(skipped) != 1 {
		t.Errorf("skipped_pipelines facts = %#v, want one entry even on a pass", got.Facts["skipped_pipelines"])
	}
}

// --- provenance.commit-linkage ---

func TestCollect_ReleaseWithNoMatchingBuildAtAll_CommitLinkageVerifiedFail(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	registerBuilds(fx) // zero builds at all

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idCommitLinkage]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("commit-linkage = %q, want verified-fail; reason=%q", got.Status, got.Reason)
	}
	perRelease, ok := got.Facts["per_release"].([]map[string]any)
	if !ok || len(perRelease) != 1 || perRelease[0]["tag"] != "v1.0.0" || perRelease[0]["run_count"] != 0 {
		t.Errorf("per_release facts = %v, want one entry tag=v1.0.0 run_count=0", got.Facts["per_release"])
	}
}

// TestCollect_BuildOnUnrelatedCommit_CommitLinkageVerifiedFail proves this
// check does NOT fall back to a branch+time-window heuristic the way
// C05/C06's own ran-per-release does — a build that ran on the default
// branch around the same time, but on a DIFFERENT commit than the release
// tag, must not count as covering it. See linkBuildsToCommits' own doc
// comment for why this diverges from pipelinehistory.LinkRunsToReleases.
func TestCollect_BuildOnUnrelatedCommit_CommitLinkageVerifiedFail(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	// This build ran on the default branch, in-window by time, but its
	// sourceVersion is a different commit than the release tag's own sha1.
	registerBuilds(fx, map[string]any{"sourceVersion": "unrelated-sha", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idCommitLinkage].Status; got != model.StatusVerifiedFail {
		t.Errorf("commit-linkage = %q, want verified-fail (a build on an unrelated commit must never count as coverage); reason=%q", got, m[idCommitLinkage].Reason)
	}
}

// TestCollect_BuildNeverSucceeds_CommitLinkageStillVerifiedPass proves this
// check is deliberately blind to build Result — "traceable to a build,"
// not "traceable to a SUCCESSFUL build" (unlike C05/C06's own
// ran-per-release) — mirrors the GitHub twin's identical choice.
func TestCollect_BuildNeverSucceeds_CommitLinkageStillVerifiedPass(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "failed", "queueTime": releaseDate.Format(time.RFC3339)})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idCommitLinkage].Status; got != model.StatusVerifiedPass {
		t.Errorf("commit-linkage = %q, want verified-pass (a failed build is still traceable to the commit); reason=%q", got, m[idCommitLinkage].Reason)
	}
}

// TestCollect_OneDroppedTag_CommitLinkageCappedAtPartial is the acceptance
// test for C05/C06's dropped-tag rule applied to commit-linkage: every
// evaluated release is covered, but a separate release tag couldn't be
// dated, so the result is capped at partial, not a clean verified-pass.
func TestCollect_OneDroppedTag_CommitLinkageCappedAtPartial(t *testing.T) {
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
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	fx.Set("GET", azuredevops.HostCore, commitsPath(testRepoID, "sha2"), adofixture.Response{
		Status: http.StatusNotFound, Body: map[string]any{"message": "not found"},
	})
	registerBuilds(fx, map[string]any{"sourceVersion": "sha1", "sourceBranch": "refs/heads/main", "result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339)})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idCommitLinkage]
	if got.Status != model.StatusPartial {
		t.Errorf("commit-linkage = %q, want partial (v1.0.0 covered, but v2.0.0 couldn't be dated); reason=%q", got.Status, got.Reason)
	}
	dropped, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(dropped) != 1 || dropped[0] != "v2.0.0" {
		t.Errorf("dropped_tags facts = %#v, want [\"v2.0.0\"]", got.Facts["dropped_tags"])
	}
}

func TestCollect_AllTagsUnresolvable_CommitLinkagePartialWithDroppedNames(t *testing.T) {
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

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	got := m[idCommitLinkage]
	if got.Status != model.StatusPartial {
		t.Errorf("commit-linkage = %q, want partial; reason=%q", got.Status, got.Reason)
	}
	dropped, ok := got.Facts["dropped_tags"].([]string)
	if !ok || len(dropped) != 2 {
		t.Fatalf("dropped_tags facts = %#v, want 2 entries", got.Facts["dropped_tags"])
	}
	if !strings.Contains(got.Reason, "could not be dated") {
		t.Errorf("Reason = %q, want it to mention the tags could not be dated", got.Reason)
	}
}

func TestCollect_NoMatchingReleaseTagsAtAll_CommitLinkageNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	fx.Set("GET", azuredevops.HostCore, refsPath(testRepoID), adofixture.Response{
		Status: http.StatusOK, Body: map[string]any{"count": 0, "value": []map[string]any{}},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idCommitLinkage].Status; got != model.StatusNotCheckable {
		t.Errorf("commit-linkage = %q, want not-checkable; reason=%q", got, m[idCommitLinkage].Reason)
	}
	if got := m[idWorkflow].Status; got != model.StatusVerifiedFail {
		t.Errorf("workflow = %q, want verified-fail (release-independent, unaffected by zero releases); reason=%q", got, m[idWorkflow].Reason)
	}
}

func TestCollect_BuildsFetchFails_CommitLinkageNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", time.Now().UTC().AddDate(0, 0, -5))
	fx.Set("GET", azuredevops.HostCore, buildsPath(), adofixture.Response{
		Status: http.StatusInternalServerError, Body: map[string]any{"message": "boom"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m[idCommitLinkage].Status; got != model.StatusNotCheckable {
		t.Errorf("commit-linkage = %q, want not-checkable; reason=%q", got, m[idCommitLinkage].Reason)
	}
}

// queryCapturingTransport records the last request's query parameters for
// a given path — mirrors pipelinehistory's/secretshygiene's identical
// helper, used here to verify the ACTUAL minTime this collector sends to
// the builds endpoint: adofixture.Transport itself is keyed by
// (method, host, path) only and ignores the query string entirely, so a
// response-content-based test can't distinguish "the old, boundary-prone
// minTime" from "the new, widened one" — only capturing the real request
// can.
type queryCapturingTransport struct {
	base      http.RoundTripper
	path      string
	lastQuery url.Values
}

func (c *queryCapturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == c.path {
		c.lastQuery = req.URL.Query()
	}
	return c.base.RoundTrip(req)
}

// TestCollect_CommitLinkageBuildsFetch_MinTimeAnchoredToOldestReleaseMinusGraceWindow
// is the regression test for the MEDIUM boundary-false-fail finding in
// review: FetchBuilds' own minTime was previously the same raw
// now-LookbackMonths cutoff releases are admitted at-or-after, so a
// release admitted right at that cutoff whose commit's build was queued
// earlier (routine for an annotated tag created some time after its own
// commit) fell outside the fetched window entirely — a false "no build
// traceable to its commit." This proves the fetch is now anchored to the
// oldest EVALUATED release's own date minus commitLinkageBuildGraceWindow
// instead: in this scenario (a release from 5 days ago, well inside the
// default 12-month lookback), that anchor is far more recent than
// now-12-months, proving minTime tracks the release date, not the raw
// lookback cutoff.
func TestCollect_CommitLinkageBuildsFetch_MinTimeAnchoredToOldestReleaseMinusGraceWindow(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx)
	releaseDate := time.Now().UTC().AddDate(0, 0, -5)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx)

	capture := &queryCapturingTransport{base: fx, path: buildsPath()}
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", capture)
	c := New(client)

	if _, err := c.Collect(context.Background(), defaultScope()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if capture.lastQuery == nil {
		t.Fatal("no request captured against the builds endpoint")
	}
	gotMinTime, err := time.Parse(time.RFC3339, capture.lastQuery.Get("minTime"))
	if err != nil {
		t.Fatalf("minTime = %q, want a valid RFC3339 timestamp: %v", capture.lastQuery.Get("minTime"), err)
	}
	wantMinTime := releaseDate.Add(-commitLinkageBuildGraceWindow)
	if diff := gotMinTime.Sub(wantMinTime); diff < -time.Second || diff > time.Second {
		t.Errorf("minTime = %v, want %v (the oldest evaluated release's own date minus the grace window) — a diff of %v means this is still anchored to the raw lookback cutoff instead", gotMinTime, wantMinTime, diff)
	}
	oldCutoff := time.Now().UTC().AddDate(0, -defaultScope().LookbackMonths, 0)
	if !gotMinTime.After(oldCutoff) {
		t.Errorf("minTime = %v, want it after the old raw lookback cutoff %v — the fix is supposed to narrow the fetch for a recent release, not widen it further", gotMinTime, oldCutoff)
	}
}

// --- shared upstream failures ---

func TestCollect_RepoNotFoundInProject_EvidenceChecksNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": "other-repo", "defaultBranch": "refs/heads/main"})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	assertAlwaysNotCheckable(t, m)
	for _, id := range evidenceCheckIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got)
		}
	}
	if !strings.Contains(m[idWorkflow].Reason, testRepo) {
		t.Errorf("Reason = %q, want it to name the repo that wasn't found", m[idWorkflow].Reason)
	}
}

func TestCollect_RepositoriesListFailure403_EvidenceChecksNotCheckable(t *testing.T) {
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
	assertAlwaysNotCheckable(t, m)
	for _, id := range evidenceCheckIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got)
		}
	}
	if !strings.Contains(m[idWorkflow].Reason, "permission") {
		t.Errorf("Reason = %q, want it to mention permission for a 403", m[idWorkflow].Reason)
	}
}

// TestCollect_PipelinesListFailure_CommitLinkageAlsoNotCheckable proves the
// deliberate asymmetry stated in the package doc comment: commit-linkage
// never reads pipeline-match data, but still goes not-checkable when
// pipeline discovery fails, mirroring sasthistory's idDefaultSetup.
func TestCollect_PipelinesListFailure_CommitLinkageAlsoNotCheckable(t *testing.T) {
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
	assertAlwaysNotCheckable(t, m)
	for _, id := range evidenceCheckIDs {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got)
		}
	}
}

// TestCollect_ReleaseResolutionFailure_WorkflowAlsoNotCheckable proves the
// mirror-image asymmetry: provenance.workflow never reads release data, but
// still goes not-checkable when this repo's own release-tag resolution
// fails outright (a genuine API error, not just an empty tag list).
func TestCollect_ReleaseResolutionFailure_WorkflowAlsoNotCheckable(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
	registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - script: cosign sign-blob artifact.bin\n")
	fx.Set("GET", azuredevops.HostCore, refsPath(testRepoID), adofixture.Response{
		Status: http.StatusForbidden, Body: map[string]any{"message": "forbidden"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), defaultScope())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	assertAlwaysNotCheckable(t, m)
	if got := m[idWorkflow].Status; got != model.StatusNotCheckable {
		t.Errorf("workflow = %q, want not-checkable (shared upstream gate includes release-tag resolution); reason=%q", got, m[idWorkflow].Reason)
	}
	if got := m[idCommitLinkage].Status; got != model.StatusNotCheckable {
		t.Errorf("commit-linkage = %q, want not-checkable; reason=%q", got, m[idCommitLinkage].Reason)
	}
}

// --- cancellation ---

// TestCollect_PreCanceledContext_AlwaysNotCheckableChecksKeepFixedReasons is
// the regression test named in review (LOW): vdp's own identical
// convention exists because this exact case regressed once there — the
// three always-not-checkable checks never depended on ctx or any API call
// to begin with, so a pre-canceled context must produce byte-identical
// results to the normal (non-canceled) path, not a generic "scan canceled"
// substitute.
func TestCollect_PreCanceledContext_AlwaysNotCheckableChecksKeepFixedReasons(t *testing.T) {
	fx := adofixture.New()
	c := newCollector(fx)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := c.Collect(ctx, collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)
	assertAlwaysNotCheckable(t, m)

	want := alwaysNotCheckableResults(testOrg, testRepo)
	wantByID := byID(want)
	for _, id := range alwaysNotCheckableIDs {
		if m[id].Reason != wantByID[id].Reason {
			t.Errorf("%s Reason (canceled ctx) = %q, want the fixed reason %q unchanged by cancellation", id, m[id].Reason, wantByID[id].Reason)
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

// TestCollect_CollectorIDMatchesGitHubTwin proves this package registers
// under the exact same Collector string as
// internal/collect/github/provenance — collect.Register panics on a
// mismatch (registry.go), but this test pins the expectation directly so a
// future rename here is caught by this package's own tests, not just a
// panic at some other package's init() time — mirrors orgsecurity's
// identical pattern.
func TestCollect_CollectorIDMatchesGitHubTwin(t *testing.T) {
	if collectorID != "C07.provenance" {
		t.Errorf("collectorID = %q, want \"C07.provenance\" (must match the GitHub twin's exactly)", collectorID)
	}
}

var checkWantStatuses = map[string][]model.Status{
	idTagsSigned:    {model.StatusNotCheckable},
	idChecksums:     {model.StatusNotCheckable},
	idSignatures:    {model.StatusNotCheckable},
	idWorkflow:      {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	idCommitLinkage: {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
}

var checksWithNoEndpoint = map[string]bool{
	idTagsSigned: true,
	idChecksums:  true,
	idSignatures: true,
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) (dev\.azure\.com|advsec\.dev\.azure\.com)/`)

// TestCollect_RegisteredMetadataCompleteForChecksReference mirrors
// sasthistory's/vdp's identical test: exact Rubric key-set equality per
// check, GET/HEAD-only Endpoints enforcing ADR-0004, orphaned-key
// detection, and the Endpoints-non-empty exemption for the three
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

// rubricState is one fixture world for TestRubricsMatchObservedBehaviour.
// build is a function rather than data because these worlds differ in WHICH
// endpoints exist at all, not just in what they answer.
type rubricState struct {
	name  string
	build func(fx *adofixture.Transport)
	want  map[string]model.Status
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// Nine states reach every status this collector can emit. tags-signed,
// checksums and signatures make no API call and return not-checkable on every
// repo unconditionally — Azure DevOps's GitAnnotatedTag carries no signature
// field at all, and the platform has no release-asset concept for the other two
// to inspect — so no fixture can move them; the guard's
// documented-but-unreachable direction is what pins their single-status rubrics.
//
// The conflation risk between the two EVIDENCE checks is specific and worth
// naming, because the code makes a deliberate choice that a careless matrix
// would never exercise: workflow reads the signature-matched pipeline set, while
// commit-linkage passes definitionIDs=nil to FetchBuilds on purpose — it asks
// whether ANY build ran on the release's commit, not whether a provenance build
// did. Set up a cosign pipeline whose build is also the release build and both
// checks move together forever. So:
//
//   - state 3 has NO provenance tooling whatsoever and a perfectly traceable
//     release: workflow fails, commit-linkage passes. If commit-linkage ever
//     started filtering by the matched pipelines' definition IDs, this is the
//     state that would catch it.
//   - state 2 is the reverse, with the tool configured and the build sitting on
//     a different commit.
//   - state 5 splits them a third way, on evidence quality rather than presence:
//     an uninspectable pipeline makes workflow not-checkable while commit-linkage
//     evaluates normally, since a pipeline this collector could not read says
//     nothing about whether a build ran on the release commit.
//
// Verified by mutation rather than assumed — see the commit message for which
// states caught which.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	releaseDate := time.Now().UTC().AddDate(0, 0, -30)

	repos := func(fx *adofixture.Transport) {
		registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	}
	// cosignPipeline is a real run-pattern match against the embedded
	// signature registry; slsaNamedPipeline matches on the pipeline NAME only,
	// which is the weakest tier and must never alone justify a pass.
	cosignPipeline := func(fx *adofixture.Transport) {
		registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
		registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
		registerYAML(fx, testRepoID, "steps:\n  - script: cosign sign-blob --bundle=out.bundle artifact.bin\n")
	}
	slsaNamedPipeline := func(fx *adofixture.Transport) {
		registerPipelines(fx, map[string]any{"id": 1, "name": "CI"})
		registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
		registerYAML(fx, testRepoID, "name: My SLSA Provenance Pipeline\nsteps:\n  - script: echo hello\n")
	}
	// uninspectablePipeline resolves to a YAML pipeline whose yamlFilename is
	// missing, which is what MatchPipelines records as a SkippedPipeline.
	uninspectablePipeline := func(fx *adofixture.Transport) {
		registerPipelines(fx, map[string]any{"id": 1, "name": "unresolved-pipeline"})
		registerDefinition(fx, 1, map[string]any{"type": 2, "yamlFilename": ""}, testRepoID, "refs/heads/main")
	}
	oneRelease := func(fx *adofixture.Transport) {
		registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
		registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	}
	build := func(sha string) map[string]any {
		return map[string]any{
			"sourceVersion": sha, "sourceBranch": "refs/heads/main",
			"result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339),
		}
	}
	denied := adofixture.Response{Status: http.StatusForbidden, Body: map[string]any{"message": "denied"}}

	alwaysNC := func(m map[string]model.Status) map[string]model.Status {
		for _, id := range alwaysNotCheckableIDs {
			m[id] = model.StatusNotCheckable
		}
		return m
	}

	states := []rubricState{
		{
			name: "a cosign pipeline and a release traceable to a build on its commit",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				cosignPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1"))
			},
			want: alwaysNC(map[string]model.Status{
				idWorkflow:      model.StatusVerifiedPass,
				idCommitLinkage: model.StatusVerifiedPass,
			}),
		},
		{
			// The tool is configured and the release is untraceable: a build
			// exists, it just is not on the release's commit.
			name: "a cosign pipeline whose only build is on a different commit",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				cosignPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha-unrelated"))
			},
			want: alwaysNC(map[string]model.Status{
				idWorkflow:      model.StatusVerifiedPass,
				idCommitLinkage: model.StatusVerifiedFail,
			}),
		},
		{
			// The state that pins commit-linkage's definitionIDs=nil choice:
			// there is no provenance tooling anywhere, and the release is still
			// fully traceable because SOME build ran on its commit. A
			// commit-linkage that filtered by the matched pipelines' definition
			// IDs would have nothing to search and would fail here.
			name: "no provenance tooling at all, but a build on the release commit",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				registerPipelines(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1"))
			},
			want: alwaysNC(map[string]model.Status{
				idWorkflow:      model.StatusVerifiedFail,
				idCommitLinkage: model.StatusVerifiedPass,
			}),
		},
		{
			// The confidence cap: a pipeline NAMED after a provenance tool with
			// no invocation in it. commit-linkage is unaffected — it never
			// consults the match at all.
			name: "a pipeline whose NAME suggests provenance, with a traceable release",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				slsaNamedPipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1"))
			},
			want: alwaysNC(map[string]model.Status{
				idWorkflow:      model.StatusPartial,
				idCommitLinkage: model.StatusVerifiedPass,
			}),
		},
		{
			// The third split, on evidence quality rather than presence: the
			// repo's only pipeline could not be read, so workflow must not
			// assert an absence — while commit-linkage is untouched, since an
			// unreadable pipeline says nothing about whether a build ran on the
			// release commit.
			name: "the repo's only pipeline cannot be inspected, and the release is traceable",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				uninspectablePipeline(fx)
				oneRelease(fx)
				registerBuilds(fx, build("sha1"))
			},
			want: alwaysNC(map[string]model.Status{
				idWorkflow:      model.StatusNotCheckable,
				idCommitLinkage: model.StatusVerifiedPass,
			}),
		},
		{
			// commit-linkage's only route to partial: every release that could
			// be evaluated is traceable, and one undateable tag matching the
			// pattern still caps the result.
			name: "every evaluated release is traceable but one release tag cannot be dated",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				cosignPipeline(fx)
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
				registerBuilds(fx, build("sha1"))
			},
			want: alwaysNC(map[string]model.Status{
				idWorkflow:      model.StatusVerifiedPass,
				idCommitLinkage: model.StatusPartial,
			}),
		},
		{
			// Nothing to evaluate rather than an evidence gap: no tag matches
			// the release pattern, so no build search is even attempted.
			name: "a configured cosign pipeline with no release tags at all",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				cosignPipeline(fx)
				fx.Set("GET", azuredevops.HostCore, refsPath(testRepoID), adofixture.Response{
					Status: http.StatusOK,
					Body:   map[string]any{"count": 0, "value": []map[string]any{}},
				})
			},
			want: alwaysNC(map[string]model.Status{
				idWorkflow:      model.StatusVerifiedPass,
				idCommitLinkage: model.StatusNotCheckable,
			}),
		},
		{
			// commit-linkage's other not-checkable route, and a second state
			// where it goes not-checkable alone: releases exist and it is the
			// build history that cannot be read.
			name: "the build history is denied while the release tags resolve",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				cosignPipeline(fx)
				oneRelease(fx)
				fx.Set("GET", azuredevops.HostCore, buildsPath(), denied)
			},
			want: alwaysNC(map[string]model.Status{
				idWorkflow:      model.StatusVerifiedPass,
				idCommitLinkage: model.StatusNotCheckable,
			}),
		},
		{
			// The shared upstream gate — the one failure that legitimately
			// moves both evidence checks together, and the only lockstep state
			// in the matrix. It earns its place by being the contrast: states
			// 5, 7 and 8 show each check going not-checkable ALONE, so this one
			// is not mistaken for the general shape.
			name: "the project's pipeline listing is denied",
			build: func(fx *adofixture.Transport) {
				repos(fx)
				fx.Set("GET", azuredevops.HostCore, pipelinesPath(), denied)
				oneRelease(fx)
				registerBuilds(fx, build("sha1"))
			},
			want: alwaysNC(map[string]model.Status{
				idWorkflow:      model.StatusNotCheckable,
				idCommitLinkage: model.StatusNotCheckable,
			}),
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

// TestCommitLinkageSearchesEveryBuildNotOnlyProvenanceBuilds pins collectRepo's
// deliberate definitionIDs=nil: commit-linkage asks whether ANY build ran on
// the release's commit, not whether a provenance-tool build did.
//
// This is a separate test rather than another state in
// TestRubricsMatchObservedBehaviour because the matrix structurally cannot make
// the claim. `definitions` is a QUERY parameter on Builds - List and
// adofixture matches on "METHOD host path" alone, so a fixture returns the same
// builds whether the parameter is present or not — found by mutation: rewriting
// collectRepo to pass the matched pipelines' definition IDs changed no status in
// any of the nine states. The request itself is the only place the claim is
// observable.
//
// A cosign pipeline IS configured here on purpose, unlike
// TestCollect_CommitLinkageBuildsFetch_MinTimeAnchoredToOldestReleaseMinusGraceWindow
// above, which registers none. With no matched pipeline this test would prove
// nothing: FetchBuilds treats an empty definition list as "unfiltered" anyway,
// so `definitions` would be absent for the wrong reason.
func TestCommitLinkageSearchesEveryBuildNotOnlyProvenanceBuilds(t *testing.T) {
	fx := adofixture.New()
	registerRepositories(fx, map[string]any{"id": testRepoID, "name": testRepo, "defaultBranch": "refs/heads/main"})
	registerPipelines(fx, map[string]any{"id": 7, "name": "CI"})
	registerDefinition(fx, 7, map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"}, testRepoID, "refs/heads/main")
	registerYAML(fx, testRepoID, "steps:\n  - script: cosign sign-blob --bundle=out.bundle artifact.bin\n")
	releaseDate := time.Now().UTC().AddDate(0, 0, -30)
	registerLightweightTag(fx, testRepoID, "v1.0.0", "sha1")
	registerCommitDate(fx, testRepoID, "sha1", releaseDate)
	registerBuilds(fx, map[string]any{
		"sourceVersion": "sha1", "sourceBranch": "refs/heads/main",
		"result": "succeeded", "queueTime": releaseDate.Format(time.RFC3339),
	})

	capture := &queryCapturingTransport{base: fx, path: buildsPath()}
	c := New(azuredevops.NewClientForTest(testOrg, "ado-test-pat", capture))
	if _, err := c.Collect(context.Background(), defaultScope()); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if capture.lastQuery == nil {
		t.Fatal("no Builds - List request was made at all; this assertion would prove nothing")
	}
	if got := capture.lastQuery.Get("definitions"); got != "" {
		t.Errorf("Builds - List was filtered to definitions=%q; commit-linkage must search every build on the "+
			"release commit, not only builds of the provenance pipeline", got)
	}
}
