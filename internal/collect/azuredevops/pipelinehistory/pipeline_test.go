package pipelinehistory

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/adofixture"
	"gitlab.com/sioakeim/attestward/internal/mapping"
)

func pipelinesPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/pipelines"
}

func definitionPath(id int) string {
	return "/" + testOrg + "/" + testProject + "/_apis/build/definitions/" + strconv.Itoa(id)
}

func itemsPath(repositoryID string) string {
	return "/" + testOrg + "/" + testProject + "/_apis/git/repositories/" + repositoryID + "/items"
}

func TestListPipelines_DecodesFields(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, pipelinesPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 2,
			"value": []map[string]any{
				{"id": 1, "name": "CI"},
				{"id": 2, "name": "Release"},
			},
		},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

	got, err := ListPipelines(context.Background(), client, testProject)
	if err != nil {
		t.Fatalf("ListPipelines: %v", err)
	}
	want := []PipelineRef{{ID: 1, Name: "CI"}, {ID: 2, Name: "Release"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("ListPipelines = %+v, want %+v", got, want)
	}
}

// TestFetchBuildDefinition_YAMLPathOutcomes is the acceptance criterion for
// the [fixture-verify] process.yamlFilename item: a YAML-type process
// (type 2) with a yamlFilename resolves; a classic/designer process
// (type 1) is NotYAML (out of scope, not a gap); a YAML-type process
// missing yamlFilename entirely is Unknown (an evidence gap, not a silent
// skip) — the exact three-way degradation the issue asked for.
func TestFetchBuildDefinition_YAMLPathOutcomes(t *testing.T) {
	tests := []struct {
		name           string
		process        map[string]any
		wantStatus     YAMLPathStatus
		wantPath       string
		wantReasonPart string
	}{
		{
			name:       "YAML process with yamlFilename resolves",
			process:    map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"},
			wantStatus: YAMLPathResolved,
			wantPath:   "azure-pipelines.yml",
		},
		{
			name:           "classic/designer process (type 1) is out of scope, not a gap",
			process:        map[string]any{"type": 1},
			wantStatus:     YAMLPathNotYAML,
			wantReasonPart: "not 2",
		},
		{
			name:           "YAML-type process missing yamlFilename is an evidence gap",
			process:        map[string]any{"type": 2},
			wantStatus:     YAMLPathUnknown,
			wantReasonPart: "no yamlFilename field",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			definitionID := 100 + i
			fx := adofixture.New().Set("GET", azuredevops.HostCore, definitionPath(definitionID), adofixture.Response{
				Status: http.StatusOK,
				Body: map[string]any{
					"id":      definitionID,
					"name":    "def",
					"process": tt.process,
					"repository": map[string]any{
						"id":            "repo-id",
						"defaultBranch": "refs/heads/main",
					},
				},
			})
			client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

			info, err := FetchBuildDefinition(context.Background(), client, testProject, definitionID)
			if err != nil {
				t.Fatalf("FetchBuildDefinition: %v", err)
			}
			if info.YAMLPath.Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q (reason: %s)", info.YAMLPath.Status, tt.wantStatus, info.YAMLPath.Reason)
			}
			if tt.wantPath != "" && info.YAMLPath.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", info.YAMLPath.Path, tt.wantPath)
			}
			if tt.wantReasonPart != "" && !strings.Contains(info.YAMLPath.Reason, tt.wantReasonPart) {
				t.Errorf("Reason = %q, want it to contain %q", info.YAMLPath.Reason, tt.wantReasonPart)
			}
			if info.RepositoryID != "repo-id" || info.DefaultBranch != "refs/heads/main" {
				t.Errorf("RepositoryID/DefaultBranch = %q/%q, want repo-id/refs/heads/main", info.RepositoryID, info.DefaultBranch)
			}
		})
	}
}

func TestFetchYAMLContent_DecodesContentField(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, itemsPath("repo-id"), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"content": "steps:\n  - task: SnykSecurityScan@1\n"},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

	got, err := FetchYAMLContent(context.Background(), client, testProject, "repo-id", "azure-pipelines.yml", "refs/heads/main")
	if err != nil {
		t.Fatalf("FetchYAMLContent: %v", err)
	}
	if got != "steps:\n  - task: SnykSecurityScan@1\n" {
		t.Errorf("content = %q, want the fixture's raw YAML text", got)
	}
}

// TestFetchYAMLContent_SendsFormatAndVersionDescriptorParams pins two
// items-Get query parameters this project depends on: $format=json (Items
// - Get is content-negotiated and would otherwise return the raw file
// stream, not JSON, against a real service — adofixture always replies
// JSON regardless, so only an explicit query assertion catches a
// regression here) and versionDescriptor.version/versionType=branch,
// pinning the YAML fetch to the same branch a caller's builds are linked
// against, with the refs/heads/ prefix stripped.
func TestFetchYAMLContent_SendsFormatAndVersionDescriptorParams(t *testing.T) {
	capture := &queryCapturingTransport{base: adofixture.New().Set("GET", azuredevops.HostCore, itemsPath("repo-id"), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"content": "steps: []\n"},
	})}
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", capture)

	if _, err := FetchYAMLContent(context.Background(), client, testProject, "repo-id", "azure-pipelines.yml", "refs/heads/main"); err != nil {
		t.Fatalf("FetchYAMLContent: %v", err)
	}

	if got := capture.lastQuery.Get("$format"); got != "json" {
		t.Errorf("$format = %q, want json", got)
	}
	if got := capture.lastQuery.Get("versionDescriptor.version"); got != "main" {
		t.Errorf("versionDescriptor.version = %q, want %q (refs/heads/ prefix stripped)", got, "main")
	}
	if got := capture.lastQuery.Get("versionDescriptor.versionType"); got != "branch" {
		t.Errorf("versionDescriptor.versionType = %q, want branch", got)
	}
}

// syntheticRegistry builds a minimal ScannerSignatureRegistry for
// MatchPipelines' own tests — not the real mappings/scanner-signatures.yaml
// (whose ado_tasks entries are #149's own follow-on stories' concern, not
// this package's), mirroring how scannermatch_test.go/pipelinematch_test.go
// build synthetic registries for matcher-behavior tests.
func syntheticRegistry() *mapping.ScannerSignatureRegistry {
	return &mapping.ScannerSignatureRegistry{
		Signatures: []mapping.ScannerSignature{
			{
				ID:       "snyk-like",
				Name:     "Snyk-like",
				Category: mapping.CategorySCA,
				Detect:   mapping.ScannerSignatureDetect{ADOTasks: []mapping.ADOTaskMatcher{{Task: "SnykSecurityScan"}}},
			},
		},
	}
}

// TestMatchPipelines_EndToEnd exercises the full discovery pipeline for
// four pipelines in one project: one YAML pipeline that matches, one
// classic/designer pipeline (silently out of scope, not in skipped), one
// YAML pipeline whose YAML contains an unresolved template: reference
// (surfaced in skipped, matching how skipped_workflows surfaces content
// this tool couldn't fully inspect), and one whose build-definition fetch
// itself fails (also surfaced in skipped).
func TestMatchPipelines_EndToEnd(t *testing.T) {
	fx := adofixture.New()

	// Pipeline 1: a real YAML pipeline that matches snyk-like.
	fx.Set("GET", azuredevops.HostCore, definitionPath(1), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"id": 1, "name": "matching",
			"process":    map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"},
			"repository": map[string]any{"id": "repo-1", "defaultBranch": "refs/heads/main"},
		},
	})
	fx.Set("GET", azuredevops.HostCore, itemsPath("repo-1"), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"content": "steps:\n  - task: SnykSecurityScan@1\n"},
	})

	// Pipeline 2: classic/designer — out of scope, not a skip.
	fx.Set("GET", azuredevops.HostCore, definitionPath(2), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"id": 2, "name": "classic",
			"process":    map[string]any{"type": 1},
			"repository": map[string]any{"id": "repo-2", "defaultBranch": "refs/heads/main"},
		},
	})

	// Pipeline 3: a YAML pipeline whose content is a template ref MatchPipeline can't resolve.
	fx.Set("GET", azuredevops.HostCore, definitionPath(3), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"id": 3, "name": "templated",
			"process":    map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"},
			"repository": map[string]any{"id": "repo-3", "defaultBranch": "refs/heads/main"},
		},
	})
	fx.Set("GET", azuredevops.HostCore, itemsPath("repo-3"), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"content": "extends:\n  template: v1/pipeline.yml@templates\n"},
	})

	// Pipeline 4: build-definition fetch itself fails.
	fx.Set("GET", azuredevops.HostCore, definitionPath(4), adofixture.Response{
		Status: http.StatusInternalServerError,
		Body:   map[string]any{"message": "TF400xxx: something went wrong"},
	})

	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)
	registry := syntheticRegistry()
	pipelines := []PipelineRef{{ID: 1, Name: "matching"}, {ID: 2, Name: "classic"}, {ID: 3, Name: "templated"}, {ID: 4, Name: "broken"}}

	matched, skipped := MatchPipelines(context.Background(), client, registry, testProject, pipelines, mapping.CategorySCA)

	if len(matched) != 1 || matched[0].DefinitionID != 1 || matched[0].Name != "matching" || len(matched[0].Matches) != 1 || matched[0].Matches[0].SignatureID != "snyk-like" {
		t.Errorf("matched = %+v, want exactly pipeline 1 (name %q) matching snyk-like", matched, "matching")
	}
	// RepositoryID lets a per-repo caller (C05/C06) filter this
	// project-wide match list down to one repo — populated straight from
	// the same FetchBuildDefinition response that resolved everything
	// else here, no extra call.
	if matched[0].RepositoryID != "repo-1" {
		t.Errorf("matched[0].RepositoryID = %q, want %q (from the build definition's own repository.id)", matched[0].RepositoryID, "repo-1")
	}

	skippedIDs := map[int]bool{}
	skippedNames := map[int]string{}
	skippedRepoIDs := map[int]string{}
	for _, s := range skipped {
		skippedIDs[s.DefinitionID] = true
		skippedNames[s.DefinitionID] = s.Name
		skippedRepoIDs[s.DefinitionID] = s.RepositoryID
	}
	if skippedIDs[2] {
		t.Error("pipeline 2 (classic/designer) appeared in skipped — it should be silently out of scope, not a gap")
	}
	if !skippedIDs[3] {
		t.Error("pipeline 3 (unresolved template ref) did not appear in skipped")
	}
	if !skippedIDs[4] {
		t.Error("pipeline 4 (build-definition fetch failure) did not appear in skipped")
	}
	if len(skipped) != 2 {
		t.Errorf("len(skipped) = %d, want 2 (pipelines 3 and 4 only)", len(skipped))
	}
	if skippedNames[3] != "templated" {
		t.Errorf("skipped pipeline 3's Name = %q, want %q", skippedNames[3], "templated")
	}
	if skippedNames[4] != "broken" {
		t.Errorf("skipped pipeline 4's Name = %q, want %q (PipelineRef's own name, since the build-definition fetch that would have known its own Name is exactly what failed)", skippedNames[4], "broken")
	}
	// Pipeline 3's build definition fetch succeeded before its later
	// steps failed, so its RepositoryID is known; pipeline 4's own
	// build-definition fetch is exactly what failed, so there is no
	// response to have read a repository field from — RepositoryID stays
	// empty, honestly, rather than guessing.
	if skippedRepoIDs[3] != "repo-3" {
		t.Errorf("skipped pipeline 3's RepositoryID = %q, want %q", skippedRepoIDs[3], "repo-3")
	}
	if skippedRepoIDs[4] != "" {
		t.Errorf("skipped pipeline 4's RepositoryID = %q, want empty (its own build-definition fetch failed, so no repository field was ever read)", skippedRepoIDs[4])
	}
}

// TestMatchPipelines_CategoryFiltering proves only matches in the
// requested category are kept — mirrors
// TestListWorkflowsAndMatchWorkflows_CategoryFiltering's intent for the
// GitHub twin.
func TestMatchPipelines_CategoryFiltering(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, definitionPath(1), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"id": 1, "name": "p",
			"process":    map[string]any{"type": 2, "yamlFilename": "azure-pipelines.yml"},
			"repository": map[string]any{"id": "repo-1", "defaultBranch": "refs/heads/main"},
		},
	})
	fx.Set("GET", azuredevops.HostCore, itemsPath("repo-1"), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"content": "steps:\n  - task: SnykSecurityScan@1\n"},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)
	registry := syntheticRegistry()

	matched, _ := MatchPipelines(context.Background(), client, registry, testProject, []PipelineRef{{ID: 1}}, mapping.CategorySAST)
	if len(matched) != 0 {
		t.Errorf("matched = %+v, want none (the only match is category sca, requested sast)", matched)
	}
}
