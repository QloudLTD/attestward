package actionssecurity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sioakim/ssdf/internal/mapping"
	"github.com/sioakim/ssdf/internal/model"
)

// loadFixture parses testdata/workflows/<name>.yaml into a workflowUnit,
// the same shape collectRepo builds from a live fetch — so these tests
// exercise the exact pure-function analyzer logic the real collector runs,
// just skipping the HTTP fetch (that's actionssecurity_test.go's job).
func loadFixture(t *testing.T, name string) workflowUnit {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "workflows", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	parsed, err := mapping.ParseWorkflowFile(raw)
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return workflowUnit{Label: name, Parsed: parsed, Raw: string(raw)}
}

const org, repo = "acme", "widgets"

func TestCheckPinned(t *testing.T) {
	tests := []struct {
		name string
		file string
		want model.Status
	}{
		{"third-party unpinned tag fails", "pinned_thirdparty_unpinned.yaml", model.StatusVerifiedFail},
		{"third-party pinned to SHA passes", "pinned_thirdparty_sha.yaml", model.StatusVerifiedPass},
		{"first-party actions/* tag caps at partial", "pinned_firstparty_tag.yaml", model.StatusPartial},
		{"no external refs at all passes vacuously", "pinned_none.yaml", model.StatusVerifiedPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := loadFixture(t, tt.file)
			got := checkPinned(org, repo, []workflowUnit{u}, nil, nil)
			if got.Status != tt.want {
				t.Errorf("status = %q, want %q; reason=%q", got.Status, tt.want, got.Reason)
			}
		})
	}
}

func TestCheckPinned_NoWorkflows_NotCheckable(t *testing.T) {
	got := checkPinned(org, repo, nil, nil, nil)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", got.Status)
	}
}

func TestCheckPinned_UnresolvedExternalWorkflowSurfacedAsFact(t *testing.T) {
	u := loadFixture(t, "pinned_none.yaml")
	unresolved := []unresolvedExternalWorkflow{{FromFile: "caller.yaml", Line: 3, Ref: "other/repo/.github/workflows/x.yml@v1"}}
	got := checkPinned(org, repo, []workflowUnit{u}, unresolved, nil)
	facts, ok := got.Facts["unresolved_external_workflows"].([]map[string]any)
	if !ok || len(facts) != 1 {
		t.Fatalf("unresolved_external_workflows facts = %#v, want one entry", got.Facts["unresolved_external_workflows"])
	}
}

func TestCheckTokenPermissions(t *testing.T) {
	tests := []struct {
		name string
		file string
		want model.Status
	}{
		{"missing everywhere fails", "permissions_missing.yaml", model.StatusVerifiedFail},
		{"explicit workflow-level passes", "permissions_explicit_workflow_level.yaml", model.StatusVerifiedPass},
		{"explicit write-all caps at partial", "permissions_write_all.yaml", model.StatusPartial},
		{"mixed jobs (one explicit, one missing) caps at partial", "permissions_mixed_jobs.yaml", model.StatusPartial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := loadFixture(t, tt.file)
			got := checkTokenPermissions(org, repo, []workflowUnit{u}, "", false, nil)
			if got.Status != tt.want {
				t.Errorf("status = %q, want %q; reason=%q", got.Status, tt.want, got.Reason)
			}
		})
	}
}

func TestCheckTokenPermissions_DefaultWorkflowPermissionSurfacedAsContextFact(t *testing.T) {
	u := loadFixture(t, "permissions_missing.yaml")
	got := checkTokenPermissions(org, repo, []workflowUnit{u}, "write", true, nil)
	if got.Facts["repo_default_workflow_permissions"] != "write" {
		t.Errorf("repo_default_workflow_permissions fact = %v, want %q", got.Facts["repo_default_workflow_permissions"], "write")
	}
	// The context fact must never change the verdict on its own — issue
	// #20's wording is "absence ... flagged; setting collected as context
	// fact", not "absence is fine if the default is read".
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("status = %q, want verified-fail regardless of the default-permission context fact", got.Status)
	}
}

func TestCheckPullRequestTarget(t *testing.T) {
	tests := []struct {
		name string
		file string
		want model.Status
	}{
		{"checkout of PR head fails", "prtarget_dangerous.yaml", model.StatusVerifiedFail},
		{"checkout via github.head_ref alias fails", "prtarget_dangerous_head_ref_alias.yaml", model.StatusVerifiedFail},
		{"pull_request_target with no checkout caps at partial", "prtarget_bare.yaml", model.StatusPartial},
		{"pull_request_target with base-ref checkout caps at partial", "prtarget_safe_base_checkout.yaml", model.StatusPartial},
		{"no pull_request_target trigger passes", "pinned_none.yaml", model.StatusVerifiedPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := loadFixture(t, tt.file)
			got := checkPullRequestTarget(org, repo, []workflowUnit{u}, nil)
			if got.Status != tt.want {
				t.Errorf("status = %q, want %q; reason=%q", got.Status, tt.want, got.Reason)
			}
		})
	}
}

func TestCheckOIDCvsSecrets(t *testing.T) {
	tests := []struct {
		name string
		file string
		want model.Status
	}{
		{"AWS OIDC passes", "deploy_aws_oidc.yaml", model.StatusVerifiedPass},
		{"AWS static credentials fail", "deploy_aws_static.yaml", model.StatusVerifiedFail},
		{"Azure OIDC passes", "deploy_azure_oidc.yaml", model.StatusVerifiedPass},
		{"Azure static credentials fail", "deploy_azure_static.yaml", model.StatusVerifiedFail},
		{"GCP OIDC passes", "deploy_gcp_oidc.yaml", model.StatusVerifiedPass},
		{"GCP static credentials fail", "deploy_gcp_static.yaml", model.StatusVerifiedFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := loadFixture(t, tt.file)
			got := checkOIDCvsSecrets(org, repo, []workflowUnit{u}, nil)
			if got.Status != tt.want {
				t.Errorf("status = %q, want %q; reason=%q", got.Status, tt.want, got.Reason)
			}
		})
	}
}

func TestCheckOIDCvsSecrets_NoDeployWorkflow_NotCheckable(t *testing.T) {
	u := loadFixture(t, "pinned_none.yaml")
	got := checkOIDCvsSecrets(org, repo, []workflowUnit{u}, nil)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", got.Status)
	}
}

func TestCheckSelfHosted(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		private bool
		want    model.Status
	}{
		{"self-hosted bare string on public repo caps at partial", "selfhosted_bare_string.yaml", false, model.StatusPartial},
		{"self-hosted label list on public repo caps at partial", "selfhosted_label_list.yaml", false, model.StatusPartial},
		{"self-hosted on private repo passes (public-fork vector doesn't apply)", "selfhosted_bare_string.yaml", true, model.StatusVerifiedPass},
		{"GitHub-hosted-only labels pass", "hosted_runner_only.yaml", false, model.StatusVerifiedPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := loadFixture(t, tt.file)
			got := checkSelfHosted(org, repo, []workflowUnit{u}, tt.private, nil)
			if got.Status != tt.want {
				t.Errorf("status = %q, want %q; reason=%q", got.Status, tt.want, got.Reason)
			}
		})
	}
}

func TestCheckSelfHosted_NoWorkflows_NotCheckable(t *testing.T) {
	got := checkSelfHosted(org, repo, nil, false, nil)
	if got.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", got.Status)
	}
}

// TestFindingsIncludeFileAndLine locks in issue #20's acceptance criterion
// "Findings include file+line facts" for at least one finding-producing
// check per kind of finding.
func TestFindingsIncludeFileAndLine(t *testing.T) {
	u := loadFixture(t, "pinned_thirdparty_unpinned.yaml")
	got := checkPinned(org, repo, []workflowUnit{u}, nil, nil)
	findings, ok := got.Facts["third_party_unpinned"].([]map[string]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("third_party_unpinned facts = %#v, want one entry", got.Facts["third_party_unpinned"])
	}
	if findings[0]["file"] != "pinned_thirdparty_unpinned.yaml" {
		t.Errorf("file = %v, want the fixture filename", findings[0]["file"])
	}
	line, ok := findings[0]["line"].(int)
	if !ok || line <= 0 {
		t.Errorf("line = %v, want a positive line number", findings[0]["line"])
	}
}

// TestLineNumbers_IndependentAcrossChecks guards against line-lookup state
// leaking between checks that share the same []workflowUnit slice — exactly
// how collectRepo calls all five check functions. Both checkPinned and
// checkPullRequestTarget search prtarget_dangerous.yaml for the identical
// "actions/checkout@v5" text; each must find its own correct line
// independently, not have the second search silently come up empty because
// the first one already "consumed" that occurrence.
func TestLineNumbers_IndependentAcrossChecks(t *testing.T) {
	units := []workflowUnit{loadFixture(t, "prtarget_dangerous.yaml")}

	pinned := checkPinned(org, repo, units, nil, nil)
	prTarget := checkPullRequestTarget(org, repo, units, nil)

	pinnedRefs, _ := pinned.Facts["first_party_unpinned"].([]map[string]any)
	if len(pinnedRefs) != 1 {
		t.Fatalf("checkPinned first_party_unpinned = %#v, want one entry", pinned.Facts["first_party_unpinned"])
	}
	if line, ok := pinnedRefs[0]["line"].(int); !ok || line <= 0 {
		t.Errorf("checkPinned line = %v, want a positive line number", pinnedRefs[0]["line"])
	}

	dangerous, _ := prTarget.Facts["dangerous"].([]map[string]any)
	if len(dangerous) != 1 {
		t.Fatalf("checkPullRequestTarget dangerous = %#v, want one entry", prTarget.Facts["dangerous"])
	}
	if line, ok := dangerous[0]["line"].(int); !ok || line <= 0 {
		t.Errorf("checkPullRequestTarget line = %v, want a positive line number — must not be consumed by checkPinned's earlier search of the same unit", dangerous[0]["line"])
	}
}
