package pipelinehistory

import (
	"context"
	"net/http"
	"testing"

	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/collect/azuredevops/adofixture"
)

func enablementPath(repositoryID string) string {
	return "/" + testOrg + "/" + testProject + "/_apis/management/repositories/" + repositoryID + "/enablement"
}

func TestFetchRepoEnablement_DecodesFields(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, enablementPath("repo-1"), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"projectId":    "proj-id",
			"repositoryId": "repo-1",
			"codeSecurityFeatures": map[string]any{
				"codeQLEnabled":                      true,
				"dependencyScanningInjectionEnabled": false,
				"codeSecurityEnabled":                true,
				"autofixEnabled":                     nil,
			},
			"secretProtectionFeatures": map[string]any{
				"secretProtectionEnabled": true,
				"blockPushes":             false,
			},
		},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

	got, err := FetchRepoEnablement(context.Background(), client, testProject, "repo-1")
	if err != nil {
		t.Fatalf("FetchRepoEnablement: %v", err)
	}
	if !got.CodeQLEnabled || got.DependencyScanningInjectionEnabled != false || !got.CodeSecurityEnabled {
		t.Errorf("codeSecurityFeatures fields = %+v, want CodeQLEnabled=true DependencyScanningInjectionEnabled=false CodeSecurityEnabled=true", got)
	}
	if got.SecretProtectionEnabled == nil || *got.SecretProtectionEnabled != true {
		t.Errorf("SecretProtectionEnabled = %v, want a non-nil pointer to true", got.SecretProtectionEnabled)
	}
	if got.BlockPushes == nil || *got.BlockPushes != false {
		t.Errorf("BlockPushes = %v, want a non-nil pointer to false", got.BlockPushes)
	}
}

// TestFetchRepoEnablement_NullFeaturesDecodeAsFalse proves a codeSecurityFeatures
// object whose fields are JSON null (Microsoft's own docs: "Null is never
// explicitly set") decodes as false, not a decode error — the same
// "not enabled" meaning either way.
func TestFetchRepoEnablement_NullFeaturesDecodeAsFalse(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, enablementPath("repo-1"), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"codeSecurityFeatures": map[string]any{
				"codeQLEnabled":                      nil,
				"dependencyScanningInjectionEnabled": nil,
				"codeSecurityEnabled":                nil,
			},
		},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

	got, err := FetchRepoEnablement(context.Background(), client, testProject, "repo-1")
	if err != nil {
		t.Fatalf("FetchRepoEnablement: %v", err)
	}
	if got.CodeQLEnabled || got.DependencyScanningInjectionEnabled || got.CodeSecurityEnabled {
		t.Errorf("FetchRepoEnablement = %+v, want all false for null features", got)
	}
}

// TestFetchRepoEnablement_NullSecretProtectionFieldsStayNilNotFalse proves
// the deliberate nil-vs-false distinction for secretProtectionFeatures
// (found in review, addendum to the original C05 work): unlike
// codeSecurityFeatures, a genuinely null blockPushes/secretProtectionEnabled
// must decode as a nil *bool, not silently collapse to false the way the
// codeSecurityFeatures trio does — C04's own secrets checks need to tell
// "confirmed disabled" apart from "this property wasn't returned."
func TestFetchRepoEnablement_NullSecretProtectionFieldsStayNilNotFalse(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, enablementPath("repo-1"), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"secretProtectionFeatures": map[string]any{
				"secretProtectionEnabled": nil,
				"blockPushes":             nil,
			},
		},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

	got, err := FetchRepoEnablement(context.Background(), client, testProject, "repo-1")
	if err != nil {
		t.Fatalf("FetchRepoEnablement: %v", err)
	}
	if got.SecretProtectionEnabled != nil {
		t.Errorf("SecretProtectionEnabled = %v, want nil (not a pointer to false)", got.SecretProtectionEnabled)
	}
	if got.BlockPushes != nil {
		t.Errorf("BlockPushes = %v, want nil (not a pointer to false)", got.BlockPushes)
	}
}

func TestFetchRepoEnablement_ErrorPropagates(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, enablementPath("repo-1"), adofixture.Response{
		Status: http.StatusNotFound,
		Body:   map[string]any{"message": "not licensed"},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

	_, err := FetchRepoEnablement(context.Background(), client, testProject, "repo-1")
	if err == nil {
		t.Fatal("FetchRepoEnablement: want an error for a 404 response")
	}
}

// TestFetchRepoEnablement_SendsIncludeAllProperties is the regression test
// for the addendum found in review: without includeAllProperties=true,
// Microsoft's own reference says blockPushes reads null regardless of its
// real state — this collector must always send it, unconditionally, not
// just when a caller happens to need secretProtectionFeatures.
func TestFetchRepoEnablement_SendsIncludeAllProperties(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostAdvSec, enablementPath("repo-1"), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{},
	})
	capture := &queryCapturingTransport{base: fx}
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", capture)

	if _, err := FetchRepoEnablement(context.Background(), client, testProject, "repo-1"); err != nil {
		t.Fatalf("FetchRepoEnablement: %v", err)
	}
	if capture.lastQuery == nil {
		t.Fatal("no request captured")
	}
	if got := capture.lastQuery.Get("includeAllProperties"); got != "true" {
		t.Errorf("includeAllProperties = %q, want \"true\"", got)
	}
	if got := capture.lastQuery.Get("api-version"); got != "7.2-preview.3" {
		t.Errorf("api-version = %q, want 7.2-preview.3", got)
	}
}
