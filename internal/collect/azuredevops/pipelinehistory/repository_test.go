package pipelinehistory

import (
	"context"
	"net/http"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/adofixture"
)

func repositoriesPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/git/repositories"
}

func TestFetchRepositories_DecodesFields(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, repositoriesPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 2,
			"value": []map[string]any{
				{"id": "repo-1-id", "name": "widgets", "defaultBranch": "refs/heads/main"},
				{"id": "repo-2-id", "name": "gadgets"},
			},
		},
	})
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)

	got, err := FetchRepositories(context.Background(), client, testProject)
	if err != nil {
		t.Fatalf("FetchRepositories: %v", err)
	}
	want := []RepositoryInfo{
		{ID: "repo-1-id", Name: "widgets", DefaultBranch: "refs/heads/main"},
		{ID: "repo-2-id", Name: "gadgets", DefaultBranch: ""},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("FetchRepositories = %+v, want %+v", got, want)
	}
}

func TestFindRepository_CaseInsensitive(t *testing.T) {
	repos := []RepositoryInfo{
		{ID: "repo-1-id", Name: "Widgets", DefaultBranch: "refs/heads/main"},
	}

	got, found := FindRepository(repos, "widgets")
	if !found {
		t.Fatal("FindRepository(\"widgets\") = not found, want found (case-insensitive match against \"Widgets\")")
	}
	if got.ID != "repo-1-id" {
		t.Errorf("FindRepository(\"widgets\").ID = %q, want %q", got.ID, "repo-1-id")
	}

	if _, found := FindRepository(repos, "nonexistent"); found {
		t.Error("FindRepository(\"nonexistent\") = found, want not found")
	}
}
