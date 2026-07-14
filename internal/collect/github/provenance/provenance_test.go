package provenance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
)

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func newCollectorForServer(t *testing.T, server *httptest.Server) *Collector {
	t.Helper()
	c := New("ghp_test-token")
	c.newClientForTest = func(token string) *ghcollect.Client {
		client := ghcollect.NewClient(token)
		baseURL, err := url.Parse(server.URL + "/")
		if err != nil {
			t.Errorf("parse test server URL: %v", err)
			return client
		}
		client.REST.BaseURL = baseURL
		return client
	}
	return c
}

func byID(results []model.CheckResult) map[string]model.CheckResult {
	m := map[string]model.CheckResult{}
	for _, r := range results {
		m[r.CheckID] = r
	}
	return m
}

const cosignWorkflowYAML = `name: Sign release
on:
  push:
    tags: ["v*"]
jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: sigstore/cosign-installer@v3
      - run: cosign sign-blob --bundle=checksums.txt.bundle --yes checksums.txt
`

func registerRepo(t *testing.T, mux *http.ServeMux, org, repo, defaultBranch string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"default_branch": defaultBranch})
	})
}

func registerNoWorkflows(t *testing.T, mux *http.ServeMux, org, repo string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": 0, "workflows": []any{}})
	})
}

func registerCosignWorkflow(t *testing.T, mux *http.ServeMux, org, repo string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "Sign release", "path": ".github/workflows/sign.yml", "state": "active"},
			},
		})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/workflows/sign.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"content": cosignWorkflowYAML, "sha": "content-sha"})
	})
}

func registerNoReleases(t *testing.T, mux *http.ServeMux, org, repo string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []any{})
	})
}

type releaseAssetFixture struct {
	Name   string
	Digest string
}

func registerRelease(t *testing.T, mux *http.ServeMux, org, repo, tag string, publishedAt time.Time, assets []releaseAssetFixture) {
	t.Helper()
	assetEntries := make([]map[string]any, 0, len(assets))
	for _, a := range assets {
		assetEntries = append(assetEntries, map[string]any{"name": a.Name, "digest": a.Digest})
	}
	mux.HandleFunc("/repos/"+org+"/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"tag_name": tag, "target_commitish": "main", "published_at": publishedAt.Format(time.RFC3339), "assets": assetEntries},
		})
	})
}

func registerLightweightTag(t *testing.T, mux *http.ServeMux, org, repo, tag, commitSHA string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/git/ref/tags/"+tag, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/" + tag,
			"object": map[string]any{"type": "commit", "sha": commitSHA},
		})
	})
}

func registerAnnotatedTag(t *testing.T, mux *http.ServeMux, org, repo, tag, tagObjSHA, commitSHA string, verified bool, reason string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/git/ref/tags/"+tag, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"ref":    "refs/tags/" + tag,
			"object": map[string]any{"type": "tag", "sha": tagObjSHA},
		})
	})
	sig := ""
	if verified || reason != "unsigned" {
		sig = "-----BEGIN SIGNATURE-----..."
	}
	mux.HandleFunc("/repos/"+org+"/"+repo+"/git/tags/"+tagObjSHA, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"object": map[string]any{"type": "commit", "sha": commitSHA},
			"verification": map[string]any{
				"verified":  verified,
				"reason":    reason,
				"signature": sig,
			},
		})
	})
}

func registerNoAttestations(t *testing.T, mux *http.ServeMux, org, repo string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/attestations/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"attestations": []any{}})
	})
}

func registerAttestationFor(t *testing.T, mux *http.ServeMux, org, repo, digest string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/attestations/"+digest, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"attestations": []map[string]any{{"repository_id": 1}},
		})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/attestations/", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{"attestations": []any{}})
	})
}

func registerWorkflowRunsForCommit(t *testing.T, mux *http.ServeMux, org, repo string, runsBySHA map[string][]map[string]any) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		sha := r.URL.Query().Get("head_sha")
		runs := runsBySHA[sha]
		writeJSON(t, w, http.StatusOK, map[string]any{"total_count": len(runs), "workflow_runs": runs})
	})
}

func TestCollect_SignedTagChecksumsSignaturesWorkflowLinkage_AllChecksPass(t *testing.T) {
	org, repo, branch, tag := "attestor-demo", "good-repo", "main", "v1.0.0"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerCosignWorkflow(t, mux, org, repo)
	publishedAt := time.Now().UTC().AddDate(0, 0, -1)
	registerRelease(t, mux, org, repo, tag, publishedAt, []releaseAssetFixture{
		{Name: "myapp_linux_amd64.tar.gz", Digest: "sha256:aaa"},
		{Name: "checksums.txt", Digest: "sha256:bbb"},
		{Name: "checksums.txt.bundle", Digest: "sha256:ccc"},
	})
	registerAnnotatedTag(t, mux, org, repo, tag, "tag-obj-sha", "commit-sha-1", true, "valid")
	registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{
		"commit-sha-1": {{"id": 1, "head_sha": "commit-sha-1", "conclusion": "success"}},
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C07.release.tags-signed"].Status; got != model.StatusVerifiedPass {
		t.Errorf("tags-signed = %q, want verified-pass; reason=%q", got, m["C07.release.tags-signed"].Reason)
	}
	if got := m["C07.release.checksums"].Status; got != model.StatusVerifiedPass {
		t.Errorf("checksums = %q, want verified-pass; reason=%q", got, m["C07.release.checksums"].Reason)
	}
	if got := m["C07.release.signatures"].Status; got != model.StatusVerifiedPass {
		t.Errorf("signatures = %q, want verified-pass; reason=%q", got, m["C07.release.signatures"].Reason)
	}
	if got := m["C07.provenance.workflow"].Status; got != model.StatusVerifiedPass {
		t.Errorf("provenance.workflow = %q, want verified-pass; reason=%q", got, m["C07.provenance.workflow"].Reason)
	}
	if got := m["C07.provenance.commit-linkage"].Status; got != model.StatusVerifiedPass {
		t.Errorf("commit-linkage = %q, want verified-pass; reason=%q", got, m["C07.provenance.commit-linkage"].Reason)
	}
}

func TestCollect_LightweightTag_TagsSignedFails(t *testing.T) {
	org, repo, branch, tag := "attestor-demo", "lightweight-repo", "main", "v1.0.0"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerRelease(t, mux, org, repo, tag, time.Now().UTC().AddDate(0, 0, -1), nil)
	registerLightweightTag(t, mux, org, repo, tag, "commit-sha-1")
	registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C07.release.tags-signed"].Status; got != model.StatusVerifiedFail {
		t.Errorf("tags-signed = %q, want verified-fail; reason=%q", got, m["C07.release.tags-signed"].Reason)
	}
}

// TestCollect_UnresolvableTagAmongOthers_CapsAtPartialNotDropped covers a
// repo with two releases in the lookback window: one whose tag resolves
// cleanly (signed and verified), and one whose tag ref lookup 404s (e.g. a
// deleted tag). The unresolvable release must still get its own row in
// per_release (not silently vanish, the exact false-verified-pass shape
// that bit C05/C06 before their own dropped-tag fixes), and the overall
// status for both tags-signed and commit-linkage (which both depend on
// the same tag resolution) must cap at partial — never verified-pass
// (that would overstate confidence about the unresolvable release) and
// never verified-fail (the resolvable release genuinely passed; an
// unknown isn't the same as a confirmed gap).
func TestCollect_UnresolvableTagAmongOthers_CapsAtPartialNotDropped(t *testing.T) {
	org, repo, branch := "attestor-demo", "mixed-resolution-repo", "main"
	goodTag, badTag := "v1.0.0", "v0.9.0"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	mux.HandleFunc("/repos/"+org+"/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"tag_name": goodTag, "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339), "assets": []any{}},
			{"tag_name": badTag, "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -2).Format(time.RFC3339), "assets": []any{}},
		})
	})
	registerAnnotatedTag(t, mux, org, repo, goodTag, "tag-obj-sha", "commit-sha-good", true, "valid")
	mux.HandleFunc("/repos/"+org+"/"+repo+"/git/ref/tags/"+badTag, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{
		"commit-sha-good": {{"id": 1, "head_sha": "commit-sha-good", "conclusion": "success"}},
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	for _, id := range []string{"C07.release.tags-signed", "C07.provenance.commit-linkage"} {
		r := m[id]
		if r.Status != model.StatusPartial {
			t.Errorf("%s = %q, want partial; reason=%q", id, r.Status, r.Reason)
		}
		table, ok := r.Facts["per_release"].([]map[string]any)
		if !ok || len(table) != 2 {
			t.Fatalf("%s per_release = %v, want 2 entries (the unresolvable release must not be silently dropped)", id, r.Facts["per_release"])
		}
		tags := map[string]bool{}
		for _, row := range table {
			tags[row["tag"].(string)] = true
		}
		if !tags[goodTag] || !tags[badTag] {
			t.Errorf("%s per_release tags = %v, want both %q and %q present", id, tags, goodTag, badTag)
		}
	}
}

func TestCollect_UnverifiedAnnotatedTag_TagsSignedFails(t *testing.T) {
	org, repo, branch, tag := "attestor-demo", "unverified-repo", "main", "v1.0.0"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerRelease(t, mux, org, repo, tag, time.Now().UTC().AddDate(0, 0, -1), nil)
	registerAnnotatedTag(t, mux, org, repo, tag, "tag-obj-sha", "commit-sha-1", false, "unsigned")
	registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C07.release.tags-signed"].Status; got != model.StatusVerifiedFail {
		t.Errorf("tags-signed = %q, want verified-fail; reason=%q", got, m["C07.release.tags-signed"].Reason)
	}
	signed, _ := m["C07.release.tags-signed"].Facts["per_release"].([]map[string]any)
	if len(signed) != 1 || signed[0]["signed"] != false {
		t.Errorf("per_release facts = %v, want signed=false", m["C07.release.tags-signed"].Facts["per_release"])
	}
}

func TestCollect_NoChecksumAsset_ChecksumsFails(t *testing.T) {
	org, repo, branch, tag := "attestor-demo", "no-checksum-repo", "main", "v1.0.0"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerRelease(t, mux, org, repo, tag, time.Now().UTC().AddDate(0, 0, -1), []releaseAssetFixture{
		{Name: "myapp_linux_amd64.tar.gz", Digest: "sha256:aaa"},
	})
	registerLightweightTag(t, mux, org, repo, tag, "commit-sha-1")
	registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C07.release.checksums"].Status; got != model.StatusVerifiedFail {
		t.Errorf("checksums = %q, want verified-fail; reason=%q", got, m["C07.release.checksums"].Reason)
	}
}

func TestCollect_NoSignatureAssetButAttestationFound_SignaturesPasses(t *testing.T) {
	org, repo, branch, tag := "attestor-demo", "attested-repo", "main", "v1.0.0"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerRelease(t, mux, org, repo, tag, time.Now().UTC().AddDate(0, 0, -1), []releaseAssetFixture{
		{Name: "myapp_linux_amd64.tar.gz", Digest: "sha256:aaa"},
	})
	registerLightweightTag(t, mux, org, repo, tag, "commit-sha-1")
	registerAttestationFor(t, mux, org, repo, "sha256:aaa")
	registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C07.release.signatures"].Status; got != model.StatusVerifiedPass {
		t.Errorf("signatures = %q, want verified-pass (attestation found); reason=%q", got, m["C07.release.signatures"].Reason)
	}
	if got, _ := m["C07.release.signatures"].Facts["per_release"].([]map[string]any); len(got) != 1 || got[0]["attested_digest"] != "sha256:aaa" {
		t.Errorf("per_release facts = %v, want attested_digest=sha256:aaa", m["C07.release.signatures"].Facts["per_release"])
	}
}

func TestCollect_NoSignatureAssetAndNoAttestation_SignaturesFails(t *testing.T) {
	org, repo, branch, tag := "attestor-demo", "unattested-repo", "main", "v1.0.0"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerRelease(t, mux, org, repo, tag, time.Now().UTC().AddDate(0, 0, -1), []releaseAssetFixture{
		{Name: "myapp_linux_amd64.tar.gz", Digest: "sha256:aaa"},
	})
	registerLightweightTag(t, mux, org, repo, tag, "commit-sha-1")
	registerNoAttestations(t, mux, org, repo)
	registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C07.release.signatures"].Status; got != model.StatusVerifiedFail {
		t.Errorf("signatures = %q, want verified-fail (no signature asset, no attestation); reason=%q", got, m["C07.release.signatures"].Reason)
	}
}

func TestCollect_NoProvenanceWorkflow_Fails(t *testing.T) {
	org, repo, branch := "attestor-demo", "no-provenance-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerNoReleases(t, mux, org, repo)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C07.provenance.workflow"].Status; got != model.StatusVerifiedFail {
		t.Errorf("provenance.workflow = %q, want verified-fail", got)
	}
	for _, id := range []string{"C07.release.tags-signed", "C07.release.checksums", "C07.release.signatures", "C07.provenance.commit-linkage"} {
		if got := m[id].Status; got != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable (no releases in window)", id, got)
		}
	}
}

func TestCollect_NoWorkflowRunOnCommit_CommitLinkageFails(t *testing.T) {
	org, repo, branch, tag := "attestor-demo", "no-run-repo", "main", "v1.0.0"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerRelease(t, mux, org, repo, tag, time.Now().UTC().AddDate(0, 0, -1), nil)
	registerLightweightTag(t, mux, org, repo, tag, "commit-sha-1")
	registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C07.provenance.commit-linkage"].Status; got != model.StatusVerifiedFail {
		t.Errorf("commit-linkage = %q, want verified-fail; reason=%q", got, m["C07.provenance.commit-linkage"].Reason)
	}
}

func TestCollect_RepoFetchFailure403_AllChecksNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/attestor-demo/secret-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"secret-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
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

func TestCollect_PreCanceledContextProducesNotCheckableNotPanic(t *testing.T) {
	mux := http.NewServeMux()
	c := newCollectorForServer(t, newTestServer(t, mux))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := c.Collect(ctx, collect.Scope{Org: "attestor-demo", Repos: []string{"repo-a"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12})
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

func TestChecksRegistered(t *testing.T) {
	if len(checkTitles) != 5 {
		t.Fatalf("len(checkTitles) = %d, want 5", len(checkTitles))
	}
	for id := range checkTitles {
		if _, ok := collect.Lookup(id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry", id)
		}
	}
}
