package provenance

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/model"
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
	org, repo, branch, tag := "attestward-demo", "good-repo", "main", "v1.0.0"
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
	org, repo, branch, tag := "attestward-demo", "lightweight-repo", "main", "v1.0.0"
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
	org, repo, branch := "attestward-demo", "mixed-resolution-repo", "main"
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
	org, repo, branch, tag := "attestward-demo", "unverified-repo", "main", "v1.0.0"
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
	org, repo, branch, tag := "attestward-demo", "no-checksum-repo", "main", "v1.0.0"
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
	org, repo, branch, tag := "attestward-demo", "attested-repo", "main", "v1.0.0"
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
	org, repo, branch, tag := "attestward-demo", "unattested-repo", "main", "v1.0.0"
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

// TestCollect_AttestationLookupFails_SignaturesCapsAtPartialNotFail pins a
// distinct bug from TestCollect_NoSignatureAssetAndNoAttestation_SignaturesFails:
// that test's registerNoAttestations returns a clean 200 with zero
// attestations — a genuinely-verified negative. Here the attestations
// call itself errors (403), which checkSignatures used to fold into the
// exact same releaseFailed verdict as a clean "not found" — asserting a
// confirmed absence of signature evidence when the truth is "unresolved,
// the lookup itself failed" (the digest that errored might well have an
// attestation). checkTagsSigned/checkCommitLinkage already distinguish
// this via releaseUnresolved; checkSignatures didn't.
func TestCollect_AttestationLookupFails_SignaturesCapsAtPartialNotFail(t *testing.T) {
	org, repo, branch, tag := "attestward-demo", "attestation-403-repo", "main", "v1.0.0"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	registerNoWorkflows(t, mux, org, repo)
	registerRelease(t, mux, org, repo, tag, time.Now().UTC().AddDate(0, 0, -1), []releaseAssetFixture{
		{Name: "myapp_linux_amd64.tar.gz", Digest: "sha256:aaa"},
	})
	registerLightweightTag(t, mux, org, repo, tag, "commit-sha-1")
	mux.HandleFunc("/repos/"+org+"/"+repo+"/attestations/sha256:aaa", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})
	registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	if got := m["C07.release.signatures"].Status; got != model.StatusPartial {
		t.Errorf("signatures = %q, want partial (attestation lookup failed — unresolved, not a confirmed absence); reason=%q", got, m["C07.release.signatures"].Reason)
	}
}

func TestCollect_NoProvenanceWorkflow_Fails(t *testing.T) {
	org, repo, branch := "attestward-demo", "no-provenance-repo", "main"
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

// TestCollect_OnlyWorkflowUnreadable_ProvenanceWorkflowNotCheckableNotFail
// is issue #207's regression case, mirroring the identical fix already
// shipped for C05/C06 on both platforms (issue #178) and this package's
// own ADO twin: a repo whose only workflow can't be fetched (content 404)
// must NOT read verified-fail ("no provenance tool detected") — that
// asserts a confirmed absence when inspection of the one workflow that
// exists actually failed. It must read not-checkable instead, with the
// skip surfaced in Facts. Before this fix, provenance.workflow was the
// one tool-configured-shaped check on either platform that discarded
// MatchWorkflows'/MatchPipelines' skipped return entirely.
func TestCollect_OnlyWorkflowUnreadable_ProvenanceWorkflowNotCheckableNotFail(t *testing.T) {
	org, repo, branch := "attestward-demo", "flaky-repo", "main"
	mux := http.NewServeMux()
	registerRepo(t, mux, org, repo, branch)
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows": []map[string]any{
				{"id": 1, "name": "Mystery", "path": ".github/workflows/mystery.yml", "state": "active"},
			},
		})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/.github/workflows/mystery.yml", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
	registerNoReleases(t, mux, org, repo)

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
	results, err := c.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m := byID(results)

	pw := m["C07.provenance.workflow"]
	if pw.Status != model.StatusNotCheckable {
		t.Errorf("provenance.workflow = %q, want not-checkable (the repo's only workflow couldn't be inspected — not a confirmed absence); reason=%q", pw.Status, pw.Reason)
	}
	skipped, ok := pw.Facts["skipped_workflows"].([]map[string]any)
	if !ok || len(skipped) != 1 || skipped[0]["path"] != ".github/workflows/mystery.yml" || skipped[0]["reason"] == "" {
		t.Errorf("skipped_workflows facts = %v, want one entry for mystery.yml with a non-empty reason", pw.Facts["skipped_workflows"])
	}
}

func TestCollect_NoWorkflowRunOnCommit_CommitLinkageFails(t *testing.T) {
	org, repo, branch, tag := "attestward-demo", "no-run-repo", "main", "v1.0.0"
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
	mux.HandleFunc("/repos/attestward-demo/secret-repo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
	})

	c := newCollectorForServer(t, newTestServer(t, mux))
	scope := collect.Scope{Org: "attestward-demo", Repos: []string{"secret-repo"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
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

	results, err := c.Collect(ctx, collect.Scope{Org: "attestward-demo", Repos: []string{"repo-a"}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12})
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

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce (see orgsecurity's own copy of this
// pattern for the full rationale). C07.release.checksums is the odd one
// out: unlike every other check in this package, it has no partial
// branch — its per-release evaluation is pure computation over already-
// fetched release/asset data with no further I/O that could leave a
// release unresolved (see checkChecksums in checks.go).
var checkWantStatuses = map[string][]model.Status{
	"C07.release.tags-signed":       {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C07.release.checksums":         {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	"C07.release.signatures":        {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C07.provenance.workflow":       {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	"C07.provenance.commit-linkage": {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) /`)

// TestCollect_RegisteredMetadataCompleteForChecksReference is
// orgsecurity's TestCollect_RegisteredMetadataCompleteForChecksReference,
// replicated per the pattern that PR validated: see that test's own doc
// comment for the full rationale (exact Rubric key-set equality per check,
// GET/HEAD-only Endpoints enforcing ADR-0004, orphaned-key detection).
func TestCollect_RegisteredMetadataCompleteForChecksReference(t *testing.T) {
	if len(checkRubrics) != len(checkTitles) {
		t.Errorf("checkRubrics has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRubrics), len(checkTitles))
	}
	if len(checkEndpoints) != len(checkTitles) {
		t.Errorf("checkEndpoints has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkEndpoints), len(checkTitles))
	}

	for id := range checkTitles {
		meta, ok := collect.Lookup(id)
		if !ok {
			t.Fatalf("check %q not found in the collect.CheckMeta registry", id)
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
				t.Errorf("%s: Endpoints entry %q isn't GET/HEAD — this project is read-only forever (ADR-0004)", id, e)
			}
		}

		if meta.FixtureRef == "" {
			t.Errorf("%s: FixtureRef is empty", id)
		}
	}
}

// TestTagsSignedRemediationDoesNotClaimOrgLevelKeyPage locks in that the
// remediation doesn't send a reader to a nonexistent org-level "SSH and
// GPG keys" settings page — GitHub only supports registering signing keys
// on a personal user account (tag/commit signature verification is always
// attributed to the individual tagger's account, never an org). Confirmed
// against this repo's own C07 demo-fixture setup, which
// registered its signing key via `gh api user/ssh_signing_keys`, not any
// org-scoped endpoint.
func TestTagsSignedRemediationDoesNotClaimOrgLevelKeyPage(t *testing.T) {
	remediation := checkRemediations["C07.release.tags-signed"]
	if strings.Contains(strings.ToLower(remediation), "org settings") || strings.Contains(remediation, "account/org") {
		t.Errorf("C07.release.tags-signed remediation implies an org-level key-registration page exists — GitHub only supports this per personal user account: %q", remediation)
	}
}

// lowConfidenceSLSAYAML is named "SLSA" — matching the slsa-generator
// signature's low-confidence workflow_name_pattern — while calling neither
// of its reusable workflows, so it produces a name-only match and nothing
// stronger.
const lowConfidenceSLSAYAML = `name: SLSA
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`

func registerNamedWorkflow(t *testing.T, mux *http.ServeMux, org, repo, name, path, content string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/actions/workflows", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, map[string]any{
			"total_count": 1,
			"workflows":   []map[string]any{{"id": 1, "name": name, "path": path, "state": "active"}},
		})
	})
	mux.HandleFunc("/repos/"+org+"/"+repo+"/contents/"+path, func(w http.ResponseWriter, _ *http.Request) {
		if content == "" {
			writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"content": content, "sha": "content-sha"})
	})
}

// registerTwoReleases registers two in-window releases sharing one asset
// list, for the states that need the rollup to see a mix of verdicts.
func registerTwoReleases(t *testing.T, mux *http.ServeMux, org, repo, tagA, tagB string, assets []releaseAssetFixture) {
	t.Helper()
	assetEntries := make([]map[string]any, 0, len(assets))
	for _, a := range assets {
		assetEntries = append(assetEntries, map[string]any{"name": a.Name, "digest": a.Digest})
	}
	mux.HandleFunc("/repos/"+org+"/"+repo+"/releases", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, []map[string]any{
			{"tag_name": tagA, "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339), "assets": assetEntries},
			{"tag_name": tagB, "target_commitish": "main", "published_at": time.Now().UTC().AddDate(0, 0, -2).Format(time.RFC3339), "assets": assetEntries},
		})
	})
}

func registerUnresolvableTag(t *testing.T, mux *http.ServeMux, org, repo, tag string) {
	t.Helper()
	mux.HandleFunc("/repos/"+org+"/"+repo+"/git/ref/tags/"+tag, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	})
}

// provRubricState is one fixture world for TestRubricsMatchObservedBehaviour.
// C07's five checks read four different upstream sources in overlapping
// combinations, and which of them a state needs to bend varies too much for
// a flat struct of optional fields — so each state registers its own
// handlers.
type provRubricState struct {
	name  string
	setup func(t *testing.T, mux *http.ServeMux, org, repo string)
	want  map[string]model.Status
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// # Conflation risks
//
// Two pairs of C07 checks read literally the same value, and the fixtures
// already in this file move each pair in lockstep:
//
//  1. tags-signed and commit-linkage both consume the SAME
//     []resolvedRelease slice, and both turn a non-nil ResolveErr into
//     releaseUnresolved. TestCollect_UnresolvableTagAmongOthers above
//     asserts exactly that lockstep — both partial, from one shared cause —
//     which is correct behaviour and also precisely the shape that would
//     hide commit-linkage reading r.Signature.Signed instead of r.RunCount.
//     States 4 and 5 are built as mirrors to break it: each holds one
//     unresolvable tag plus one resolvable one, and the resolvable one is
//     arranged so the two checks reach OPPOSITE verdicts on it. In state 4
//     it is signed but has no run (tags-signed partial, commit-linkage
//     verified-fail); in state 5 it is lightweight but has a run
//     (tags-signed verified-fail, commit-linkage partial). Since
//     rollupReleaseResults lets a confirmed failure outrank an unresolved
//     one, the two checks come out on opposite sides of both statuses.
//  2. checksums and signatures both read the SAME raw.Assets name list
//     through the SAME matchingAssetNames helper, differing only in which
//     regexp set they pass it. States 2 and 3 are the split: a release with
//     checksums.txt and no signature asset, and a release with a .sig and
//     no checksum file.
//
// A third, weaker sharing is structural: all four per-release checks return
// not-checkable together when no release matches the window, since none of
// them has anything to evaluate. provenance.workflow is release-independent
// and does not, which state 8 pins.
//
// # Confirmed by mutation, not assumed
//
// Each was injected into the production code and traced to the states that
// caught it:
//
//   - collectRepo feeding checkCommitLinkage the tag's signed-and-verified
//     state in place of its run count — the conflation this matrix is built
//     against, written at the source rather than as a weaker
//     always-passes stub: caught by states 2, 3, 4, 5 and 6, in both
//     directions.
//   - checkChecksums passing signatureAssetPatterns to matchingAssetNames:
//     caught by states 2, 3, 5 and 11, in both directions.
//   - checkTagsSigned's `r.Signature.Signed && r.Signature.Verified`
//     weakened to `r.Signature.Signed` alone: caught by state 6 alone, whose
//     tag carries a signature GitHub does not verify — every other state's
//     tag is either verified or lightweight, where the two are equivalent.
//   - rollupReleaseResults' `case anyFailed` moved below `case
//     anyUnresolved`, so an unresolved release outranks a confirmed one:
//     caught by states 4 and 5 — the only states holding both verdicts at
//     once, and the reason they are mirrors rather than one state.
//   - checkSignatures' AttestationErr arm changed from releaseUnresolved to
//     releaseFailed: caught by state 7 alone.
//   - checkProvenanceWorkflow's `case hasAny` (partial) deleted: caught by
//     state 3 alone, the only state with a name-only provenance match.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	const org = "attestward-demo"
	yesterday := time.Now().UTC().AddDate(0, 0, -1)

	states := []provRubricState{
		{
			name: "signed tag, checksum and signature assets, provenance workflow, and a run on the commit",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerCosignWorkflow(t, mux, org, repo)
				registerRelease(t, mux, org, repo, "v1.0.0", yesterday, []releaseAssetFixture{
					{Name: "myapp_linux_amd64.tar.gz"},
					{Name: "checksums.txt"},
					{Name: "checksums.txt.bundle"},
				})
				registerAnnotatedTag(t, mux, org, repo, "v1.0.0", "tag-obj-sha", "commit-sha-1", true, "valid")
				registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{
					"commit-sha-1": {{"id": 1, "head_sha": "commit-sha-1", "conclusion": "success"}},
				})
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusVerifiedPass,
				"C07.release.checksums":         model.StatusVerifiedPass,
				"C07.release.signatures":        model.StatusVerifiedPass,
				"C07.provenance.workflow":       model.StatusVerifiedPass,
				"C07.provenance.commit-linkage": model.StatusVerifiedPass,
			},
		},
		{
			// A signed tag whose commit no workflow ever ran on, and a
			// checksum file with no signature beside it. Both shared pairs
			// split here in one direction.
			name: "signed tag with a checksum asset, but no run on the commit and no signature asset",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerNoWorkflows(t, mux, org, repo)
				registerRelease(t, mux, org, repo, "v1.0.0", yesterday, []releaseAssetFixture{
					{Name: "myapp_linux_amd64.tar.gz"},
					{Name: "checksums.txt"},
				})
				registerAnnotatedTag(t, mux, org, repo, "v1.0.0", "tag-obj-sha", "commit-sha-1", true, "valid")
				registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{})
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusVerifiedPass,
				"C07.release.checksums":         model.StatusVerifiedPass,
				"C07.release.signatures":        model.StatusVerifiedFail,
				"C07.provenance.workflow":       model.StatusVerifiedFail,
				"C07.provenance.commit-linkage": model.StatusVerifiedFail,
			},
		},
		{
			// The exact reverse of state 2 on both pairs: a lightweight
			// (so structurally unsignable) tag whose commit DOES carry a
			// run, and a signature asset with no checksum file. Also the
			// only route to provenance.workflow's partial.
			name: "lightweight tag with a signature asset and a run, but no checksum asset",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerNamedWorkflow(t, mux, org, repo, "SLSA", ".github/workflows/slsa.yml", lowConfidenceSLSAYAML)
				registerRelease(t, mux, org, repo, "v1.0.0", yesterday, []releaseAssetFixture{
					{Name: "myapp_linux_amd64.tar.gz"},
					{Name: "myapp_linux_amd64.tar.gz.sig"},
				})
				registerLightweightTag(t, mux, org, repo, "v1.0.0", "commit-sha-1")
				registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{
					"commit-sha-1": {{"id": 1, "head_sha": "commit-sha-1", "conclusion": "success"}},
				})
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusVerifiedFail,
				"C07.release.checksums":         model.StatusVerifiedFail,
				"C07.release.signatures":        model.StatusVerifiedPass,
				"C07.provenance.workflow":       model.StatusPartial,
				"C07.provenance.commit-linkage": model.StatusVerifiedPass,
			},
		},
		{
			// One unresolvable tag plus one that IS resolvable, signed, and
			// has no run on its commit. tags-signed sees pass + unresolved
			// and caps at partial; commit-linkage sees fail + unresolved
			// and reports the confirmed failure. Same shared
			// []resolvedRelease, opposite answers.
			name: "unresolvable tag alongside a signed tag with no run on its commit",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerNoWorkflows(t, mux, org, repo)
				registerTwoReleases(t, mux, org, repo, "v1.0.0", "v0.9.0", nil)
				registerAnnotatedTag(t, mux, org, repo, "v1.0.0", "tag-obj-sha", "commit-sha-good", true, "valid")
				registerUnresolvableTag(t, mux, org, repo, "v0.9.0")
				registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{})
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusPartial,
				"C07.release.checksums":         model.StatusVerifiedFail,
				"C07.release.signatures":        model.StatusVerifiedFail,
				"C07.provenance.workflow":       model.StatusVerifiedFail,
				"C07.provenance.commit-linkage": model.StatusVerifiedFail,
			},
		},
		{
			// State 4's mirror: the resolvable tag is now lightweight but
			// its commit DOES carry a run, so the two checks swap sides —
			// tags-signed reports the confirmed failure, commit-linkage
			// caps at partial.
			name: "unresolvable tag alongside a lightweight tag with a run on its commit",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerCosignWorkflow(t, mux, org, repo)
				registerTwoReleases(t, mux, org, repo, "v1.0.0", "v0.9.0", []releaseAssetFixture{
					{Name: "checksums.txt"},
				})
				registerLightweightTag(t, mux, org, repo, "v1.0.0", "commit-sha-good")
				registerUnresolvableTag(t, mux, org, repo, "v0.9.0")
				registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{
					"commit-sha-good": {{"id": 1, "head_sha": "commit-sha-good", "conclusion": "success"}},
				})
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusVerifiedFail,
				"C07.release.checksums":         model.StatusVerifiedPass,
				"C07.release.signatures":        model.StatusVerifiedFail,
				"C07.provenance.workflow":       model.StatusVerifiedPass,
				"C07.provenance.commit-linkage": model.StatusPartial,
			},
		},
		{
			// The tag is annotated and carries a signature GitHub will not
			// verify — the only state that separates "signed" from
			// "verified".
			name: "annotated tag whose signature is not verified",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerCosignWorkflow(t, mux, org, repo)
				registerRelease(t, mux, org, repo, "v1.0.0", yesterday, []releaseAssetFixture{
					{Name: "checksums.txt"},
					{Name: "checksums.txt.bundle"},
				})
				registerAnnotatedTag(t, mux, org, repo, "v1.0.0", "tag-obj-sha", "commit-sha-1", false, "unknown_key")
				registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{
					"commit-sha-1": {{"id": 1, "head_sha": "commit-sha-1", "conclusion": "success"}},
				})
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusVerifiedFail,
				"C07.release.checksums":         model.StatusVerifiedPass,
				"C07.release.signatures":        model.StatusVerifiedPass,
				"C07.provenance.workflow":       model.StatusVerifiedPass,
				"C07.provenance.commit-linkage": model.StatusVerifiedPass,
			},
		},
		{
			// No signature asset by naming convention, and the attestation
			// lookup that would have settled the other kind of evidence
			// itself failed — the only route to signatures' partial.
			name: "attestation lookup fails with no signature asset",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerNoWorkflows(t, mux, org, repo)
				registerRelease(t, mux, org, repo, "v1.0.0", yesterday, []releaseAssetFixture{
					{Name: "myapp_linux_amd64.tar.gz", Digest: "sha256:aaa"},
				})
				mux.HandleFunc("/repos/"+org+"/"+repo+"/attestations/", func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusInternalServerError, map[string]any{"message": "boom"})
				})
				registerAnnotatedTag(t, mux, org, repo, "v1.0.0", "tag-obj-sha", "commit-sha-1", true, "valid")
				registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{
					"commit-sha-1": {{"id": 1, "head_sha": "commit-sha-1", "conclusion": "success"}},
				})
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusVerifiedPass,
				"C07.release.checksums":         model.StatusVerifiedFail,
				"C07.release.signatures":        model.StatusPartial,
				"C07.provenance.workflow":       model.StatusVerifiedFail,
				"C07.provenance.commit-linkage": model.StatusVerifiedPass,
			},
		},
		{
			// No release matches the window, so the four per-release checks
			// have nothing to evaluate — while provenance.workflow, which
			// never looks at a release, still answers. The only state that
			// separates it from the other four.
			name: "no releases in the lookback window",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerCosignWorkflow(t, mux, org, repo)
				registerNoReleases(t, mux, org, repo)
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusNotCheckable,
				"C07.release.checksums":         model.StatusNotCheckable,
				"C07.release.signatures":        model.StatusNotCheckable,
				"C07.provenance.workflow":       model.StatusVerifiedPass,
				"C07.provenance.commit-linkage": model.StatusNotCheckable,
			},
		},
		{
			// The reverse of state 8: the release resolves cleanly on every
			// axis while the repo's only workflow can't be inspected, so
			// provenance.workflow alone refuses to assert an absence.
			name: "the only workflow is unreadable while the release is fully evidenced",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerNamedWorkflow(t, mux, org, repo, "Mystery", ".github/workflows/mystery.yml", "")
				registerRelease(t, mux, org, repo, "v1.0.0", yesterday, []releaseAssetFixture{
					{Name: "checksums.txt"},
					{Name: "checksums.txt.bundle"},
				})
				registerAnnotatedTag(t, mux, org, repo, "v1.0.0", "tag-obj-sha", "commit-sha-1", true, "valid")
				registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{
					"commit-sha-1": {{"id": 1, "head_sha": "commit-sha-1", "conclusion": "success"}},
				})
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusVerifiedPass,
				"C07.release.checksums":         model.StatusVerifiedPass,
				"C07.release.signatures":        model.StatusVerifiedPass,
				"C07.provenance.workflow":       model.StatusNotCheckable,
				"C07.provenance.commit-linkage": model.StatusVerifiedPass,
			},
		},
		{
			// The repo read fails, so collectRepo returns before any
			// check-specific evidence exists: the only route to all five
			// reporting not-checkable together.
			name: "repo read forbidden",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				mux.HandleFunc("/repos/"+org+"/"+repo, func(w http.ResponseWriter, _ *http.Request) {
					writeJSON(t, w, http.StatusForbidden, map[string]any{"message": "Forbidden"})
				})
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusNotCheckable,
				"C07.release.checksums":         model.StatusNotCheckable,
				"C07.release.signatures":        model.StatusNotCheckable,
				"C07.provenance.workflow":       model.StatusNotCheckable,
				"C07.provenance.commit-linkage": model.StatusNotCheckable,
			},
		},
		{
			// signatures' second, independently-sufficient evidence route:
			// no signature-shaped asset name, but a GitHub Artifact
			// Attestation exists for one of the release's asset digests.
			name: "no signature asset but an attestation exists for an asset digest",
			setup: func(t *testing.T, mux *http.ServeMux, org, repo string) {
				registerRepo(t, mux, org, repo, "main")
				registerCosignWorkflow(t, mux, org, repo)
				registerRelease(t, mux, org, repo, "v1.0.0", yesterday, []releaseAssetFixture{
					{Name: "myapp_linux_amd64.tar.gz", Digest: "sha256:aaa"},
					{Name: "checksums.txt"},
				})
				registerAttestationFor(t, mux, org, repo, "sha256:aaa")
				registerAnnotatedTag(t, mux, org, repo, "v1.0.0", "tag-obj-sha", "commit-sha-1", true, "valid")
				registerWorkflowRunsForCommit(t, mux, org, repo, map[string][]map[string]any{
					"commit-sha-1": {{"id": 1, "head_sha": "commit-sha-1", "conclusion": "success"}},
				})
			},
			want: map[string]model.Status{
				"C07.release.tags-signed":       model.StatusVerifiedPass,
				"C07.release.checksums":         model.StatusVerifiedPass,
				"C07.release.signatures":        model.StatusVerifiedPass,
				"C07.provenance.workflow":       model.StatusVerifiedPass,
				"C07.provenance.commit-linkage": model.StatusVerifiedPass,
			},
		},
	}

	var all []model.CheckResult
	for i, st := range states {
		t.Run(st.name, func(t *testing.T) {
			// A distinct repo name per state keeps each state's handler
			// registrations on their own mux paths, so a helper that
			// registers a fixed path can't collide across states.
			repo := fmt.Sprintf("rubric-repo-%02d", i+1)
			mux := http.NewServeMux()
			st.setup(t, mux, org, repo)

			c := newCollectorForServer(t, newTestServer(t, mux))
			scope := collect.Scope{Org: org, Repos: []string{repo}, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12}
			results, err := c.Collect(context.Background(), scope)
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
			// Compared whole, in both directions: a missing key is as much
			// a defect as a wrong one, and a row count would show neither.
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

	collecttest.AssertRubricsMatchObservedBehaviour(t, "github", collectorID, all)
}
