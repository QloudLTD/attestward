package provenance

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

func newTestCollector(t *testing.T, handler http.Handler) *Collector {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewForTest(server.URL, "token", func() (*gitlabcollect.Client, error) {
		return gitlabcollect.NewClientForTest(server.URL, "token", http.DefaultTransport)
	})
}

func byID(results []model.CheckResult) map[string]model.CheckResult {
	out := map[string]model.CheckResult{}
	for _, r := range results {
		out[r.CheckID] = r
	}
	return out
}

func collectWith(t *testing.T, handler http.Handler, org string, repos ...string) []model.CheckResult {
	t.Helper()
	c := newTestCollector(t, handler)
	results, err := c.Collect(context.Background(), collect.Scope{
		Org: org, Repos: repos, ReleaseTagPattern: "v*", LookbackReleases: 5, LookbackMonths: 12,
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return results
}

// releaseJSON builds one entry of the /releases response, verified
// 2026-08-11 against a live release on gitlab.com/sioakeim/attestward-scratch.
func releaseJSON(tag string, links []string) string {
	linkJSON := "["
	for i, l := range links {
		if i > 0 {
			linkJSON += ","
		}
		linkJSON += fmt.Sprintf(`{"name":%q}`, l)
	}
	linkJSON += "]"
	return fmt.Sprintf(`{"tag_name":%q,"released_at":"2026-08-01T00:00:00Z","assets":{"links":%s}}`, tag, linkJSON)
}

// provMux serves GET /projects/:id/releases and, per-tag, GET
// .../repository/tags/:tag/signature. sigStatus/sig let a state supply
// either a 2xx verification_status or a non-2xx status per tag; an absent
// entry in sigStatus defaults to 404 (unsigned), matching the real API's
// documented behavior for a tag nobody has signed.
func provMux(releases []string, sigStatus map[string]int, sigVerified map[string]bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/g%2Fp/releases", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "["+joinCommas(releases)+"]")
	})
	seen := map[string]bool{}
	for tag := range sigStatus {
		tag := tag
		if seen[tag] {
			continue
		}
		seen[tag] = true
		mux.HandleFunc("/api/v4/projects/g%2Fp/repository/tags/"+tag+"/signature", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			status := sigStatus[tag]
			if status != http.StatusOK {
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, `{"message":"404 Signature Not Found"}`)
				return
			}
			verified := "unverified"
			if sigVerified[tag] {
				verified = "verified"
			}
			_, _ = fmt.Fprintf(w, `{"signature_type":"X509","verification_status":%q}`, verified)
		})
	}
	return mux
}

func joinCommas(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func TestCommitLinkageAndWorkflowAreAlwaysNotCheckable(t *testing.T) {
	states := []http.Handler{
		provMux(nil, nil, nil),
		provMux([]string{releaseJSON("v1.0.0", []string{"checksums.txt", "attestward.sig"})},
			map[string]int{"v1.0.0": 200}, map[string]bool{"v1.0.0": true}),
	}
	for i, h := range states {
		t.Run(fmt.Sprintf("state-%d", i), func(t *testing.T) {
			got := byID(collectWith(t, h, "g", "p"))
			for _, id := range []string{idCommitLinkage, idWorkflow} {
				if got[id].Status != model.StatusNotCheckable {
					t.Errorf("%s = %q, want not-checkable in every state", id, got[id].Status)
				}
			}
		})
	}
}

func TestZeroReleasesInWindowIsNotCheckable(t *testing.T) {
	got := byID(collectWith(t, provMux(nil, nil, nil), "g", "p"))
	for _, id := range []string{idChecksums, idSignatures, idTagsSigned} {
		if got[id].Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got[id].Status)
		}
	}
}

func TestReleaseTagPatternExcludesNonMatchingTags(t *testing.T) {
	// "staging-2026" does not match the default "v*" pattern collectWith uses.
	got := byID(collectWith(t, provMux([]string{releaseJSON("staging-2026", nil)}, nil, nil), "g", "p"))
	for _, id := range []string{idChecksums, idSignatures, idTagsSigned} {
		if got[id].Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable — no release tag matched the pattern", id, got[id].Status)
		}
	}
}

func TestChecksumAndSignatureAssetsPass(t *testing.T) {
	releases := []string{releaseJSON("v1.0.0", []string{"checksums.txt", "attestward.sig"})}
	got := byID(collectWith(t, provMux(releases, map[string]int{"v1.0.0": 200}, map[string]bool{"v1.0.0": true}), "g", "p"))
	if got[idChecksums].Status != model.StatusVerifiedPass {
		t.Errorf("checksums = %q, want verified-pass; reason=%q", got[idChecksums].Status, got[idChecksums].Reason)
	}
	if got[idSignatures].Status != model.StatusVerifiedPass {
		t.Errorf("signatures = %q, want verified-pass; reason=%q", got[idSignatures].Status, got[idSignatures].Reason)
	}
}

func TestNoMatchingAssetsFails(t *testing.T) {
	releases := []string{releaseJSON("v1.0.0", []string{"attestward-linux-amd64"})}
	got := byID(collectWith(t, provMux(releases, map[string]int{"v1.0.0": 404}, nil), "g", "p"))
	if got[idChecksums].Status != model.StatusVerifiedFail {
		t.Errorf("checksums = %q, want verified-fail", got[idChecksums].Status)
	}
	if got[idSignatures].Status != model.StatusVerifiedFail {
		t.Errorf("signatures = %q, want verified-fail", got[idSignatures].Status)
	}
}

// TestChecksumPatternsMatchTheDocumentedConventions guards each pattern
// individually, so a future edit that narrows or breaks one regex is
// caught at the specific pattern, not just "some checksum check failed".
func TestChecksumPatternsMatchTheDocumentedConventions(t *testing.T) {
	for _, name := range []string{"checksums.txt", "SHA256SUMS", "sha256sums.txt", "attestward-linux-amd64.sha256", "attestward.sha256sum"} {
		if !matchesAnyPattern(name, checksumAssetPatterns) {
			t.Errorf("%q did not match any checksum pattern", name)
		}
	}
	if matchesAnyPattern("attestward-linux-amd64", checksumAssetPatterns) {
		t.Error("a plain binary name matched a checksum pattern")
	}
}

func TestSignaturePatternsMatchTheDocumentedConventions(t *testing.T) {
	for _, name := range []string{"attestward.sig", "cosign.pem", "attestward.intoto.jsonl", "attestward.sigstore", "attestward.sigstore.json", "attestward.bundle"} {
		if !matchesAnyPattern(name, signatureAssetPatterns) {
			t.Errorf("%q did not match any signature pattern", name)
		}
	}
}

func TestTagVerifiedIsAPass(t *testing.T) {
	releases := []string{releaseJSON("v1.0.0", nil)}
	got := byID(collectWith(t, provMux(releases, map[string]int{"v1.0.0": 200}, map[string]bool{"v1.0.0": true}), "g", "p"))
	if got[idTagsSigned].Status != model.StatusVerifiedPass {
		t.Errorf("tags-signed = %q, want verified-pass; reason=%q", got[idTagsSigned].Status, got[idTagsSigned].Reason)
	}
}

func TestTagUnsignedIs404AndAFail(t *testing.T) {
	releases := []string{releaseJSON("v1.0.0", nil)}
	got := byID(collectWith(t, provMux(releases, map[string]int{"v1.0.0": 404}, nil), "g", "p"))
	if got[idTagsSigned].Status != model.StatusVerifiedFail {
		t.Errorf("tags-signed = %q, want verified-fail; reason=%q", got[idTagsSigned].Status, got[idTagsSigned].Reason)
	}
}

func TestTagSignedButUnverifiedIsAFail(t *testing.T) {
	releases := []string{releaseJSON("v1.0.0", nil)}
	got := byID(collectWith(t, provMux(releases, map[string]int{"v1.0.0": 200}, map[string]bool{"v1.0.0": false}), "g", "p"))
	if got[idTagsSigned].Status != model.StatusVerifiedFail {
		t.Errorf("tags-signed = %q, want verified-fail; reason=%q", got[idTagsSigned].Status, got[idTagsSigned].Reason)
	}
}

// TestTagSignedResponseWithNoVerificationStatusIsUnresolved covers a 2xx
// body that doesn't carry the documented verification_status field (e.g.
// `{}` or a 204 with no body) — that's an unresolvable lookup, not evidence
// the tag is signed-but-not-verified, which is what an empty string would
// otherwise be read as under the plain err==nil-and-not-"verified" case.
func TestTagSignedResponseWithNoVerificationStatusIsUnresolved(t *testing.T) {
	releases := []string{releaseJSON("v1.0.0", nil)}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/g%2Fp/releases", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, "["+releases[0]+"]")
	})
	mux.HandleFunc("/api/v4/projects/g%2Fp/repository/tags/v1.0.0/signature", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{}`)
	})
	got := byID(collectWith(t, mux, "g", "p"))
	if got[idTagsSigned].Status != model.StatusPartial {
		t.Errorf("tags-signed = %q, want partial — a 2xx body with no verification_status field is unresolved, not a confirmed fail", got[idTagsSigned].Status)
	}
}

func TestTagSignatureLookupErrorIsPartialNotFail(t *testing.T) {
	releases := []string{releaseJSON("v1.0.0", nil)}
	got := byID(collectWith(t, provMux(releases, map[string]int{"v1.0.0": 500}, nil), "g", "p"))
	if got[idTagsSigned].Status != model.StatusPartial {
		t.Errorf("tags-signed = %q, want partial — a 500 says nothing about whether the tag is signed", got[idTagsSigned].Status)
	}
}

// TestFailBeatsUnresolvedAcrossMultipleReleases exercises
// rollupReleaseResults with more than one release in the window — every
// other tags-signed test only ever supplies one, so a swap of the
// anyFailed/anyUnresolved precedence in the switch (partial winning over a
// confirmed fail) would pass the rest of this file's tests unnoticed.
func TestFailBeatsUnresolvedAcrossMultipleReleases(t *testing.T) {
	releases := []string{
		releaseJSON("v2.0.0", nil), // unresolved: signature lookup 500s
		releaseJSON("v1.0.0", nil), // confirmed fail: unsigned (404)
	}
	got := byID(collectWith(t, provMux(releases, map[string]int{"v2.0.0": 500, "v1.0.0": 404}, nil), "g", "p"))
	if got[idTagsSigned].Status != model.StatusVerifiedFail {
		t.Errorf("tags-signed = %q, want verified-fail — a confirmed failure must win over an unresolved release, not the reverse", got[idTagsSigned].Status)
	}
}

func TestReleasesReadFailureIsNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/g%2Fp/releases", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		_, _ = fmt.Fprint(w, `{"message":"403 Forbidden"}`)
	})
	got := byID(collectWith(t, mux, "g", "p"))
	for _, id := range []string{idChecksums, idSignatures, idTagsSigned} {
		if got[id].Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got[id].Status)
		}
	}
}

func TestClientBuildFailureIsNotCheckableForEveryCheck(t *testing.T) {
	c := NewForTest("https://example.invalid", "token", func() (*gitlabcollect.Client, error) {
		return nil, fmt.Errorf("boom")
	})
	results, err := c.Collect(context.Background(), collect.Scope{Org: "g", Repos: []string{"p"}, ReleaseTagPattern: "v*"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 5 {
		t.Fatalf("len(results) = %d, want 5", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
	}
}

func TestID(t *testing.T) {
	if got := New("https://gitlab.example", "t").ID(); got != collectorID {
		t.Errorf("ID() = %q, want %q", got, collectorID)
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue
// #10), with per-state expected statuses compared as a whole map, from the
// start — every state pinning an outcome, not just executing a path.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	pass, fail, partial, nc := model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable
	always := map[string]model.Status{idCommitLinkage: nc, idWorkflow: nc}
	withReleaseChecks := func(checksums, signatures, tagsSigned model.Status) map[string]model.Status {
		out := map[string]model.Status{}
		for k, v := range always {
			out[k] = v
		}
		out[idChecksums] = checksums
		out[idSignatures] = signatures
		out[idTagsSigned] = tagsSigned
		return out
	}

	states := []struct {
		name string
		h    http.Handler
		want map[string]model.Status
	}{
		{"all evidence present and verified",
			provMux([]string{releaseJSON("v1.0.0", []string{"checksums.txt", "attestward.sig"})},
				map[string]int{"v1.0.0": 200}, map[string]bool{"v1.0.0": true}),
			withReleaseChecks(pass, pass, pass)},
		{"no matching assets, tag unsigned",
			provMux([]string{releaseJSON("v1.0.0", []string{"attestward-linux-amd64"})},
				map[string]int{"v1.0.0": 404}, nil),
			withReleaseChecks(fail, fail, fail)},
		{"tag signed but unverified",
			provMux([]string{releaseJSON("v1.0.0", []string{"checksums.txt", "attestward.sig"})},
				map[string]int{"v1.0.0": 200}, map[string]bool{"v1.0.0": false}),
			withReleaseChecks(pass, pass, fail)},
		{"signature lookup errors, everything else fine",
			provMux([]string{releaseJSON("v1.0.0", []string{"checksums.txt", "attestward.sig"})},
				map[string]int{"v1.0.0": 500}, nil),
			withReleaseChecks(pass, pass, partial)},
		{"zero releases in window", provMux(nil, nil, nil), withReleaseChecks(nc, nc, nc)},
		{"releases unreadable", (func() http.Handler {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v4/projects/g%2Fp/releases", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(403)
				_, _ = fmt.Fprint(w, `{"message":"nope"}`)
			})
			return mux
		})(), withReleaseChecks(nc, nc, nc)},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			res := collectWith(t, st.h, "g", "p")
			got := map[string]model.Status{}
			for _, r := range res {
				got[r.CheckID] = r.Status
			}
			if len(got) != len(st.want) {
				t.Fatalf("got %d results, want %d", len(got), len(st.want))
			}
			for id, want := range st.want {
				if got[id] != want {
					t.Errorf("%s = %q, want %q", id, got[id], want)
				}
			}
			all = append(all, res...)
		})
	}

	collecttest.AssertRubricsMatchObservedBehaviour(t, platform, collectorID, all)
}
