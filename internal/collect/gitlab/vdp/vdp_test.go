package vdp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: repos})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return results
}

// projectStatus/fileStatus/fileBody build a mux that mirrors the two calls
// collectRepo actually makes: GET /projects/:id (for default_branch), then
// GET /projects/:id/repository/files/{path} for each candidate path in
// candidatePaths. fileBody, keyed by candidate path, lets a state supply a
// different (or absent) response per path — SECURITY.md at the root vs at
// docs/ are two different URLs on the real API.
func vdpMux(projectStatus int, fileStatus map[string]int, fileBody map[string]string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/g%2Fp", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if projectStatus != http.StatusOK {
			w.WriteHeader(projectStatus)
			_, _ = fmt.Fprint(w, `{"message":"nope"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"default_branch":"main"}`)
	})
	for _, path := range candidatePaths {
		path := path
		mux.HandleFunc("/api/v4/projects/g%2Fp/repository/files/"+escapePath(path), func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			status, ok := fileStatus[path]
			if !ok {
				status = http.StatusNotFound
			}
			if status != http.StatusOK {
				w.WriteHeader(status)
				_, _ = fmt.Fprint(w, `{"message":"nope"}`)
				return
			}
			body := fileBody[path]
			_, _ = fmt.Fprintf(w, `{"encoding":"base64","content":%q}`, base64.StdEncoding.EncodeToString([]byte(body)))
		})
	}
	return mux
}

func TestPrivateReportingAndSecurityPolicyOrgAreAlwaysNotCheckable(t *testing.T) {
	results := collectWith(t, vdpMux(200, nil, nil), "g", "p")
	ids := byID(results)
	for _, id := range []string{privateReportingID, securityPolicyOrgID} {
		r, ok := ids[id]
		if !ok {
			t.Fatalf("%s missing from results", id)
		}
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if len(r.Provenance) != 0 {
			t.Errorf("%s carries provenance, but no API call backs it", id)
		}
	}
	if ids[securityPolicyOrgID].Scope.Repo != "" {
		t.Error("securityPolicyOrgID must be org-scoped, not stamped with a repo")
	}
}

func TestSecurityMDResolvesAtRoot(t *testing.T) {
	got := byID(collectWith(t, vdpMux(200, map[string]int{"SECURITY.md": 200}, map[string]string{"SECURITY.md": "contact security@example.com"}), "g", "p"))
	if got[securityMDID].Status != model.StatusVerifiedPass {
		t.Errorf("security-md = %q, want verified-pass; reason=%q", got[securityMDID].Status, got[securityMDID].Reason)
	}
	if got[securityMDID].Facts["resolved_path"] != "SECURITY.md" {
		t.Errorf("resolved_path = %v, want SECURITY.md", got[securityMDID].Facts["resolved_path"])
	}
}

func TestSecurityMDFallsBackToDocsPath(t *testing.T) {
	got := byID(collectWith(t, vdpMux(200, map[string]int{"docs/SECURITY.md": 200}, map[string]string{"docs/SECURITY.md": "contact security@example.com"}), "g", "p"))
	if got[securityMDID].Status != model.StatusVerifiedPass {
		t.Errorf("security-md = %q, want verified-pass", got[securityMDID].Status)
	}
	if got[securityMDID].Facts["resolved_path"] != "docs/SECURITY.md" {
		t.Errorf("resolved_path = %v, want docs/SECURITY.md", got[securityMDID].Facts["resolved_path"])
	}
}

func TestNeitherPathFoundIsAFail(t *testing.T) {
	got := byID(collectWith(t, vdpMux(200, nil, nil), "g", "p"))
	if got[securityMDID].Status != model.StatusVerifiedFail {
		t.Errorf("security-md = %q, want verified-fail", got[securityMDID].Status)
	}
	if got[intakeChannelID].Status != model.StatusVerifiedFail {
		t.Errorf("intake-channel = %q, want verified-fail", got[intakeChannelID].Status)
	}
}

func TestResolvedButVagueContentIsPartial(t *testing.T) {
	got := byID(collectWith(t, vdpMux(200, map[string]int{"SECURITY.md": 200}, map[string]string{"SECURITY.md": "We take security seriously."}), "g", "p"))
	if got[securityMDID].Status != model.StatusVerifiedPass {
		t.Errorf("security-md = %q, want verified-pass — the file exists", got[securityMDID].Status)
	}
	if got[intakeChannelID].Status != model.StatusPartial {
		t.Errorf("intake-channel = %q, want partial", got[intakeChannelID].Status)
	}
}

func TestURLSignalAlonePasses(t *testing.T) {
	got := byID(collectWith(t, vdpMux(200, map[string]int{"SECURITY.md": 200}, map[string]string{"SECURITY.md": "Report via https://example.com/security"}), "g", "p"))
	if got[intakeChannelID].Status != model.StatusVerifiedPass {
		t.Errorf("intake-channel = %q, want verified-pass; reason=%q", got[intakeChannelID].Status, got[intakeChannelID].Reason)
	}
}

func TestProjectFetchFailureIsNotCheckable(t *testing.T) {
	got := byID(collectWith(t, vdpMux(403, nil, nil), "g", "p"))
	for _, id := range []string{securityMDID, intakeChannelID} {
		if got[id].Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got[id].Status)
		}
	}
}

// TestMissingProjectIsNotCheckableNotAFail pins the distinction review found:
// unlike the Azure DevOps twin, which addresses the repo directly and so
// folds a missing/invisible repo into verified-fail, this collector reads
// the project first for its default branch — so a 404 there is a read
// failure (not-checkable), never a confirmed absence of the file. A reader
// treating verified-fail as excluding "the token couldn't see the project"
// would have the two statuses backwards without this.
func TestMissingProjectIsNotCheckableNotAFail(t *testing.T) {
	got := byID(collectWith(t, vdpMux(404, nil, nil), "g", "p"))
	for _, id := range []string{securityMDID, intakeChannelID} {
		if got[id].Status == model.StatusVerifiedFail {
			t.Errorf("%s = verified-fail for a 404'd project — that asserts a confirmed absence of "+
				"SECURITY.md when the file was never actually looked for", id)
		}
		if got[id].Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got[id].Status)
		}
	}
}

// TestEmptyDecodedContentIsNotCheckableNotAFalseFail pins the one guard in
// resolve.go that had no test of its own — review's mutation deleting it
// survived the whole suite. A 2xx response that decodes to zero bytes is
// indistinguishable from a genuinely empty file from this response alone,
// so it must not be silently treated as "keep trying, not found": that
// would either under-report (false verified-fail, if no later path exists)
// or, worse, quietly skip a real response the caller should have been told
// it couldn't interpret.
func TestEmptyDecodedContentIsNotCheckableNotAFalseFail(t *testing.T) {
	got := byID(collectWith(t, vdpMux(200, map[string]int{"SECURITY.md": 200}, map[string]string{"SECURITY.md": ""}), "g", "p"))
	if got[securityMDID].Status != model.StatusNotCheckable {
		t.Errorf("security-md = %q, want not-checkable — a 2xx response that decoded to empty content is "+
			"not evidence the file is absent", got[securityMDID].Status)
	}
}

func TestFileReadFailureIsNotCheckable(t *testing.T) {
	got := byID(collectWith(t, vdpMux(200, map[string]int{"SECURITY.md": 403, "docs/SECURITY.md": 403}, nil), "g", "p"))
	for _, id := range []string{securityMDID, intakeChannelID} {
		if got[id].Status != model.StatusNotCheckable {
			t.Errorf("%s = %q, want not-checkable", id, got[id].Status)
		}
	}
}

func TestUnexpectedEncodingIsNotCheckableNotAFalseFail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/g%2Fp", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"default_branch":"main"}`)
	})
	mux.HandleFunc("/api/v4/projects/g%2Fp/repository/files/SECURITY.md", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"encoding":"none","content":"whatever"}`)
	})
	mux.HandleFunc("/api/v4/projects/g%2Fp/repository/files/docs%2FSECURITY.md", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	})
	got := byID(collectWith(t, mux, "g", "p"))
	if got[securityMDID].Status != model.StatusNotCheckable {
		t.Errorf("an unrecognised encoding produced %q, not not-checkable — a file demonstrably exists, so "+
			"reporting it as a confirmed absence (verified-fail) would be a false negative", got[securityMDID].Status)
	}
}

func TestClientBuildFailureIsNotCheckableForEveryCheck(t *testing.T) {
	c := NewForTest("https://example.invalid", "token", func() (*gitlabcollect.Client, error) {
		return nil, fmt.Errorf("boom")
	})
	results, err := c.Collect(context.Background(), collect.Scope{Org: "g", Repos: []string{"p"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
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

// twoRepoVDPMux serves a readable project and a root SECURITY.md with an
// actionable intake channel for each of two distinct projects, so both
// per-repo checks reach their evidence-carrying pass and every recorded
// provenance endpoint — the project read and the file read alike — names
// exactly one project, making a cross-repo attribution visible in the
// endpoint string itself.
func twoRepoVDPMux(repos ...string) http.Handler {
	mux := http.NewServeMux()
	for _, repo := range repos {
		id := "g%2F" + repo
		content := "Report vulnerabilities to security@" + repo + ".example.com"
		mux.HandleFunc("/api/v4/projects/"+id, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"default_branch":"main"}`)
		})
		mux.HandleFunc("/api/v4/projects/"+id+"/repository/files/SECURITY.md", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"encoding":"base64","content":%q}`, base64.StdEncoding.EncodeToString([]byte(content)))
		})
	}
	return mux
}

// TestProvenanceNeverCitesAnotherReposAPICalls pins issue #15, the same
// defect #14 fixed in envseparation/provenance and which was empirically
// reproduced here: scanning p1,p2 in one run, repo p2's C10.vdp.security-md
// and C10.vdp.intake-channel results carried a provenance entry citing GET
// /api/v4/projects/g%2Fp1/repository/files/SECURITY.md. Client.Provenance()
// is cumulative over every call ever made through a client instance, so a
// client built once outside the scope.Repos loop attributes an earlier
// repo's API calls to a later repo's evidence — for an attestation tool
// whose whole claim is that each status is independently auditable from its
// own recorded API calls, that is an evidence-integrity defect, not a
// cosmetic one. Building the client per repo is what keeps each result's
// evidence its own; this test fails if that construction moves back out of
// collectRepo.
func TestProvenanceNeverCitesAnotherReposAPICalls(t *testing.T) {
	results := collectWith(t, twoRepoVDPMux("p1", "p2"), "g", "p1", "p2")

	sawP2Evidence := false
	for _, r := range results {
		if r.Scope.Repo != "p2" {
			continue
		}
		for _, p := range r.Provenance {
			if strings.Contains(p.Endpoint, "p1") {
				t.Errorf("%s (repo p2) provenance cites %s %s — an API call made while processing repo p1, "+
					"not p2", r.CheckID, p.Method, p.Endpoint)
			}
			if strings.Contains(p.Endpoint, "p2") {
				sawP2Evidence = true
			}
		}
	}
	if !sawP2Evidence {
		t.Fatal("no p2 result carried a single provenance entry naming p2 — the cross-repo assertion above " +
			"would have passed vacuously")
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue
// #10). Each state pins its expected status per check, compared as a whole
// map — a state that merely executes a code path without asserting its
// outcome is worse than no state at all (found in review of this
// package's github/orgsecurity sibling on 2026-08-10).
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	pass, fail, partial, nc := model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable
	always := map[string]model.Status{privateReportingID: nc, securityPolicyOrgID: nc}
	withRepoChecks := func(securityMD, intake model.Status) map[string]model.Status {
		out := map[string]model.Status{}
		for k, v := range always {
			out[k] = v
		}
		out[securityMDID] = securityMD
		out[intakeChannelID] = intake
		return out
	}

	states := []struct {
		name    string
		handler http.Handler
		want    map[string]model.Status
	}{
		{"resolved with actionable content", vdpMux(200, map[string]int{"SECURITY.md": 200}, map[string]string{"SECURITY.md": "security@example.com"}), withRepoChecks(pass, pass)},
		{"resolved but vague", vdpMux(200, map[string]int{"SECURITY.md": 200}, map[string]string{"SECURITY.md": "we take security seriously"}), withRepoChecks(pass, partial)},
		{"not found anywhere", vdpMux(200, nil, nil), withRepoChecks(fail, fail)},
		{"project unreadable", vdpMux(403, nil, nil), withRepoChecks(nc, nc)},
		{"project missing (404)", vdpMux(404, nil, nil), withRepoChecks(nc, nc)},
		{"file unreadable", vdpMux(200, map[string]int{"SECURITY.md": 403, "docs/SECURITY.md": 403}, nil), withRepoChecks(nc, nc)},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			res := collectWith(t, st.handler, "g", "p")
			got := map[string]model.Status{}
			for _, r := range res {
				got[r.CheckID] = r.Status
			}
			if !mapsEqual(got, st.want) {
				t.Errorf("statuses = %v, want %v", got, st.want)
			}
			all = append(all, res...)
		})
	}

	collecttest.AssertRubricsMatchObservedBehaviour(t, platform, collectorID, all)
}

func mapsEqual(a, b map[string]model.Status) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
