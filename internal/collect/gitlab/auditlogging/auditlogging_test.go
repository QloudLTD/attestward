package auditlogging

import (
	"context"
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

// realHook is the shape GitLab really returns, captured 2026-08-10 from a
// live project (a hook created and then deleted for that purpose) against
// GET /projects/:id/hooks. Recorded rather than invented so field names —
// alert_status in particular — are exercised as the API actually spells them.
const realHook = `{"id":%d,"url":"https://example.invalid/webhook","alert_status":%q,
	"push_events":%t,"releases_events":%t,"deployment_events":%t,"tag_push_events":false,
	"merge_requests_events":false,"enable_ssl_verification":true}`

func hookJSON(id int, status string, push, releases, deploy bool) string {
	return fmt.Sprintf(realHook, id, status, push, releases, deploy)
}

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

func hooksHandler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}
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

// TestThreeChecksAreAlwaysNotCheckable pins the honesty invariant this
// package's three unreal checks depend on: they never fabricate a pass or a
// fail, whatever the webhooks endpoint does — they make no API call at all.
func TestThreeChecksAreAlwaysNotCheckable(t *testing.T) {
	results := collectWith(t, hooksHandler(200, "[]"), "g", "p")
	ids := byID(results)
	for _, id := range []string{idLogStreaming, idOrgLogAvailable, idRetentionAware} {
		r, ok := ids[id]
		if !ok {
			t.Fatalf("%s missing from results", id)
		}
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if r.Reason != auditPaidTierReason {
			t.Errorf("%s reason = %q, want the shared paid-tier reason — using anything else here would be the "+
				"exact bug this package was written to fix", id, r.Reason)
		}
		if len(r.Provenance) != 0 {
			t.Errorf("%s carries provenance, but no API call backs it", id)
		}
	}
}

func TestZeroWebhooksIsAFail(t *testing.T) {
	got := byID(collectWith(t, hooksHandler(200, "[]"), "g", "p"))[idRepoWebhooks]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("status = %q, want verified-fail; reason=%q", got.Status, got.Reason)
	}
}

func TestExecutableAndSubscribedIsAPass(t *testing.T) {
	body := "[" + hookJSON(1, alertExecutable, true, false, false) + "]"
	got := byID(collectWith(t, hooksHandler(200, body), "g", "p"))[idRepoWebhooks]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("status = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}
}

// TestOnlyRelevantEventsCount guards the other side of the pass condition: an
// executable hook that subscribes to nothing this check treats as export
// (tag_push, merge_requests, etc.) must not pass just for being healthy.
func TestOnlyRelevantEventsCount(t *testing.T) {
	body := "[" + hookJSON(1, alertExecutable, false, false, false) + "]"
	got := byID(collectWith(t, hooksHandler(200, body), "g", "p"))[idRepoWebhooks]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("an executable hook subscribed to nothing relevant = %q, want verified-fail", got.Status)
	}
}

func TestDisabledOrBackingOffHookIsAFail(t *testing.T) {
	for _, status := range []string{alertTemporarilyDisabled, alertDisabled} {
		t.Run(status, func(t *testing.T) {
			body := "[" + hookJSON(1, status, true, false, false) + "]"
			got := byID(collectWith(t, hooksHandler(200, body), "g", "p"))[idRepoWebhooks]
			if got.Status != model.StatusVerifiedFail {
				t.Errorf("alert_status %q, subscribed and healthy-looking otherwise = %q, want verified-fail — "+
					"it is not currently delivering", status, got.Status)
			}
		})
	}
}

func TestUnrecognisedAlertStatusIsNotCheckableNotFail(t *testing.T) {
	body := "[" + hookJSON(1, "quarantined", true, false, false) + "]"
	got := byID(collectWith(t, hooksHandler(200, body), "g", "p"))[idRepoWebhooks]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("unrecognised alert_status = %q, want not-checkable — guessing it means \"not delivering\" "+
			"would assert something never observed", got.Status)
	}
}

// TestUnrecognisedAlertStatusDoesNotSpoilAConfirmedPass pins that the refusal
// to guess only applies when it might change the verdict. A second hook whose
// status this build cannot interpret does not undo a pass a different,
// confirmed hook already earned.
func TestUnrecognisedAlertStatusDoesNotSpoilAConfirmedPass(t *testing.T) {
	body := "[" + hookJSON(1, alertExecutable, true, false, false) + "," +
		hookJSON(2, "quarantined", false, false, false) + "]"
	got := byID(collectWith(t, hooksHandler(200, body), "g", "p"))[idRepoWebhooks]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("status = %q, want verified-pass — hook 1 already confirms the property", got.Status)
	}
}

func TestWebhooksReadFailureIsNotCheckable(t *testing.T) {
	got := byID(collectWith(t, hooksHandler(403, `{"message":"403 Forbidden"}`), "g", "p"))[idRepoWebhooks]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", got.Status)
	}
}

// TestWebhooks403ReasonNamesTheRoleNotTheTier is the operator-facing half of
// issue #19. GET /projects/:id/hooks is Free-tier, so a 403 here is a role
// problem, not a paywall — but this package's other three checks are all
// paid-tier stories, which makes "we must be on the wrong plan" the obvious
// wrong conclusion to jump to. The reason has to rule it out.
func TestWebhooks403ReasonNamesTheRoleNotTheTier(t *testing.T) {
	got := byID(collectWith(t, hooksHandler(403, `{"message":"403 Forbidden"}`), "g", "p"))[idRepoWebhooks]
	for _, want := range []string{"Maintainer", "403 at Reporter"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("403 reason must mention %q, got: %s", want, got.Reason)
		}
	}
}

// TestNon403ReadFailureDoesNotBlameTheRole is the other side of the same
// property: a 404 or a transport error must NOT be attributed to Reporter.
// Naming a cause that was never observed is the failure mode this repo keeps
// correcting, and a blanket role hint would be exactly that.
func TestNon403ReadFailureDoesNotBlameTheRole(t *testing.T) {
	got := byID(collectWith(t, hooksHandler(404, `{"message":"404 Project Not Found"}`), "g", "p"))[idRepoWebhooks]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", got.Status)
	}
	if strings.Contains(got.Reason, "Reporter") {
		t.Errorf("a 404 must not be blamed on the token's role, got: %s", got.Reason)
	}
}

// TestWebhooksTokenScopeMatchesWhatTheEndpointAnswers pins the documentation
// fix. A Reporter token measured live gets 403 from this check's only
// endpoint, so documenting Reporter promised an answer the scan cannot
// produce. The three sibling checks make no API call and must keep saying so
// — raising them would invent a requirement none of them has.
func TestWebhooksTokenScopeMatchesWhatTheEndpointAnswers(t *testing.T) {
	meta, ok := collect.LookupPlatform(platform, idRepoWebhooks)
	if !ok {
		t.Fatalf("%s is not registered", idRepoWebhooks)
	}
	if !strings.Contains(meta.TokenScope, "Maintainer") {
		t.Errorf("%s token scope = %q; GET /projects/:id/hooks returns 403 at Reporter, so Reporter is not enough",
			idRepoWebhooks, meta.TokenScope)
	}

	for _, id := range []string{idLogStreaming, idOrgLogAvailable, idRetentionAware} {
		m, ok := collect.LookupPlatform(platform, id)
		if !ok {
			t.Fatalf("%s is not registered", id)
		}
		if !strings.HasPrefix(m.TokenScope, "none") {
			t.Errorf("%s token scope = %q, want the no-API-call wording — it makes no request, so naming a role "+
				"would invent a requirement it does not have", id, m.TokenScope)
		}
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

func TestNoReposMeansOnlyTheOrgLevelChecksEmit(t *testing.T) {
	results := collectWith(t, hooksHandler(200, "[]"), "g")
	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3 (no repos in scope, so repo.webhooks never runs)", len(results))
	}
	for _, r := range results {
		if r.CheckID == idRepoWebhooks {
			t.Error("repo.webhooks emitted with zero repos in scope")
		}
	}
}

func TestID(t *testing.T) {
	if got := New("https://gitlab.example", "t").ID(); got != collectorID {
		t.Errorf("ID() = %q, want %q", got, collectorID)
	}
}

// twoRepoHooksMux serves one executable, event-exporting hook for each of
// two distinct projects, so C09.repo.webhooks reaches its evidence-carrying
// pass for both and the single recorded provenance endpoint per result names
// exactly one project, making a cross-repo attribution visible in the
// endpoint string itself.
func twoRepoHooksMux(repos ...string) http.Handler {
	mux := http.NewServeMux()
	for i, repo := range repos {
		body := "[" + hookJSON(i+1, alertExecutable, true, false, false) + "]"
		mux.HandleFunc("/api/v4/projects/g%2F"+repo+"/hooks", hooksHandler(200, body))
	}
	return mux
}

// TestProvenanceNeverCitesAnotherReposAPICalls pins issue #15, the same
// defect #14 fixed in envseparation/provenance and which was empirically
// reproduced here: scanning p1,p2 in one run, repo p2's C09.repo.webhooks
// result carried a provenance entry citing GET /api/v4/projects/g%2Fp1/hooks.
// Client.Provenance() is cumulative over every call ever made through a
// client instance, so a client built once outside the scope.Repos loop
// attributes an earlier repo's API calls to a later repo's evidence — for an
// attestation tool whose whole claim is that each status is independently
// auditable from its own recorded API calls, that is an evidence-integrity
// defect, not a cosmetic one. Building the client per repo is what keeps each
// result's evidence its own; this test fails if that construction moves back
// out of webhooksResult.
func TestProvenanceNeverCitesAnotherReposAPICalls(t *testing.T) {
	results := collectWith(t, twoRepoHooksMux("p1", "p2"), "g", "p1", "p2")

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
// #10). Each state pins its expected status per check — comparing the whole
// map, not counting results — because a state that merely executes a code
// path without asserting its outcome is worse than no state at all: review
// found exactly that gap in this package's github/orgsecurity sibling on
// 2026-08-10, where a branch was reached and its result checked by nothing.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	pass, fail, nc := model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable
	always := map[string]model.Status{idLogStreaming: nc, idOrgLogAvailable: nc, idRetentionAware: nc}
	withWebhooks := func(webhooks model.Status) map[string]model.Status {
		out := map[string]model.Status{}
		for k, v := range always {
			out[k] = v
		}
		out[idRepoWebhooks] = webhooks
		return out
	}

	states := []struct {
		name    string
		handler http.HandlerFunc
		want    map[string]model.Status
	}{
		{"zero hooks", hooksHandler(200, "[]"), withWebhooks(fail)},
		{"executable and subscribed", hooksHandler(200, "["+hookJSON(1, alertExecutable, true, false, false)+"]"), withWebhooks(pass)},
		{"executable but irrelevant events", hooksHandler(200, "["+hookJSON(1, alertExecutable, false, false, false)+"]"), withWebhooks(fail)},
		{"disabled", hooksHandler(200, "["+hookJSON(1, alertDisabled, true, false, false)+"]"), withWebhooks(fail)},
		{"unrecognised status", hooksHandler(200, "["+hookJSON(1, "quarantined", true, false, false)+"]"), withWebhooks(nc)},
		{"webhooks unreadable", hooksHandler(403, `{"message":"nope"}`), withWebhooks(nc)},
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
