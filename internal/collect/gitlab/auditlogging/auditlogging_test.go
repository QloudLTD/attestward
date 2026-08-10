package auditlogging

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
