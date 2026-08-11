package vdp

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	gogscollect "gitlab.com/sioakeim/attestward/internal/collect/gogs"
	"gitlab.com/sioakeim/attestward/internal/collect/gogs/gogsfixture"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const baseURL = "https://gogs.example.com"

func fileResponse(content string) gogsfixture.Response {
	return gogsfixture.Response{Status: 200, Body: map[string]any{
		"type":     "file",
		"encoding": "base64",
		"size":     len(content),
		"path":     "SECURITY.md",
		"content":  base64.StdEncoding.EncodeToString([]byte(content)),
	}}
}

func notFound() gogsfixture.Response {
	// Verified against Gogs 0.15: a missing path answers 404 with an
	// empty body, not a JSON error envelope.
	return gogsfixture.Response{Status: 404, RawBody: []byte{}}
}

func contentsPath(path string) string {
	return "/api/v1/repos/acme/widget/contents/" + path
}

func collectWith(t *testing.T, fx *gogsfixture.Transport) []model.CheckResult {
	t.Helper()
	c := NewForTest(baseURL, "token", func() (*gogscollect.Client, error) {
		return gogscollect.NewClientForTest(baseURL, "token", fx)
	})
	results, err := c.Collect(context.Background(), collect.Scope{Org: "acme", Repos: []string{"widget"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return results
}

func byID(results []model.CheckResult) map[string]model.CheckResult {
	out := map[string]model.CheckResult{}
	for _, r := range results {
		out[r.CheckID] = r
	}
	return out
}

// TestCollect_AlwaysEmitsEveryCheckID is the cardinality invariant a Gogs
// pack depends on: a reader comparing a Gogs pack to a GitHub one must
// never have to wonder whether a missing row means "not applicable here"
// or "the scan stopped early". Two of these four can only ever be
// not-checkable, and they must still appear.
func TestCollect_AlwaysEmitsEveryCheckID(t *testing.T) {
	fx := gogsfixture.New()
	for _, p := range candidatePaths {
		fx.Set("GET", contentsPath(p), notFound())
	}

	got := byID(collectWith(t, fx))
	for _, id := range checkIDs {
		if _, ok := got[id]; !ok {
			t.Errorf("result for %s missing entirely", id)
		}
	}
	if len(got) != len(checkIDs) {
		t.Errorf("got %d distinct check IDs, want %d", len(got), len(checkIDs))
	}
}

// TestCollect_PolicyPresentWithChannel is the ordinary healthy case, and
// it also pins the resolution order: `.github/SECURITY.md` wins, and the
// later candidates are never requested once a file resolves.
func TestCollect_PolicyPresentWithChannel(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", contentsPath(".github/SECURITY.md"), fileResponse("Report to security@acme.example."))

	results := collectWith(t, fx)
	got := byID(results)

	if s := got[securityMDID]; s.Status != model.StatusVerifiedPass {
		t.Errorf("security-md status = %q (%s), want verified-pass", s.Status, s.Reason)
	} else if s.Facts["resolved_path"] != ".github/SECURITY.md" {
		t.Errorf("resolved_path fact = %v, want the path actually read", s.Facts["resolved_path"])
	}

	intake := got[intakeChannelID]
	if intake.Status != model.StatusVerifiedPass {
		t.Errorf("intake-channel status = %q (%s), want verified-pass", intake.Status, intake.Reason)
	}
	signals, _ := intake.Facts["intake_signals"].([]string)
	if len(signals) != 1 || signals[0] != "email" {
		t.Errorf("intake_signals = %v, want exactly [email]", intake.Facts["intake_signals"])
	}

	for _, call := range fx.Calls() {
		if call == "GET "+contentsPath("SECURITY.md") || call == "GET "+contentsPath("docs/SECURITY.md") {
			t.Errorf("kept walking candidate paths after a file resolved: %v", fx.Calls())
		}
	}
}

// TestCollect_PolicyPresentWithoutChannel: a file that exists and says
// nothing actionable is capped at partial. Passing it would let "we take
// security seriously" satisfy a control about being reachable.
func TestCollect_PolicyPresentWithoutChannel(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", contentsPath(".github/SECURITY.md"), notFound())
	fx.Set("GET", contentsPath("SECURITY.md"), fileResponse("We take security seriously and act promptly."))

	got := byID(collectWith(t, fx))
	if s := got[securityMDID]; s.Status != model.StatusVerifiedPass {
		t.Errorf("security-md status = %q, want verified-pass — the file does exist", s.Status)
	}
	intake := got[intakeChannelID]
	if intake.Status != model.StatusPartial {
		t.Errorf("intake-channel status = %q (%s), want partial", intake.Status, intake.Reason)
	}
	if signals, _ := intake.Facts["intake_signals"].([]string); len(signals) != 0 {
		t.Errorf("intake_signals = %v, want an empty list rather than an absent key", intake.Facts["intake_signals"])
	}
}

// TestCollect_PolicyAbsentEverywhereIsAConfirmedFail: every candidate path
// answered 404, so absence is something the scan established, not
// something it assumed. This is the case that must NOT be not-checkable.
func TestCollect_PolicyAbsentEverywhereIsAConfirmedFail(t *testing.T) {
	fx := gogsfixture.New()
	for _, p := range candidatePaths {
		fx.Set("GET", contentsPath(p), notFound())
	}

	got := byID(collectWith(t, fx))
	if s := got[securityMDID]; s.Status != model.StatusVerifiedFail {
		t.Errorf("security-md status = %q (%s), want verified-fail", s.Status, s.Reason)
	}
	if s := got[intakeChannelID]; s.Status != model.StatusVerifiedFail {
		t.Errorf("intake-channel status = %q, want verified-fail — there is no file to advertise a channel", s.Status)
	}
	if len(fx.Calls()) != len(candidatePaths) {
		t.Errorf("made %d calls, want one per candidate path (%d)", len(fx.Calls()), len(candidatePaths))
	}
}

// TestCollect_APIErrorIsNotCheckableNotAbsence is this codebase's recurring
// defect class, in its C10 shape: a 500 must never be reported as "no
// policy exists". A verified-fail here would be a fabricated observation in
// a signed pack.
func TestCollect_APIErrorIsNotCheckableNotAbsence(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", contentsPath(".github/SECURITY.md"), gogsfixture.Response{
		Status: 500, Body: map[string]any{"message": "internal server error"},
	})

	got := byID(collectWith(t, fx))
	for _, id := range []string{securityMDID, intakeChannelID} {
		if s := got[id]; s.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q (%s), want not-checkable — a 5xx establishes nothing about the repo", id, s.Status, s.Reason)
		}
	}
}

// TestCollect_AuthFailureIsNotCheckable: a 401 means the token cannot see
// the repo, which says nothing about whether a policy exists.
func TestCollect_AuthFailureIsNotCheckable(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", contentsPath(".github/SECURITY.md"), gogsfixture.Response{
		Status: http.StatusUnauthorized, Body: map[string]any{"message": "unauthorized"},
	})

	got := byID(collectWith(t, fx))
	if s := got[securityMDID]; s.Status != model.StatusNotCheckable {
		t.Errorf("security-md status = %q (%s), want not-checkable", s.Status, s.Reason)
	}
}

// TestCollect_DirectoryNamedSecurityMDIsNotAPolicy pins the trap the Azure
// DevOps twin found in review: a *folder* called SECURITY.md must not
// verified-pass with empty content. On Gogs a directory comes back as a
// JSON array rather than an object, so this is a different shape of the
// same mistake.
func TestCollect_DirectoryNamedSecurityMDIsNotAPolicy(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", contentsPath(".github/SECURITY.md"), gogsfixture.Response{
		Status: 200, Body: []map[string]any{{"type": "file", "name": "README.md", "path": ".github/SECURITY.md/README.md"}},
	})
	fx.Set("GET", contentsPath("SECURITY.md"), notFound())
	fx.Set("GET", contentsPath("docs/SECURITY.md"), notFound())

	got := byID(collectWith(t, fx))
	if s := got[securityMDID]; s.Status != model.StatusVerifiedFail {
		t.Errorf("security-md status = %q (%s), want verified-fail — a directory is not a policy file", s.Status, s.Reason)
	}
}

// TestCollect_UnexpectedEncodingIsNotCheckable: content this collector
// cannot decode must not be reported as an absence. Skipping the path
// silently would turn a decoding failure into a confirmed "no policy".
func TestCollect_UnexpectedEncodingIsNotCheckable(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", contentsPath(".github/SECURITY.md"), gogsfixture.Response{Status: 200, Body: map[string]any{
		"type": "file", "encoding": "none", "size": 99, "path": ".github/SECURITY.md", "content": "",
	}})

	got := byID(collectWith(t, fx))
	if s := got[securityMDID]; s.Status != model.StatusNotCheckable {
		t.Errorf("security-md status = %q (%s), want not-checkable", s.Status, s.Reason)
	}
}

// TestCollect_PlatformFactChecksNeverClaimEvidence guards the two checks
// that can only be not-checkable. If either ever grew a provenance entry,
// it would be claiming this tool asked the instance something it never
// asked; if either ever produced a verified-fail, it would be blaming a
// producer for not enabling a feature that does not exist.
func TestCollect_PlatformFactChecksNeverClaimEvidence(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", contentsPath(".github/SECURITY.md"), fileResponse("mail security@acme.example"))

	got := byID(collectWith(t, fx))
	for _, id := range []string{privateReportingID, securityPolicyOrgID} {
		r := got[id]
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable on every instance", id, r.Status)
		}
		if len(r.Provenance) != 0 {
			t.Errorf("%s carries %d provenance entries, want none — no call backs it", id, len(r.Provenance))
		}
		if r.Provenance == nil {
			t.Errorf("%s Provenance is nil, want an empty slice (schema invariant)", id)
		}
	}
}

// TestCollect_CanceledContextDoesNotRewritePlatformFacts: cancellation is
// true of the two checks that would have made a call, and false of the two
// that never would. Replacing the platform fact with "the scan was
// canceled" would lose the only information a reader can act on.
func TestCollect_CanceledContextDoesNotRewritePlatformFacts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewForTest(baseURL, "token", func() (*gogscollect.Client, error) {
		return gogscollect.NewClientForTest(baseURL, "token", gogsfixture.New())
	})
	results, err := c.Collect(ctx, collect.Scope{Org: "acme", Repos: []string{"widget"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	got := byID(results)
	if len(got) != len(checkIDs) {
		t.Fatalf("got %d results, want %d even under cancellation", len(got), len(checkIDs))
	}
	if r := got[securityMDID]; r.Status != model.StatusNotCheckable {
		t.Errorf("security-md status = %q, want not-checkable", r.Status)
	}
	if r := got[privateReportingID]; strings.Contains(r.Reason, "canceled") {
		t.Errorf("private-reporting Reason = %q, want the platform fact rather than a cancellation message", r.Reason)
	}
	if r := got[privateReportingID]; !strings.Contains(r.Reason, "no private vulnerability reporting feature") {
		t.Errorf("private-reporting Reason = %q, want it to state the platform fact", r.Reason)
	}
}

// TestRegisteredMetadataIsComplete: the checks reference is generated from
// this metadata, so an empty rubric or remediation ships as a hole in
// customer-facing documentation. Endpoints is deliberately empty for the
// two platform-fact checks and must NOT be empty for the two real ones.
func TestRegisteredMetadataIsComplete(t *testing.T) {
	for _, id := range checkIDs {
		meta, ok := collect.LookupPlatform(platform, id)
		if !ok {
			t.Fatalf("%s is not registered for platform %q", id, platform)
		}
		if meta.Collector != collectorID {
			t.Errorf("%s Collector = %q, want %q — every platform registering an ID must agree", id, meta.Collector, collectorID)
		}
		if meta.Title == "" || meta.Remediation == "" || len(meta.Rubric) == 0 {
			t.Errorf("%s has empty Title/Remediation/Rubric", id)
		}
		for _, verb := range meta.Endpoints {
			if len(verb) < 4 || verb[:4] != "GET " {
				t.Errorf("%s registers a non-GET endpoint %q — this tool is read-only forever (ADR-0004)", id, verb)
			}
		}
	}
	if len(mustMeta(t, securityMDID).Endpoints) == 0 {
		t.Error("security-md registers no endpoints, but its result is API-derived")
	}
	if len(mustMeta(t, privateReportingID).Endpoints) != 0 {
		t.Error("private-reporting registers an endpoint, but no call backs it")
	}
}

func mustMeta(t *testing.T, id string) collect.CheckMeta {
	t.Helper()
	meta, ok := collect.LookupPlatform(platform, id)
	if !ok {
		t.Fatalf("%s not registered", id)
	}
	return meta
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue
// #10), with per-state expected statuses compared as a whole map — the
// lesson from review earlier the same day: a state that merely executes a
// code path without asserting its outcome is worse than no state at all.
// States reuse the fixtures TestCollect_* above already established rather
// than reinventing them.
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
		name string
		fx   func() *gogsfixture.Transport
		want map[string]model.Status
	}{
		{"resolved with an actionable channel", func() *gogsfixture.Transport {
			fx := gogsfixture.New()
			fx.Set("GET", contentsPath(".github/SECURITY.md"), fileResponse("Report to security@acme.example."))
			return fx
		}, withRepoChecks(pass, pass)},
		{"resolved but vague", func() *gogsfixture.Transport {
			fx := gogsfixture.New()
			fx.Set("GET", contentsPath(".github/SECURITY.md"), notFound())
			fx.Set("GET", contentsPath("SECURITY.md"), fileResponse("We take security seriously."))
			return fx
		}, withRepoChecks(pass, partial)},
		{"absent everywhere", func() *gogsfixture.Transport {
			fx := gogsfixture.New()
			for _, p := range candidatePaths {
				fx.Set("GET", contentsPath(p), notFound())
			}
			return fx
		}, withRepoChecks(fail, fail)},
		{"API error", func() *gogsfixture.Transport {
			fx := gogsfixture.New()
			fx.Set("GET", contentsPath(".github/SECURITY.md"), gogsfixture.Response{
				Status: 500, Body: map[string]any{"message": "internal server error"},
			})
			return fx
		}, withRepoChecks(nc, nc)},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			res := collectWith(t, st.fx())
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
