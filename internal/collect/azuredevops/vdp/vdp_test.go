package vdp

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/adofixture"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const (
	testOrg     = "acme-ado"
	testProject = "WidgetsApp"
	testPAT     = "ado-test-pat"
	testRepo    = "widgets"
)

func newCollector(fx *adofixture.Transport) *Collector {
	c := New(testOrg, testPAT)
	c.newClientForTest = func(org, pat string) *azuredevops.Client {
		return azuredevops.NewClientForTest(org, pat, fx)
	}
	return c
}

func itemsPath(project, repo string) string {
	return "/" + testOrg + "/" + project + "/_apis/git/repositories/" + repo + "/items"
}

func byID(results []model.CheckResult) map[string]model.CheckResult {
	m := map[string]model.CheckResult{}
	for _, r := range results {
		m[r.CheckID] = r
	}
	return m
}

func notFoundResponse() adofixture.Response {
	return adofixture.Response{Status: http.StatusNotFound, Body: map[string]any{"message": "not found"}}
}

// contentResponse is a valid GitItem response for a real, readable
// SECURITY.md blob — includes isFolder/gitObjectType/objectId alongside
// content, since resolveSecurityMD's guards (added in review: a bare
// Content decode let a folder or unexpected-shape response silently
// verified-pass) now require all three to trust a 2xx response as a
// resolved file.
func contentResponse(content string) adofixture.Response {
	return adofixture.Response{Status: http.StatusOK, Body: map[string]any{
		"isFolder":      false,
		"gitObjectType": "blob",
		"objectId":      "61a86fdaa79e5c6f5fb6e4026508489feb6ed92c",
		"content":       content,
	}}
}

// folderResponse is what Items - Get returns for a folder that happens to
// be named the same as a candidate path (e.g. a SECURITY.md/ directory) —
// isFolder true, gitObjectType "tree", and (as a real ADO response would)
// no content field at all, since content doesn't apply to a tree object.
func folderResponse() adofixture.Response {
	return adofixture.Response{Status: http.StatusOK, Body: map[string]any{
		"isFolder":      true,
		"gitObjectType": "tree",
	}}
}

// contentOmittedResponse is a validly-shaped blob (isFolder false,
// gitObjectType blob, a real objectId) whose content field is absent —
// the case Azure DevOps can return for content types it doesn't inline
// even with includeContent=true (e.g. binary).
func contentOmittedResponse() adofixture.Response {
	return adofixture.Response{Status: http.StatusOK, Body: map[string]any{
		"isFolder":      false,
		"gitObjectType": "blob",
		"objectId":      "61a86fdaa79e5c6f5fb6e4026508489feb6ed92c",
	}}
}

// unexpectedShapeResponse is a 2xx response that is neither a folder nor
// a validly-shaped blob (gitObjectType absent, no objectId) — an
// unrecognized shape this collector has no live Entra org to have
// confirmed can't occur, so it must error rather than being silently
// trusted as a resolved file.
func unexpectedShapeResponse() adofixture.Response {
	return adofixture.Response{Status: http.StatusOK, Body: map[string]any{
		"isFolder": false,
	}}
}

// --- security-md ---

// TestCollect_SecurityMD_RootHit_VerifiedPass proves the fallback path is
// never tried when the root candidate resolves — fx.Calls() is the only
// way to prove that (a passing status alone can't distinguish "found on
// the first try" from "found after a fallback that also happened").
func TestCollect_SecurityMD_RootHit_VerifiedPass(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), contentResponse("Report vulnerabilities to security@example.com"))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[securityMDID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("security-md = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}
	if got.Facts["resolved_path"] != "/SECURITY.md" {
		t.Errorf("resolved_path = %v, want /SECURITY.md", got.Facts["resolved_path"])
	}
	if calls := fx.Calls(); len(calls) != 1 {
		t.Errorf("calls = %v, want exactly 1 (the fallback path must not be tried when the root path hits)", calls)
	}
}

// TestCollect_SecurityMD_FallbackHit_VerifiedPass proves the /docs/SECURITY.md
// fallback is actually attempted (and used) when the root candidate 404s —
// both requests hit the identical URL path (only the "path" query parameter
// differs between candidates), so SetSequence is what lets the fixture
// serve a 404 then a 200 to the same key in call order.
func TestCollect_SecurityMD_FallbackHit_VerifiedPass(t *testing.T) {
	fx := adofixture.New()
	fx.SetSequence("GET", azuredevops.HostCore, itemsPath(testProject, testRepo),
		notFoundResponse(),
		contentResponse("Report vulnerabilities to security@example.com"),
	)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[securityMDID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("security-md = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}
	if got.Facts["resolved_path"] != "/docs/SECURITY.md" {
		t.Errorf("resolved_path = %v, want /docs/SECURITY.md", got.Facts["resolved_path"])
	}
	if calls := fx.Calls(); len(calls) != 2 {
		t.Errorf("calls = %v, want exactly 2 (root 404, then the docs/ fallback)", calls)
	}
}

// TestCollect_SecurityMD_Both404_VerifiedFail proves the two-path chain is
// exhausted (not a single 404 short-circuiting to fail) before reporting
// fail.
func TestCollect_SecurityMD_Both404_VerifiedFail(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), notFoundResponse())

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[securityMDID]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("security-md = %q, want verified-fail; reason=%q", got.Status, got.Reason)
	}
	if calls := fx.Calls(); len(calls) != 2 {
		t.Errorf("calls = %v, want exactly 2 (both candidate paths tried)", calls)
	}
}

// TestCollect_SecurityMD_GenericError_NotCheckable proves a genuine API
// error (not a 404) short-circuits the chain immediately rather than being
// treated as "try the next path".
func TestCollect_SecurityMD_GenericError_NotCheckable(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), adofixture.Response{
		Status: http.StatusInternalServerError,
		Body:   map[string]any{"message": "boom"},
	})

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[securityMDID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("security-md = %q, want not-checkable; reason=%q", got.Status, got.Reason)
	}
	if calls := fx.Calls(); len(calls) != 1 {
		t.Errorf("calls = %v, want exactly 1 (a genuine error must not be retried against the fallback path)", calls)
	}
	// intake-channel shares the same resolve failure.
	if got := byID(results)[intakeChannelID]; got.Status != model.StatusNotCheckable {
		t.Errorf("intake-channel = %q, want not-checkable (shares security-md's resolve error)", got.Status)
	}
}

// TestCollect_SecurityMD_FolderAtRoot_TriesFallback_VerifiedPass is the
// regression case found in review: a folder happening to be named
// SECURITY.md must not be silently treated as a resolved file — it must
// be skipped exactly like a 404, trying the next candidate path.
func TestCollect_SecurityMD_FolderAtRoot_TriesFallback_VerifiedPass(t *testing.T) {
	fx := adofixture.New()
	fx.SetSequence("GET", azuredevops.HostCore, itemsPath(testProject, testRepo),
		folderResponse(),
		contentResponse("security@example.com"),
	)

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[securityMDID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("security-md = %q, want verified-pass (folder at root must not block the fallback); reason=%q", got.Status, got.Reason)
	}
	if got.Facts["resolved_path"] != "/docs/SECURITY.md" {
		t.Errorf("resolved_path = %v, want /docs/SECURITY.md", got.Facts["resolved_path"])
	}
	if calls := fx.Calls(); len(calls) != 2 {
		t.Errorf("calls = %v, want exactly 2 (root is a folder, so the fallback is tried)", calls)
	}
}

// TestCollect_SecurityMD_BothCandidatesFolders_VerifiedFail proves a
// folder at BOTH candidate paths still exhausts the chain to a genuine
// verified-fail, not an error and not a false pass — the folder guard
// must never itself become a not-checkable path.
func TestCollect_SecurityMD_BothCandidatesFolders_VerifiedFail(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), folderResponse())

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[securityMDID]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("security-md = %q, want verified-fail; reason=%q", got.Status, got.Reason)
	}
	if calls := fx.Calls(); len(calls) != 2 {
		t.Errorf("calls = %v, want exactly 2 (both candidates are folders)", calls)
	}
}

// TestCollect_SecurityMD_ContentOmitted_NotCheckable is the second
// regression case found in review: a validly-shaped blob response (a real
// file, not a folder) whose content field Azure DevOps didn't populate
// must not silently verified-pass with an empty Content — that would make
// intake-channel's own Reason claim content was inspected when it never
// was.
func TestCollect_SecurityMD_ContentOmitted_NotCheckable(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), contentOmittedResponse())

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[securityMDID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("security-md = %q, want not-checkable (content field wasn't populated); reason=%q", got.Status, got.Reason)
	}
	if !contains(got.Reason, "content") {
		t.Errorf("Reason = %q, want it to explain content wasn't returned", got.Reason)
	}
	// intake-channel shares the same resolve failure — it must not claim
	// to have inspected content that was never actually returned.
	if got := byID(results)[intakeChannelID]; got.Status != model.StatusNotCheckable {
		t.Errorf("intake-channel = %q, want not-checkable (shares security-md's resolve error)", got.Status)
	}
}

// TestCollect_SecurityMD_UnexpectedItemShape_NotCheckable proves a 2xx
// response that's neither a recognizable folder nor a validly-shaped blob
// (missing gitObjectType/objectId) errors out rather than being silently
// trusted as a resolved file — this collector has no live Entra org to
// have confirmed every shape Items - Get can return (see resolve.go's own
// [fixture-verify] note).
func TestCollect_SecurityMD_UnexpectedItemShape_NotCheckable(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), unexpectedShapeResponse())

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[securityMDID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("security-md = %q, want not-checkable (unexpected item shape); reason=%q", got.Status, got.Reason)
	}
}

// TestCollect_ContentNegotiationQueryParams pins the exact query this
// collector must send: $format=json (without it, Items - Get's documented
// default for a file blob is a raw byte stream, not the JSON envelope
// gitItemRaw expects to decode — see resolve.go's own doc comment),
// includeContent=true, api-version=7.1, and the right "path" value per
// candidate in order.
func TestCollect_ContentNegotiationQueryParams(t *testing.T) {
	fx := adofixture.New()
	fx.SetSequence("GET", azuredevops.HostCore, itemsPath(testProject, testRepo),
		notFoundResponse(),
		contentResponse("security@example.com"),
	)
	capture := &queryCapturingTransport{base: fx}
	c := New(testOrg, testPAT)
	c.newClientForTest = func(org, pat string) *azuredevops.Client {
		return azuredevops.NewClientForTest(org, pat, capture)
	}

	if _, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}}); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if len(capture.queries) != 2 {
		t.Fatalf("captured %d queries, want 2", len(capture.queries))
	}
	wantPaths := []string{"/SECURITY.md", "/docs/SECURITY.md"}
	for i, q := range capture.queries {
		if got := q.Get("path"); got != wantPaths[i] {
			t.Errorf("query[%d] path = %q, want %q", i, got, wantPaths[i])
		}
		if got := q.Get("$format"); got != "json" {
			t.Errorf("query[%d] $format = %q, want json", i, got)
		}
		if got := q.Get("includeContent"); got != "true" {
			t.Errorf("query[%d] includeContent = %q, want true", i, got)
		}
		if got := q.Get("api-version"); got != "7.1" {
			t.Errorf("query[%d] api-version = %q, want 7.1", i, got)
		}
	}
}

// --- intake-channel ---

func TestCollect_IntakeChannel_EmailMatch_VerifiedPass(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), contentResponse("Contact security@example.com to report a vulnerability."))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[intakeChannelID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("intake-channel = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}
}

func TestCollect_IntakeChannel_URLMatch_VerifiedPass(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), contentResponse("Report at https://example.com/security"))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[intakeChannelID]
	if got.Status != model.StatusVerifiedPass {
		t.Errorf("intake-channel = %q, want verified-pass; reason=%q", got.Status, got.Reason)
	}
}

func TestCollect_IntakeChannel_NoSignal_Partial(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), contentResponse("We take security seriously."))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[intakeChannelID]
	if got.Status != model.StatusPartial {
		t.Errorf("intake-channel = %q, want partial; reason=%q", got.Status, got.Reason)
	}
}

func TestCollect_IntakeChannel_NoSecurityMD_VerifiedFail(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), notFoundResponse())

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[intakeChannelID]
	if got.Status != model.StatusVerifiedFail {
		t.Errorf("intake-channel = %q, want verified-fail; reason=%q", got.Status, got.Reason)
	}
}

// --- private-reporting ---

// TestCollect_PrivateReporting_AlwaysNotCheckableNoAPICall proves this
// check's own result carries zero provenance and the fixed reason
// regardless of what security-md/intake-channel resolved for the same
// repo — it makes no API call of its own at all.
func TestCollect_PrivateReporting_AlwaysNotCheckableNoAPICall(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), contentResponse("security@example.com"))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[privateReportingID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("private-reporting = %q, want not-checkable", got.Status)
	}
	if len(got.Provenance) != 0 {
		t.Errorf("private-reporting Provenance = %v, want empty (no API call)", got.Provenance)
	}
	if got.Provenance == nil {
		t.Error("private-reporting Provenance is nil, want a non-nil empty slice (a nil Provenance marshals to JSON null and fails the evidence-pack schema's required array type)")
	}
}

// --- security-policy-org ---

// TestCollect_SecurityPolicyOrg_AlwaysNotCheckableNoAPICall uses a
// completely empty adofixture.Transport (no repos in scope either) — if
// checkSecurityPolicyOrg ever made a call, this test would fail with a
// wrapped adofixture.ErrNoFixture-derived error instead of the fixed
// not-checkable result asserted below.
func TestCollect_SecurityPolicyOrg_AlwaysNotCheckableNoAPICall(t *testing.T) {
	fx := adofixture.New()
	c := newCollector(fx)

	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[securityPolicyOrgID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("security-policy-org = %q, want not-checkable", got.Status)
	}
	if !contains(got.Reason, "org-wide-default") {
		t.Errorf("Reason = %q, want it to explain the org-wide-default mechanism doesn't exist", got.Reason)
	}
	if got.Scope.Repo != "" {
		t.Errorf("security-policy-org Scope.Repo = %q, want empty (org-level, not per-repo)", got.Scope.Repo)
	}
	if len(got.Provenance) != 0 {
		t.Errorf("security-policy-org Provenance = %v, want empty (no API call)", got.Provenance)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- cancellation ---

func TestCollect_PreCanceledContextProducesNotCheckableNotPanic(t *testing.T) {
	fx := adofixture.New()
	c := newCollector(fx)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := c.Collect(ctx, collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[securityMDID]
	if got.Status != model.StatusNotCheckable {
		t.Errorf("security-md = %q, want not-checkable for a pre-canceled context", got.Status)
	}
}

// TestCollect_PreCanceledContext_PrivateReportingKeepsFixedReason is the
// regression case found in review: canceling the context must not
// override privateReporting's own fixed, evidence-free reason with a
// generic "scan canceled" one — it never depended on ctx or any API call
// in the first place, in the canceled path any more than the normal one,
// so its result here must be byte-identical to the normal (non-canceled)
// result computed directly.
func TestCollect_PreCanceledContext_PrivateReportingKeepsFixedReason(t *testing.T) {
	fx := adofixture.New()
	c := newCollector(fx)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := c.Collect(ctx, collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)[privateReportingID]
	want := checkPrivateReporting(testOrg, testRepo)
	if got.Reason != want.Reason {
		t.Errorf("private-reporting Reason (canceled ctx) = %q, want the fixed reason %q unchanged by cancellation", got.Reason, want.Reason)
	}
	if got.Status != model.StatusNotCheckable {
		t.Errorf("private-reporting = %q, want not-checkable", got.Status)
	}
}

// --- full-Collect wiring / registry completeness ---

func TestCollect_AllFourChecksReturned(t *testing.T) {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), contentResponse("security@example.com"))

	c := newCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject, Repos: []string{testRepo}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != len(checkIDs) {
		t.Fatalf("Collect returned %d results, want %d", len(results), len(checkIDs))
	}
	m := byID(results)
	for _, id := range checkIDs {
		if _, ok := m[id]; !ok {
			t.Errorf("Collect result missing check %s", id)
		}
	}
}

func TestChecksRegistered(t *testing.T) {
	for _, id := range checkIDs {
		meta, ok := collect.LookupPlatform("azuredevops", id)
		if !ok {
			t.Errorf("check %s not registered under platform azuredevops", id)
			continue
		}
		if meta.Collector != collectorID {
			t.Errorf("%s Collector = %q, want %q", id, meta.Collector, collectorID)
		}
		if meta.TokenScope == "" {
			t.Errorf("%s TokenScope is empty", id)
		}
	}
}

var checksWithNoEndpoint = map[string]bool{
	privateReportingID:  true,
	securityPolicyOrgID: true,
}

var checkWantStatuses = map[string][]model.Status{
	securityMDID:        {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusNotCheckable},
	intakeChannelID:     {model.StatusVerifiedPass, model.StatusPartial, model.StatusVerifiedFail, model.StatusNotCheckable},
	privateReportingID:  {model.StatusNotCheckable},
	securityPolicyOrgID: {model.StatusNotCheckable},
}

var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) dev\.azure\.com/`)

// TestCollect_RegisteredMetadataCompleteForChecksReference mirrors the
// GitHub twin's identical test (see its own doc comment for the full
// rationale): exact Rubric key-set equality per check, GET/HEAD-only
// Endpoints enforcing ADR-0004, orphaned-key detection, and the
// Endpoints-non-empty exemption for the two permanently-evidence-free
// checks.
func TestCollect_RegisteredMetadataCompleteForChecksReference(t *testing.T) {
	if len(checkRubrics) != len(checkTitles) {
		t.Errorf("checkRubrics has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRubrics), len(checkTitles))
	}
	if len(checkEndpoints) != len(checkTitles) {
		t.Errorf("checkEndpoints has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkEndpoints), len(checkTitles))
	}

	for id := range checkTitles {
		meta, ok := collect.LookupPlatform("azuredevops", id)
		if !ok {
			t.Fatalf("check %q not found in the collect.CheckMeta registry under platform azuredevops", id)
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

		if len(meta.Endpoints) == 0 && !checksWithNoEndpoint[id] {
			t.Errorf("%s: Endpoints is empty, want at least one (or add it to checksWithNoEndpoint with a reason)", id)
		}
		if len(meta.Endpoints) > 0 && checksWithNoEndpoint[id] {
			t.Errorf("%s: checksWithNoEndpoint says this check should have zero Endpoints, but it has %v", id, meta.Endpoints)
		}
		for _, e := range meta.Endpoints {
			if !endpointVerbRE.MatchString(e) {
				t.Errorf("%s: Endpoints entry %q isn't GET/HEAD against dev.azure.com — this project is read-only forever (ADR-0004)", id, e)
			}
		}

		if meta.FixtureRef == "" {
			t.Errorf("%s: FixtureRef is empty", id)
		}
	}
}

// queryCapturingTransport records the query parameters of every request in
// call order — mirroring pipelinehistory's/auditlogging's identical helper,
// but a slice (not a map keyed by path) since the two SECURITY.md
// candidates share the same URL path and are distinguished only by their
// query, not their path.
type queryCapturingTransport struct {
	base    http.RoundTripper
	queries []url.Values
}

func (c *queryCapturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.queries = append(c.queries, req.URL.Query())
	return c.base.RoundTrip(req)
}

// rubricState is one fixture world for TestRubricsMatchObservedBehaviour.
// items is the response sequence Items - Get serves as resolveSecurityMD
// walks candidatePaths (both candidates hit the identical URL path and
// differ only in the "path" query parameter, so order is the only way to
// distinguish them — see TestCollect_SecurityMD_FallbackHit_VerifiedPass).
type rubricState struct {
	name  string
	items []adofixture.Response
	want  map[string]model.Status
}

func (st rubricState) fixture() *adofixture.Transport {
	fx := adofixture.New()
	fx.SetSequence("GET", azuredevops.HostCore, itemsPath(testProject, testRepo), st.items...)
	return fx
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// Four states reach every status ADO C10 can emit. private-reporting and
// security-policy-org make no API call and are not-checkable unconditionally
// (Azure DevOps has neither feature), so no fixture can move them; the guard's
// documented-but-unreachable direction is what pins that.
//
// security-md and intake-channel are the conflated pair here, and genuinely
// so: they are computed from ONE resolveSecurityMD call, sharing its error and
// its Found flag, so three of the four states below necessarily move them in
// lockstep. State 2 is the one that separates them — a SECURITY.md that
// resolves but says nothing actionable — and without it the two checks would
// agree in every state despite reading different fields of the same struct.
//
// That separation is verified by injection, not assumed. Two mutations, and
// it takes states 1 and 2 TOGETHER to catch them — either state alone leaves
// one of the two undetected:
//
//   - running findIntakeChannelMatches over resolved.Path instead of
//     resolved.Content is caught by state 1: the path "/SECURITY.md" carries
//     no email or URL, so the pass becomes a partial and intake-channel's
//     verified-pass leaves the matrix.
//   - treating a resolved-but-vague file as a pass — dropping the
//     len(matches) == 0 branch — is caught by state 2: it becomes a
//     verified-pass and partial leaves the matrix.
//
// State 2 also serves the /docs/ fallback: its first response 404s, so the
// file it resolves is the second candidate, not the first.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	states := []rubricState{
		{
			name:  "SECURITY.md at the repo root advertising an email",
			items: []adofixture.Response{contentResponse("Report vulnerabilities to security@example.com")},
			want: map[string]model.Status{
				securityMDID:        model.StatusVerifiedPass,
				intakeChannelID:     model.StatusVerifiedPass,
				privateReportingID:  model.StatusNotCheckable,
				securityPolicyOrgID: model.StatusNotCheckable,
			},
		},
		{
			// The separating state: the file resolves (via the docs/ fallback)
			// so security-md passes, but it carries no actionable channel, so
			// intake-channel caps at partial. The only state where these two
			// disagree.
			name: "SECURITY.md resolves via the docs/ fallback but names no channel",
			items: []adofixture.Response{
				notFoundResponse(),
				contentResponse("We take security seriously and review all reports carefully."),
			},
			want: map[string]model.Status{
				securityMDID:        model.StatusVerifiedPass,
				intakeChannelID:     model.StatusPartial,
				privateReportingID:  model.StatusNotCheckable,
				securityPolicyOrgID: model.StatusNotCheckable,
			},
		},
		{
			// Both candidates 404: a confirmed absence, not a gap — which is
			// why both checks fail rather than degrading.
			name:  "no SECURITY.md at either candidate path",
			items: []adofixture.Response{notFoundResponse(), notFoundResponse()},
			want: map[string]model.Status{
				securityMDID:        model.StatusVerifiedFail,
				intakeChannelID:     model.StatusVerifiedFail,
				privateReportingID:  model.StatusNotCheckable,
				securityPolicyOrgID: model.StatusNotCheckable,
			},
		},
		{
			// A 2xx whose shape resolveSecurityMD refuses to trust as a read
			// file. Distinct from a 404: the resolve itself errored, so both
			// dependent checks degrade rather than reporting an absence they
			// did not establish.
			name:  "items - get returns an untrustworthy shape",
			items: []adofixture.Response{contentOmittedResponse()},
			want: map[string]model.Status{
				securityMDID:        model.StatusNotCheckable,
				intakeChannelID:     model.StatusNotCheckable,
				privateReportingID:  model.StatusNotCheckable,
				securityPolicyOrgID: model.StatusNotCheckable,
			},
		},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			results, err := newCollector(st.fixture()).Collect(context.Background(), collect.Scope{
				Org: testOrg, Project: testProject, Repos: []string{testRepo},
			})
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
			// Compared whole, in both directions: a missing key is as much a
			// defect as a wrong one, and a row count would show neither.
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

	collecttest.AssertRubricsMatchObservedBehaviour(t, "azuredevops", collectorID, all)
}
