package orgsecurity

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/adofixture"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const testOrg = "attestward-demo"

func usersPath() string    { return "/" + testOrg + "/_apis/graph/users" }
func projectsPath() string { return "/" + testOrg + "/_apis/projects" }

// newTestCollector wires a Collector against fx via
// azuredevops.NewClientForTest — the exported cross-package testing seam
// that package's own doc comment describes, reusing the real
// auth+provenance+rate-limit chain unmodified (the same pattern
// pipelinehistory's tests use).
func newTestCollector(fx http.RoundTripper) *Collector {
	client := azuredevops.NewClientForTest(testOrg, "ado-test-pat", fx)
	return New(client)
}

func resultByID(results []model.CheckResult, id string) model.CheckResult {
	for _, r := range results {
		if r.CheckID == id {
			return r
		}
	}
	return model.CheckResult{}
}

func onePrivateProjectFixture(fx *adofixture.Transport) *adofixture.Transport {
	return fx.Set("GET", azuredevops.HostCore, projectsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{
				{"name": "internal-project", "visibility": "private"},
			},
		},
	})
}

// TestCollect_MSAPresent_2FAFails covers the msa-present rubric line: any
// msa identity is a definitive verified-fail, never averaged away by
// coexisting aad identities.
func TestCollect_MSAPresent_2FAFails(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 2,
			"value": []map[string]any{
				{"subjectKind": "user", "origin": "aad"},
				{"subjectKind": "user", "origin": "msa"},
			},
		},
	})
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}

	twoFA := resultByID(results, id2FARequired)
	if twoFA.Status != model.StatusVerifiedFail {
		t.Errorf("2fa-required status = %q, want verified-fail; reason=%q", twoFA.Status, twoFA.Reason)
	}
	if twoFA.Facts["aad_user_count"] != 1 || twoFA.Facts["msa_user_count"] != 1 {
		t.Errorf("2fa-required Facts = %v, want aad_user_count=1, msa_user_count=1", twoFA.Facts)
	}

	withoutTFA := resultByID(results, idMembersWithout2FA)
	if withoutTFA.Status != model.StatusNotCheckable {
		t.Errorf("members-without-2fa status = %q, want not-checkable", withoutTFA.Status)
	}
	if withoutTFA.Facts["msa_user_count"] != 1 {
		t.Errorf("members-without-2fa Facts[msa_user_count] = %v, want 1 (borrowed from the shared Graph fetch)", withoutTFA.Facts["msa_user_count"])
	}
}

// TestCollect_AllAAD_2FAPartial covers the all-aad rubric line: never
// verified-pass, even when every identity is Entra-backed — see the
// package doc comment for why.
func TestCollect_AllAAD_2FAPartial(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 2,
			"value": []map[string]any{
				{"subjectKind": "user", "origin": "aad"},
				{"subjectKind": "user", "origin": "aad"},
			},
		},
	})
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twoFA := resultByID(results, id2FARequired)
	if twoFA.Status != model.StatusPartial {
		t.Errorf("2fa-required status = %q, want partial; reason=%q", twoFA.Status, twoFA.Reason)
	}
	if twoFA.Facts["aad_user_count"] != 2 || twoFA.Facts["msa_user_count"] != 0 {
		t.Errorf("2fa-required Facts = %v, want aad_user_count=2, msa_user_count=0", twoFA.Facts)
	}

	// Never verified-pass anywhere in the result set for this check — the
	// deliberate under-claim the package doc comment describes.
	for _, r := range results {
		if r.CheckID == id2FARequired && r.Status == model.StatusVerifiedPass {
			t.Error("2fa-required reached verified-pass — this check must never claim full pass (epic #34 open decision 3)")
		}
	}
}

// TestCollect_ServicePrincipalsAndGroupsExcluded proves subjectKind values
// other than "user" (service principals, groups) never contribute to
// aad_user_count/msa_user_count — issue #150's literal spec: "svc/imp
// excluded" — AND that a REAL subjectKind=="user"/origin=="vsts" build-
// service identity (Azure DevOps' own service accounts arrive this way,
// per Microsoft's documented sample response — a servicePrincipal/group
// subjectKind alone does not cover this case) lands in
// vsts_service_identity_count, not aad/msa/other_origin_user_count. This
// doubles as the regression test for the review finding on this PR: the
// fix for unrecognized origins (see
// TestCollect_UnrecognizedOriginForcesNotCheckable below) must not
// overcorrect by also treating a genuinely-service vsts identity as an
// unclassifiable human one.
func TestCollect_ServicePrincipalsAndGroupsExcluded(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 5,
			"value": []map[string]any{
				{"subjectKind": "user", "origin": "aad"},
				{"subjectKind": "user", "origin": "vsts"},
				{"subjectKind": "servicePrincipal", "origin": "aad"},
				{"subjectKind": "group", "origin": "vsts"},
				{"subjectKind": "aggregate", "origin": "aad"},
			},
		},
	})
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twoFA := resultByID(results, id2FARequired)
	if twoFA.Facts["aad_user_count"] != 1 {
		t.Errorf("aad_user_count = %v, want 1 (only the single subjectKind==user/origin==aad entry counted)", twoFA.Facts["aad_user_count"])
	}
	if twoFA.Facts["msa_user_count"] != 0 {
		t.Errorf("msa_user_count = %v, want 0", twoFA.Facts["msa_user_count"])
	}
	if twoFA.Facts["vsts_service_identity_count"] != 1 {
		t.Errorf("vsts_service_identity_count = %v, want 1 (the real subjectKind==user/origin==vsts build-service identity)", twoFA.Facts["vsts_service_identity_count"])
	}
	if twoFA.Facts["other_origin_user_count"] != 0 {
		t.Errorf("other_origin_user_count = %v, want 0 — the vsts service identity must not be counted as an unclassifiable human", twoFA.Facts["other_origin_user_count"])
	}
	if twoFA.Status != model.StatusPartial {
		t.Errorf("2fa-required status = %q, want partial (the one real human user is aad-only; the vsts identity must not force not-checkable)", twoFA.Status)
	}
}

// TestCollect_UnrecognizedOriginForcesNotCheckable is the regression test
// for this PR's review finding: an org with a human identity whose origin
// this tool doesn't recognize (e.g. "ghb", GitHub-linked accounts — a real
// ADO sign-up path) must never round up to a vacuous partial claim just
// because zero identities are origin=="msa". It has to report
// not-checkable and name what it couldn't classify.
func TestCollect_UnrecognizedOriginForcesNotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 3,
			"value": []map[string]any{
				{"subjectKind": "user", "origin": "aad"},
				{"subjectKind": "user", "origin": "aad"},
				{"subjectKind": "user", "origin": "ghb"},
			},
		},
	})
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twoFA := resultByID(results, id2FARequired)
	if twoFA.Status != model.StatusNotCheckable {
		t.Errorf("2fa-required status = %q, want not-checkable (an unrecognized origin must never round up to partial); reason=%q", twoFA.Status, twoFA.Reason)
	}
	if twoFA.Facts["aad_user_count"] != 2 {
		t.Errorf("aad_user_count = %v, want 2", twoFA.Facts["aad_user_count"])
	}
	if twoFA.Facts["other_origin_user_count"] != 1 {
		t.Errorf("other_origin_user_count = %v, want 1", twoFA.Facts["other_origin_user_count"])
	}
	if !containsFold(twoFA.Reason, "ghb") {
		t.Errorf("2fa-required reason = %q, want it to name the unrecognized origin (ghb)", twoFA.Reason)
	}
}

// TestCollect_NoRecognizedHumanIdentities_NotCheckable covers an org where
// every Graph subject is excluded from human classification entirely
// (service principals and vsts-origin service identities) — zero
// subjectKind=="user" entries have a recognized human origin (aad/msa) at
// all, so there is nothing to evaluate. Also not-checkable, not a vacuous
// partial over an empty count.
func TestCollect_NoRecognizedHumanIdentities_NotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 2,
			"value": []map[string]any{
				{"subjectKind": "user", "origin": "vsts"},
				{"subjectKind": "servicePrincipal", "origin": "aad"},
			},
		},
	})
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twoFA := resultByID(results, id2FARequired)
	if twoFA.Status != model.StatusNotCheckable {
		t.Errorf("2fa-required status = %q, want not-checkable (zero recognized human identities); reason=%q", twoFA.Status, twoFA.Reason)
	}
	if twoFA.Facts["aad_user_count"] != 0 || twoFA.Facts["msa_user_count"] != 0 || twoFA.Facts["other_origin_user_count"] != 0 {
		t.Errorf("2fa-required Facts = %v, want aad/msa/other_origin counts all zero", twoFA.Facts)
	}
	if twoFA.Facts["vsts_service_identity_count"] != 1 {
		t.Errorf("vsts_service_identity_count = %v, want 1", twoFA.Facts["vsts_service_identity_count"])
	}
}

// TestCollect_GraphAPIFailure_AllDependentChecksNotCheckable covers the
// api-fail rubric line: a 403 reading the Graph Users list makes
// 2fa-required not-checkable, and members-without-2fa's borrowed
// msa_user_count Fact is absent (not zero — there is no evidence for it at
// all) since it has nothing to borrow.
func TestCollect_GraphAPIFailure_AllDependentChecksNotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusForbidden,
		Body:   map[string]any{"message": "Forbidden"},
	})
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twoFA := resultByID(results, id2FARequired)
	if twoFA.Status != model.StatusNotCheckable {
		t.Errorf("2fa-required status = %q, want not-checkable", twoFA.Status)
	}
	if len(twoFA.Provenance) == 0 {
		t.Error("2fa-required has no provenance, want the failed Graph Users call's entry attached")
	}
	if !containsFold(twoFA.Reason, "permission") {
		t.Errorf("2fa-required reason = %q, want it to mention the permission problem", twoFA.Reason)
	}

	withoutTFA := resultByID(results, idMembersWithout2FA)
	if withoutTFA.Status != model.StatusNotCheckable {
		t.Errorf("members-without-2fa status = %q, want not-checkable", withoutTFA.Status)
	}
	if _, ok := withoutTFA.Facts["msa_user_count"]; ok {
		t.Errorf("members-without-2fa Facts has msa_user_count = %v, want it absent — the Graph fetch it borrows from failed", withoutTFA.Facts["msa_user_count"])
	}
	if withoutTFA.Provenance == nil {
		t.Error("members-without-2fa Provenance is nil, want a non-nil (possibly empty) slice — a nil Provenance marshals to JSON null and fails the evidence-pack schema")
	}
}

// TestCollect_GraphPaginatesViaContinuationToken proves the collector
// consumes GetJSON's X-MS-ContinuationToken pagination to exhaustion,
// counting every page's identities and recording one provenance entry per
// page.
func TestCollect_GraphPaginatesViaContinuationToken(t *testing.T) {
	fx := adofixture.New().SetSequence("GET", azuredevops.HostGraph, usersPath(),
		adofixture.Response{
			Status:  http.StatusOK,
			Headers: map[string]string{"X-MS-ContinuationToken": "page-2-token"},
			Body: map[string]any{
				"count": 1,
				"value": []map[string]any{{"subjectKind": "user", "origin": "msa"}},
			},
		},
		adofixture.Response{
			Status: http.StatusOK,
			Body: map[string]any{
				"count": 1,
				"value": []map[string]any{{"subjectKind": "user", "origin": "aad"}},
			},
		},
	)
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twoFA := resultByID(results, id2FARequired)
	if twoFA.Facts["aad_user_count"] != 1 || twoFA.Facts["msa_user_count"] != 1 {
		t.Errorf("Facts = %v, want aad_user_count=1, msa_user_count=1 (both pages counted)", twoFA.Facts)
	}
	if twoFA.Status != model.StatusVerifiedFail {
		t.Errorf("2fa-required status = %q, want verified-fail", twoFA.Status)
	}
	if len(twoFA.Provenance) != 2 {
		t.Errorf("len(Provenance) = %d, want 2 (one per page)", len(twoFA.Provenance))
	}
}

// TestCollect_PublicProjectPresent_VerifiedFail covers the
// public-project-present rubric line, and confirms Facts record the
// project's name — issue #150 explicitly allows this (unlike member
// identities, project names are never redacted).
func TestCollect_PublicProjectPresent_VerifiedFail(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": 0, "value": []map[string]any{}},
	})
	fx.Set("GET", azuredevops.HostCore, projectsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 2,
			"value": []map[string]any{
				{"name": "leaky-project", "visibility": "public"},
				{"name": "internal-project", "visibility": "private"},
			},
		},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	canCreate := resultByID(results, idMembersCanCreatePublic)
	if canCreate.Status != model.StatusVerifiedFail {
		t.Errorf("members-can-create-public status = %q, want verified-fail; reason=%q", canCreate.Status, canCreate.Reason)
	}
	if canCreate.Facts["public_project_count"] != 1 {
		t.Errorf("public_project_count = %v, want 1", canCreate.Facts["public_project_count"])
	}
	names, _ := canCreate.Facts["public_project_names"].([]string)
	if len(names) != 1 || names[0] != "leaky-project" {
		t.Errorf("public_project_names = %v, want [leaky-project]", canCreate.Facts["public_project_names"])
	}
}

// TestCollect_NoPublicProjects_NotCheckable covers the
// public-project-absent rubric line: zero public projects is not-checkable
// (policy-off vs policy-on-but-unused ambiguity), never verified-pass.
func TestCollect_NoPublicProjects_NotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": 0, "value": []map[string]any{}},
	})
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	canCreate := resultByID(results, idMembersCanCreatePublic)
	if canCreate.Status != model.StatusNotCheckable {
		t.Errorf("members-can-create-public status = %q, want not-checkable; reason=%q", canCreate.Status, canCreate.Reason)
	}
	if canCreate.Facts["public_project_count"] != 0 {
		t.Errorf("public_project_count = %v, want 0", canCreate.Facts["public_project_count"])
	}
}

// TestCollect_ProjectsAPIFailure_NotCheckable covers the projects-list
// api-fail rubric line, distinct from the zero-public-projects case above
// (different Reason, same Status).
func TestCollect_ProjectsAPIFailure_NotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": 0, "value": []map[string]any{}},
	})
	fx.Set("GET", azuredevops.HostCore, projectsPath(), adofixture.Response{
		Status: http.StatusNotFound,
		Body:   map[string]any{"message": "Not Found"},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	canCreate := resultByID(results, idMembersCanCreatePublic)
	if canCreate.Status != model.StatusNotCheckable {
		t.Errorf("members-can-create-public status = %q, want not-checkable", canCreate.Status)
	}
	if !containsFold(canCreate.Reason, "not found") {
		t.Errorf("members-can-create-public reason = %q, want it to mention the 404", canCreate.Reason)
	}
	if len(canCreate.Provenance) == 0 {
		t.Error("members-can-create-public has no provenance, want the failed projects call's entry attached")
	}
}

// TestCollect_DefaultRepoPermissionAlwaysNotCheckable proves
// default-repo-permission never varies with fixture data at all — no API
// call backs it (see the package doc comment).
func TestCollect_DefaultRepoPermissionAlwaysNotCheckable(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 1,
			"value": []map[string]any{{"subjectKind": "user", "origin": "aad"}},
		},
	})
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	defaultPerm := resultByID(results, idDefaultRepoPermission)
	if defaultPerm.Status != model.StatusNotCheckable {
		t.Errorf("default-repo-permission status = %q, want not-checkable", defaultPerm.Status)
	}
	if defaultPerm.Provenance == nil {
		t.Error("default-repo-permission Provenance is nil, want a non-nil (possibly empty) slice")
	}
	if len(defaultPerm.Provenance) != 0 {
		t.Errorf("default-repo-permission Provenance = %v, want empty — no API call backs this check at all", defaultPerm.Provenance)
	}
}

// TestCollect_NeverLeaksIdentityDetails is the privacy rule from the issue
// ("Facts carry counts, never user names"), confirmed the same way the
// GitHub twin's equivalent test is: only the documented count keys ever
// appear in Facts for the two identity-derived checks.
func TestCollect_NeverLeaksIdentityDetails(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body: map[string]any{
			"count": 2,
			"value": []map[string]any{
				{"subjectKind": "user", "origin": "msa", "displayName": "should-never-appear"},
				{"subjectKind": "user", "origin": "aad", "displayName": "also-should-never-appear"},
			},
		},
	})
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	twoFA := resultByID(results, id2FARequired)
	if len(twoFA.Facts) != 4 {
		t.Fatalf("2fa-required Facts = %v, want exactly {aad_user_count, msa_user_count, vsts_service_identity_count, other_origin_user_count}", twoFA.Facts)
	}

	withoutTFA := resultByID(results, idMembersWithout2FA)
	if len(withoutTFA.Facts) != 1 {
		t.Fatalf("members-without-2fa Facts = %v, want exactly {msa_user_count}", withoutTFA.Facts)
	}
}

// TestCollect_ProvenanceNeverNil proves every one of the four results
// carries a non-nil Provenance slice, whether or not an API call actually
// backs that specific check — the same evidence-pack schema invariant the
// GitHub twin's tests enforce.
func TestCollect_ProvenanceNeverNil(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostGraph, usersPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": 0, "value": []map[string]any{}},
	})
	onePrivateProjectFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}
	for _, r := range results {
		if r.Provenance == nil {
			t.Errorf("%s Provenance is nil, want a non-nil (possibly empty) slice", r.CheckID)
		}
	}
}

// TestCollect_RegistersAllFourChecks proves the init()-registered CheckMeta
// entries match the four check IDs Collect() actually produces, under the
// azuredevops platform specifically.
func TestCollect_RegistersAllFourChecks(t *testing.T) {
	for id := range checkTitles {
		if _, ok := collect.LookupPlatform("azuredevops", id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry for platform azuredevops", id)
		}
	}
	if len(checkTitles) != 4 {
		t.Fatalf("len(checkTitles) = %d, want 4", len(checkTitles))
	}
}

// TestCollect_CollectorIDMatchesGitHubTwin proves this package registers
// under the exact same Collector string as
// internal/collect/github/orgsecurity — collect.Register panics on a
// mismatch (registry.go), but this test pins the expectation directly so a
// future rename here is caught by this package's own tests, not just a
// panic at some other package's init() time.
func TestCollect_CollectorIDMatchesGitHubTwin(t *testing.T) {
	if collectorID != "C01.org-security" {
		t.Errorf("collectorID = %q, want \"C01.org-security\" (must match the GitHub twin's exactly)", collectorID)
	}
}

// checksWithNoEndpoint are the checks whose Endpoints is legitimately
// empty: neither makes any API call at all, so nothing backs their
// (permanently fixed) not-checkable status — see checkRubrics' own doc
// comment, and internal/collect/github/auditlogging's identical pattern
// for C09.audit.log-streaming/retention-awareness.
var checksWithNoEndpoint = map[string]bool{
	idMembersWithout2FA:     true,
	idDefaultRepoPermission: true,
}

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce — see orgsecurity's GitHub twin for the
// full rationale of why this can't be derived structurally. Two of these
// four checks never reach verified-pass (see the package doc comment); the
// other two never reach anything but not-checkable.
var checkWantStatuses = map[string][]model.Status{
	id2FARequired:            {model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	idMembersWithout2FA:      {model.StatusNotCheckable},
	idDefaultRepoPermission:  {model.StatusNotCheckable},
	idMembersCanCreatePublic: {model.StatusVerifiedFail, model.StatusNotCheckable},
}

// endpointVerbRE matches this package's Endpoints convention: verb, then
// host, then path (see checkEndpoints' own doc comment for why the host is
// included, unlike the GitHub twin's path-only strings) — restricted to the
// two hosts this collector actually calls (HostGraph, HostCore).
var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) (vssps\.dev\.azure\.com|dev\.azure\.com)/`)

// TestCollect_RegisteredMetadataCompleteForChecksReference mirrors the
// GitHub twin's test of the same name (see its own doc comment for the
// full rationale: exact Rubric key-set equality per check, GET/HEAD-only
// Endpoints enforcing ADR-0004, orphaned-key detection) — except the
// Endpoints-non-empty assertion, which this package's two
// permanently-evidence-free checks are deliberately exempt from (see
// checksWithNoEndpoint), the same exemption auditlogging's own copy of
// this test introduced for C09.
func TestCollect_RegisteredMetadataCompleteForChecksReference(t *testing.T) {
	if len(checkRubrics) != len(checkTitles) {
		t.Errorf("checkRubrics has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRubrics), len(checkTitles))
	}
	if len(checkEndpoints) != len(checkTitles) {
		t.Errorf("checkEndpoints has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkEndpoints), len(checkTitles))
	}
	if len(checkTokenScopes) != len(checkTitles) {
		t.Errorf("checkTokenScopes has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkTokenScopes), len(checkTitles))
	}
	if len(checkRemediations) != len(checkTitles) {
		t.Errorf("checkRemediations has %d entries, checkTitles has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRemediations), len(checkTitles))
	}

	for id := range checkTitles {
		meta, ok := collect.LookupPlatform("azuredevops", id)
		if !ok {
			t.Fatalf("check %q not found in the collect.CheckMeta registry", id)
		}
		if meta.Collector != collectorID {
			t.Errorf("%s Collector = %q, want %q", id, meta.Collector, collectorID)
		}
		if meta.TokenScope == "" {
			t.Errorf("%s TokenScope is empty", id)
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
				t.Errorf("%s: Endpoints entry %q isn't GET/HEAD against a known ADO host — this project is read-only forever (ADR-0004)", id, e)
			}
		}

		if meta.FixtureRef == "" {
			t.Errorf("%s: FixtureRef is empty", id)
		}
	}
}

// containsFold is a case-insensitive substring check for asserting on
// Reason text without pinning its exact casing.
func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
