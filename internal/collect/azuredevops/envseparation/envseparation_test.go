package envseparation

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops/adofixture"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const (
	testOrg     = "attestward-demo"
	testProject = "demo-project"
)

func environmentsPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/distributedtask/environments"
}
func checksPath() string {
	return "/" + testOrg + "/" + testProject + "/_apis/pipelines/checks/configurations"
}

// newTestCollector wires a Collector against fx via
// azuredevops.NewClientForTest — the same cross-package testing seam
// orgsecurity's/repoprotection's own tests use.
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

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func environmentsFixture(fx *adofixture.Transport, envs ...map[string]any) *adofixture.Transport {
	return fx.Set("GET", azuredevops.HostCore, environmentsPath(), adofixture.Response{
		Status: http.StatusOK,
		Body:   map[string]any{"count": len(envs), "value": envs},
	})
}

// checksFixtureSequence registers one checks-configurations response per
// production-like environment, served IN ORDER as fetchAllCheckConfigurations
// calls them — adofixture keys responses by "METHOD host path" only (query
// strings, including resourceId, aren't matched — see its own doc
// comment), so distinguishing per-environment responses on the identical
// checksPath() requires SetSequence, relying on fetchAllCheckConfigurations
// iterating prodEnvs in the same order environmentsFixture's own envs
// arguments were given (Go preserves JSON array order through unmarshal).
func checksFixtureSequence(fx *adofixture.Transport, perEnvChecks ...[]map[string]any) *adofixture.Transport {
	responses := make([]adofixture.Response, len(perEnvChecks))
	for i, checks := range perEnvChecks {
		responses[i] = adofixture.Response{
			Status: http.StatusOK,
			Body:   map[string]any{"count": len(checks), "value": checks},
		}
	}
	return fx.SetSequence("GET", azuredevops.HostCore, checksPath(), responses...)
}

func approvalCheck(disabled bool) map[string]any {
	return map[string]any{
		"id": 1, "isDisabled": disabled,
		"type": map[string]any{"id": approvalCheckTypeID, "name": "Approval"},
	}
}

func taskCheckWithAllowedBranches(allowedBranches string, disabled bool) map[string]any {
	return map[string]any{
		"id": 2, "isDisabled": disabled,
		"type":     map[string]any{"id": taskCheckTypeID, "name": "Task Check"},
		"settings": map[string]any{"inputs": map[string]any{"allowedBranches": allowedBranches}},
	}
}

func TestCollect_NoEnvironmentsAllNotCheckable(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
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
		if r.Scope.Repo != "" {
			t.Errorf("%s Scope.Repo = %q, want empty — C03 is project-scoped, never repo-scoped", r.CheckID, r.Scope.Repo)
		}
		if r.Scope.Project != testProject {
			t.Errorf("%s Scope.Project = %q, want %q", r.CheckID, r.Scope.Project, testProject)
		}
		if !containsFold(r.Reason, "no environments configured") {
			t.Errorf("%s Reason = %q, want it to mention no environments configured", r.CheckID, r.Reason)
		}
	}
}

func TestCollect_EnvsExistNoneProdLikeAllPartial(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx,
		map[string]any{"id": 1, "name": "staging"},
		map[string]any{"id": 2, "name": "dev"},
	)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusPartial {
			t.Errorf("%s status = %q, want partial (envs exist, none production-like)", r.CheckID, r.Status)
		}
		names, ok := r.Facts["all_environment_names"].([]string)
		if !ok || len(names) != 2 {
			t.Errorf("%s Facts[all_environment_names] = %v, want [staging dev]", r.CheckID, r.Facts["all_environment_names"])
		}
	}
}

func TestCollect_ProdEnvFullyProtectedAllPass(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx, map[string]any{"id": 1, "name": "production"})
	checksFixtureSequence(fx, []map[string]any{
		approvalCheck(false),
		taskCheckWithAllowedBranches("refs/heads/main", false),
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusVerifiedPass {
			t.Errorf("%s status = %q, want verified-pass; reason=%q", r.CheckID, r.Status, r.Reason)
		}
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance", r.CheckID)
		}
	}
}

func TestCollect_ProdEnvNoChecksAllRelevantChecksFail(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx, map[string]any{"id": 1, "name": "Production"})
	checksFixtureSequence(fx, []map[string]any{})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := resultByID(results, idExists).Status; got != model.StatusVerifiedPass {
		t.Errorf("exists status = %q, want verified-pass (a production-like env exists, case-insensitive match)", got)
	}
	for _, id := range []string{idProtectionRules, idRequiredReviewers, idBranchPolicy} {
		if got := resultByID(results, id).Status; got != model.StatusVerifiedFail {
			t.Errorf("%s status = %q, want verified-fail (env has no checks at all)", id, got)
		}
	}
}

// TestCollect_MultipleProdEnvsEveryOneMustPass proves each check requires
// EVERY production-like environment to satisfy a criterion, not just one.
func TestCollect_MultipleProdEnvsEveryOneMustPass(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx,
		map[string]any{"id": 1, "name": "production"},
		map[string]any{"id": 2, "name": "production-eu"},
	)
	checksFixtureSequence(fx,
		[]map[string]any{approvalCheck(false), taskCheckWithAllowedBranches("refs/heads/main", false)},
		[]map[string]any{},
	)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	pr := resultByID(results, idProtectionRules)
	if pr.Status != model.StatusVerifiedFail {
		t.Errorf("protection-rules status = %q, want verified-fail (production-eu has no checks)", pr.Status)
	}
	without, ok := pr.Facts["environments_without_checks"].([]string)
	if !ok || len(without) != 1 || without[0] != "production-eu" {
		t.Errorf("environments_without_checks = %v, want [production-eu]", pr.Facts["environments_without_checks"])
	}

	rr := resultByID(results, idRequiredReviewers)
	if rr.Status != model.StatusVerifiedFail {
		t.Errorf("required-reviewers status = %q, want verified-fail (production-eu has no Approval check)", rr.Status)
	}

	bp := resultByID(results, idBranchPolicy)
	if bp.Status != model.StatusVerifiedFail {
		t.Errorf("branch-policy status = %q, want verified-fail (production-eu has no Task Check)", bp.Status)
	}
}

func TestCollect_EnvironmentsAPIFailure_PermissionGated(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, environmentsPath(), adofixture.Response{
		Status: http.StatusForbidden,
		Body:   map[string]any{"message": "Forbidden"},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
		if len(r.Provenance) == 0 {
			t.Errorf("%s has no provenance, want the failed environments call's entry attached", r.CheckID)
		}
		if !containsFold(r.Reason, "permission") {
			t.Errorf("%s Reason = %q, want it to mention permission", r.CheckID, r.Reason)
		}
	}
}

func TestCollect_EnvironmentsAPIFailure_NotFound(t *testing.T) {
	fx := adofixture.New().Set("GET", azuredevops.HostCore, environmentsPath(), adofixture.Response{
		Status: http.StatusNotFound,
		Body:   map[string]any{"message": "Not Found"},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
		if !containsFold(r.Reason, "not found") {
			t.Errorf("%s Reason = %q, want it to mention not found", r.CheckID, r.Reason)
		}
	}
}

// TestCollect_ChecksConfigurationsAPIFailure_ExistsUnaffected is the
// regression test for the structural split in Collect: idExists only ever
// depends on the environments list, so a Check Configurations failure
// must never make it not-checkable — only the three checks-derived checks
// are affected.
func TestCollect_ChecksConfigurationsAPIFailure_ExistsUnaffected(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx, map[string]any{"id": 1, "name": "production"})
	fx.Set("GET", azuredevops.HostCore, checksPath(), adofixture.Response{
		Status: http.StatusForbidden,
		Body:   map[string]any{"message": "Forbidden"},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if got := resultByID(results, idExists).Status; got != model.StatusVerifiedPass {
		t.Errorf("exists status = %q, want verified-pass — a Check Configurations failure must never affect idExists", got)
	}
	for _, id := range []string{idProtectionRules, idRequiredReviewers, idBranchPolicy} {
		r := resultByID(results, id)
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if !containsFold(r.Reason, "permission") {
			t.Errorf("%s reason = %q, want it to mention permission", id, r.Reason)
		}
	}
}

func TestCollect_BranchPolicy_ConfiguredAllowedBranches_Pass(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx, map[string]any{"id": 1, "name": "production"})
	checksFixtureSequence(fx, []map[string]any{taskCheckWithAllowedBranches("refs/heads/main,refs/heads/release/*", false)})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	bp := resultByID(results, idBranchPolicy)
	if bp.Status != model.StatusVerifiedPass {
		t.Errorf("branch-policy = %q, want verified-pass; reason=%q", bp.Status, bp.Reason)
	}
}

// TestCollect_BranchPolicy_WildcardAllowedBranches_Ambiguous is the
// regression test for the review finding on this PR: resolveBranchPolicy
// used to reject only the literal whole-string "*", so
// "refs/heads/*"/"refs/*" (the task's other two documented no-restriction
// spellings) and a mixed list containing any one match-all entry
// ("refs/heads/main,*") were misread as a genuine restriction — a false
// verified-pass. Every one of these must fall to the conservative partial
// fallback instead, never a fabricated pass.
func TestCollect_BranchPolicy_WildcardAllowedBranches_Ambiguous(t *testing.T) {
	cases := []struct {
		name            string
		allowedBranches string
	}{
		{"bare asterisk", "*"},
		{"refs/heads/* spelling", "refs/heads/*"},
		{"refs/* spelling", "refs/*"},
		{"mixed list with one wildcard entry", "refs/heads/main,*"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := adofixture.New()
			environmentsFixture(fx, map[string]any{"id": 1, "name": "production"})
			checksFixtureSequence(fx, []map[string]any{taskCheckWithAllowedBranches(tc.allowedBranches, false)})

			c := newTestCollector(fx)
			results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			bp := resultByID(results, idBranchPolicy)
			if bp.Status != model.StatusPartial {
				t.Errorf("branch-policy(%q) = %q, want partial (a match-all entry anywhere in the list is vacuous); reason=%q", tc.allowedBranches, bp.Status, bp.Reason)
			}
		})
	}
}

// TestCollect_BranchPolicy_UnparseableSettings_Ambiguous is the regression
// test for the [fixture-verify] gap this package's own doc comment flags:
// a Task Check whose settings don't decode into taskCheckSettingsRaw at
// all must degrade to the issue #151-specified conservative partial, never
// error or silently guess.
func TestCollect_BranchPolicy_UnparseableSettings_Ambiguous(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx, map[string]any{"id": 1, "name": "production"})
	checksFixtureSequence(fx, []map[string]any{
		{
			"id": 3, "isDisabled": false,
			"type":     map[string]any{"id": taskCheckTypeID, "name": "Task Check"},
			"settings": "not-an-object",
		},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	bp := resultByID(results, idBranchPolicy)
	if bp.Status != model.StatusPartial {
		t.Errorf("branch-policy = %q, want partial (unparseable settings shape); reason=%q", bp.Status, bp.Reason)
	}
	if !containsFold(bp.Reason, "could not be interpreted") {
		t.Errorf("reason = %q, want issue #151's exact conservative-fallback wording", bp.Reason)
	}
}

// TestCollect_BranchPolicy_AbsentOutranksAmbiguous proves a definitive
// "no Task Check at all" on one environment reports verified-fail overall
// even when a different production-like environment is merely ambiguous —
// this collector never reports a status stronger than what the worst-off
// environment actually warrants.
func TestCollect_BranchPolicy_AbsentOutranksAmbiguous(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx,
		map[string]any{"id": 1, "name": "production"},
		map[string]any{"id": 2, "name": "production-eu"},
	)
	checksFixtureSequence(fx,
		[]map[string]any{taskCheckWithAllowedBranches("*", false)},
		[]map[string]any{},
	)

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	bp := resultByID(results, idBranchPolicy)
	if bp.Status != model.StatusVerifiedFail {
		t.Errorf("branch-policy = %q, want verified-fail (absent outranks ambiguous across environments); reason=%q", bp.Status, bp.Reason)
	}
}

// TestCollect_DisabledChecksDontCount proves isDisabled==true check
// configurations never satisfy protection-rules, required-reviewers, or
// branch-policy.
func TestCollect_DisabledChecksDontCount(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx, map[string]any{"id": 1, "name": "production"})
	checksFixtureSequence(fx, []map[string]any{
		approvalCheck(true),
		taskCheckWithAllowedBranches("refs/heads/main", true),
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, id := range []string{idProtectionRules, idRequiredReviewers, idBranchPolicy} {
		if got := resultByID(results, id).Status; got != model.StatusVerifiedFail {
			t.Errorf("%s status = %q, want verified-fail (disabled checks must not count)", id, got)
		}
	}
}

// TestCollect_ApprovalCheckTypeIDCaseInsensitive proves the type id
// comparison tolerates a server that doesn't match its own documented
// casing — the same hedge established elsewhere in this epic (see the
// package doc comment).
func TestCollect_ApprovalCheckTypeIDCaseInsensitive(t *testing.T) {
	fx := adofixture.New()
	environmentsFixture(fx, map[string]any{"id": 1, "name": "production"})
	checksFixtureSequence(fx, []map[string]any{
		{"id": 1, "isDisabled": false, "type": map[string]any{"id": strings.ToUpper(approvalCheckTypeID), "name": "Approval"}},
	})

	c := newTestCollector(fx)
	results, err := c.Collect(context.Background(), collect.Scope{Org: testOrg, Project: testProject})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	rr := resultByID(results, idRequiredReviewers)
	if rr.Status != model.StatusVerifiedPass {
		t.Errorf("required-reviewers = %q, want verified-pass (type id comparison must be case-insensitive); reason=%q", rr.Status, rr.Reason)
	}
}

func TestChecksRegistered(t *testing.T) {
	if len(checkIDs) != 4 {
		t.Fatalf("len(checkIDs) = %d, want 4", len(checkIDs))
	}
	for _, id := range checkIDs {
		if _, ok := collect.LookupPlatform("azuredevops", id); !ok {
			t.Errorf("check %q not found in the collect.CheckMeta registry for platform azuredevops", id)
		}
	}
}

// TestCollect_CollectorIDMatchesGitHubTwin proves this package registers
// under the exact same Collector string as
// internal/collect/github/envseparation — collect.Register panics on a
// mismatch (registry.go), but this test pins the expectation directly.
func TestCollect_CollectorIDMatchesGitHubTwin(t *testing.T) {
	if collectorID != "C03.env-separation" {
		t.Errorf("collectorID = %q, want \"C03.env-separation\" (must match the GitHub twin's exactly)", collectorID)
	}
}

// checkWantStatuses is a human-reviewed declaration of exactly which
// statuses each check can produce — see orgsecurity's own copy of this
// pattern for the full rationale. idExists can never produce
// verified-fail, mirroring its GitHub twin exactly.
var checkWantStatuses = map[string][]model.Status{
	idExists:            {model.StatusVerifiedPass, model.StatusPartial, model.StatusNotCheckable},
	idProtectionRules:   {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	idRequiredReviewers: {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
	idBranchPolicy:      {model.StatusVerifiedPass, model.StatusVerifiedFail, model.StatusPartial, model.StatusNotCheckable},
}

// endpointVerbRE matches this package's Endpoints convention: verb, host,
// path — see checkEndpoints' own doc comment.
var endpointVerbRE = regexp.MustCompile(`^(GET|HEAD) dev\.azure\.com/`)

// TestCollect_RegisteredMetadataCompleteForChecksReference mirrors
// orgsecurity's/repoprotection's test of the same name — see either's own
// doc comment for the full rationale.
func TestCollect_RegisteredMetadataCompleteForChecksReference(t *testing.T) {
	if len(checkRubrics) != len(checkIDs) {
		t.Errorf("checkRubrics has %d entries, checkIDs has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRubrics), len(checkIDs))
	}
	if len(checkEndpoints) != len(checkIDs) {
		t.Errorf("checkEndpoints has %d entries, checkIDs has %d — a typo'd/orphaned key won't otherwise be caught", len(checkEndpoints), len(checkIDs))
	}
	if len(checkTokenScopes) != len(checkIDs) {
		t.Errorf("checkTokenScopes has %d entries, checkIDs has %d — a typo'd/orphaned key won't otherwise be caught", len(checkTokenScopes), len(checkIDs))
	}
	if len(checkRemediations) != len(checkIDs) {
		t.Errorf("checkRemediations has %d entries, checkIDs has %d — a typo'd/orphaned key won't otherwise be caught", len(checkRemediations), len(checkIDs))
	}

	for _, id := range checkIDs {
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
			t.Fatalf("checkWantStatuses is missing an entry for %q", id)
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
				t.Errorf("%s: Rubric has an entry for status %q, but checkWantStatuses says this check can't produce it", id, s)
			}
		}

		if len(meta.Endpoints) == 0 {
			t.Errorf("%s: Endpoints is empty, want at least one", id)
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

// rubricState is one fixture world for TestRubricsMatchObservedBehaviour.
// envs is the Environments - List response; perEnvChecks is one Check
// Configurations - List response per PRODUCTION-LIKE environment, in the
// order fetchAllCheckConfigurations walks them; checksErr, when set, replaces
// the whole checks sequence with that one failing response.
type rubricState struct {
	name         string
	envs         adofixture.Response
	perEnvChecks [][]map[string]any
	checksErr    *adofixture.Response
	want         map[string]model.Status
}

func (st rubricState) fixture() *adofixture.Transport {
	fx := adofixture.New()
	fx.Set("GET", azuredevops.HostCore, environmentsPath(), st.envs)
	switch {
	case st.checksErr != nil:
		fx.Set("GET", azuredevops.HostCore, checksPath(), *st.checksErr)
	case st.perEnvChecks != nil:
		checksFixtureSequence(fx, st.perEnvChecks...)
	}
	return fx
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// Twelve states reach every status this collector can emit. env.exists has no
// verified-fail in its rubric at all — Collect computes it only after the
// environments list has already confirmed a production-like environment, so a
// "no such environment" world is partial or not-checkable, never a fail. The
// guard's both-directions comparison is what holds that: adding a
// verified-fail entry to its rubric would immediately be reported as
// documented-but-unreachable.
//
// Two conflation risks are real here and both are structural rather than
// hypothetical:
//
//  1. protection-rules, required-reviewers and branch-policy all read the SAME
//     per-environment check-configuration list, and differ only in which check
//     TYPE they look for and whether they read isDisabled. A matrix that varies
//     "does this environment have checks" moves all three in lockstep. States 2
//     and 3 split required-reviewers from branch-policy in opposite directions
//     (an Approval-only environment vs a Task-Check-only one); state 4 splits
//     protection-rules from BOTH with a check of a third type that neither of
//     them recognises; state 5 splits them again with no missing check at all —
//     the Approval check is present but disabled while the Task Check is live.
//
//  2. env.exists shares the environments response with the other three but
//     deliberately does NOT share their second call: Collect answers it from the
//     environments list alone, before Check Configurations - List is attempted.
//     State 12 is the only state that proves this — the checks call is denied and
//     env.exists still passes while the other three go not-checkable. A matrix
//     that only ever failed the environments list would move all four together
//     and never test the claim.
//
// Verified by mutation rather than assumed — see the commit message for which
// states caught which.
//
// Three of the four not-checkable/partial routes involve no transport failure
// whatsoever: state 9 has environments that simply do not look like production,
// state 10 has an empty (but successful) environments list, and state 12's
// environments call succeeds. Only state 11 is an actual API denial.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	envsOK := func(envs ...map[string]any) adofixture.Response {
		return adofixture.Response{
			Status: http.StatusOK,
			Body:   map[string]any{"count": len(envs), "value": envs},
		}
	}
	env := func(id int, name string) map[string]any {
		return map[string]any{"id": id, "name": name}
	}
	forbidden := adofixture.Response{Status: http.StatusForbidden, Body: map[string]any{"message": "denied"}}

	// businessHoursCheck is a real, enabled check of a type this collector
	// recognises as neither Approval nor Task Check — the "Business hours"
	// check named in idProtectionRules' own remediation text. It is what makes
	// state 4 a split rather than a blank: protection-rules counts any enabled
	// check, and the other two must not count this one.
	businessHoursCheck := map[string]any{
		"id": 3, "isDisabled": false,
		"type": map[string]any{"id": "7c6ecd7c-b1e0-4b6a-a5f0-4b1b6d5a1f2e", "name": "Business Hours"},
	}
	onlyProd := envsOK(env(11, "production"))

	states := []rubricState{
		{
			name: "one production environment with an Approval check and a Task Check restricting to main",
			envs: onlyProd,
			perEnvChecks: [][]map[string]any{{
				approvalCheck(false),
				taskCheckWithAllowedBranches("refs/heads/main", false),
			}},
			want: map[string]model.Status{
				idExists:            model.StatusVerifiedPass,
				idProtectionRules:   model.StatusVerifiedPass,
				idRequiredReviewers: model.StatusVerifiedPass,
				idBranchPolicy:      model.StatusVerifiedPass,
			},
		},
		{
			// Type split, half one: an Approval check satisfies
			// protection-rules and required-reviewers and must not satisfy
			// branch-policy.
			name:         "one production environment with only an Approval check",
			envs:         onlyProd,
			perEnvChecks: [][]map[string]any{{approvalCheck(false)}},
			want: map[string]model.Status{
				idExists:            model.StatusVerifiedPass,
				idProtectionRules:   model.StatusVerifiedPass,
				idRequiredReviewers: model.StatusVerifiedPass,
				idBranchPolicy:      model.StatusVerifiedFail,
			},
		},
		{
			// Type split, the exact reverse of state 2.
			name:         "one production environment with only a Task Check restricting to main",
			envs:         onlyProd,
			perEnvChecks: [][]map[string]any{{taskCheckWithAllowedBranches("refs/heads/main", false)}},
			want: map[string]model.Status{
				idExists:            model.StatusVerifiedPass,
				idProtectionRules:   model.StatusVerifiedPass,
				idRequiredReviewers: model.StatusVerifiedFail,
				idBranchPolicy:      model.StatusVerifiedPass,
			},
		},
		{
			// Splits protection-rules from both type-specific checks: a real,
			// enabled check of neither tracked type. protection-rules counts
			// any check; the other two must recognise this one as neither.
			name:         "one production environment whose only check is neither an Approval nor a Task Check",
			envs:         onlyProd,
			perEnvChecks: [][]map[string]any{{businessHoursCheck}},
			want: map[string]model.Status{
				idExists:            model.StatusVerifiedPass,
				idProtectionRules:   model.StatusVerifiedPass,
				idRequiredReviewers: model.StatusVerifiedFail,
				idBranchPolicy:      model.StatusVerifiedFail,
			},
		},
		{
			// The isDisabled axis, and a split with nothing missing: both
			// tracked check types are configured on this environment and only
			// the Approval one is disabled. required-reviewers must read
			// isDisabled; protection-rules still passes on the live Task Check.
			name: "production environment with a DISABLED Approval check alongside a live Task Check",
			envs: onlyProd,
			perEnvChecks: [][]map[string]any{{
				approvalCheck(true),
				taskCheckWithAllowedBranches("refs/heads/main", false),
			}},
			want: map[string]model.Status{
				idExists:            model.StatusVerifiedPass,
				idProtectionRules:   model.StatusVerifiedPass,
				idRequiredReviewers: model.StatusVerifiedFail,
				idBranchPolicy:      model.StatusVerifiedPass,
			},
		},
		{
			// protection-rules' only route to verified-fail. It is necessarily
			// lockstep — an environment with no live check cannot have a live
			// check of a particular type — so the fixture earns its keep a
			// different way: the checks are PRESENT and merely disabled, so
			// this is not the trivially-empty list.
			name: "production environment whose Approval and Task checks are both disabled",
			envs: onlyProd,
			perEnvChecks: [][]map[string]any{{
				approvalCheck(true),
				taskCheckWithAllowedBranches("refs/heads/main", true),
			}},
			want: map[string]model.Status{
				idExists:            model.StatusVerifiedPass,
				idProtectionRules:   model.StatusVerifiedFail,
				idRequiredReviewers: model.StatusVerifiedFail,
				idBranchPolicy:      model.StatusVerifiedFail,
			},
		},
		{
			// branch-policy's ambiguous route to partial, reached with the
			// mixed list a previous version of hasRealBranchRestriction misread
			// as a genuine restriction: "*" alongside a specific branch still
			// allows every branch. The Approval check is live, so this state
			// also holds branch-policy apart from the other two while nothing
			// is missing.
			name: "production environment whose Task Check allows main AND a match-all wildcard",
			envs: onlyProd,
			perEnvChecks: [][]map[string]any{{
				approvalCheck(false),
				taskCheckWithAllowedBranches("refs/heads/main,*", false),
			}},
			want: map[string]model.Status{
				idExists:            model.StatusVerifiedPass,
				idProtectionRules:   model.StatusVerifiedPass,
				idRequiredReviewers: model.StatusVerifiedPass,
				idBranchPolicy:      model.StatusPartial,
			},
		},
		{
			// Three production-like environments, walked in order, each in a
			// different branch-policy state: restricted, ambiguous, absent.
			// This is the state that pins two things a single-environment
			// matrix cannot: that the checks are evaluated across EVERY
			// production-like environment rather than the first, and that a
			// confident absence outranks an honest "can't tell" when both
			// occur at once.
			name: "three production environments: one restricted, one ambiguous, one with no Task Check",
			envs: envsOK(env(11, "production"), env(12, "prod-eu"), env(13, "prod-us")),
			perEnvChecks: [][]map[string]any{
				{approvalCheck(false), taskCheckWithAllowedBranches("refs/heads/main", false)},
				{approvalCheck(false), taskCheckWithAllowedBranches("*", false)},
				{approvalCheck(false)},
			},
			want: map[string]model.Status{
				idExists:            model.StatusVerifiedPass,
				idProtectionRules:   model.StatusVerifiedPass,
				idRequiredReviewers: model.StatusVerifiedPass,
				idBranchPolicy:      model.StatusVerifiedFail,
			},
		},
		{
			// Every check's only route to partial except branch-policy's, and
			// the only state where env.exists is partial. No checks call is
			// made at all here, which is why the fixture registers none.
			name: "environments exist but none is named production-like",
			envs: envsOK(env(21, "staging"), env(22, "dev")),
			want: map[string]model.Status{
				idExists:            model.StatusPartial,
				idProtectionRules:   model.StatusPartial,
				idRequiredReviewers: model.StatusPartial,
				idBranchPolicy:      model.StatusPartial,
			},
		},
		{
			// Not-checkable with no transport failure anywhere: the
			// environments call succeeds and the project simply has none.
			name: "the project has zero environments",
			envs: envsOK(),
			want: map[string]model.Status{
				idExists:            model.StatusNotCheckable,
				idProtectionRules:   model.StatusNotCheckable,
				idRequiredReviewers: model.StatusNotCheckable,
				idBranchPolicy:      model.StatusNotCheckable,
			},
		},
		{
			name: "the environments list is denied",
			envs: forbidden,
			want: map[string]model.Status{
				idExists:            model.StatusNotCheckable,
				idProtectionRules:   model.StatusNotCheckable,
				idRequiredReviewers: model.StatusNotCheckable,
				idBranchPolicy:      model.StatusNotCheckable,
			},
		},
		{
			// The state that pins env.exists' independence from the second
			// call: a production environment demonstrably exists and only the
			// checks read is denied. Nothing else in the matrix separates
			// env.exists from the other three on the not-checkable axis.
			name:      "a production environment exists but its check configurations are denied",
			envs:      onlyProd,
			checksErr: &forbidden,
			want: map[string]model.Status{
				idExists:            model.StatusVerifiedPass,
				idProtectionRules:   model.StatusNotCheckable,
				idRequiredReviewers: model.StatusNotCheckable,
				idBranchPolicy:      model.StatusNotCheckable,
			},
		},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			results, err := newTestCollector(st.fixture()).Collect(context.Background(), collect.Scope{
				Org: testOrg, Project: testProject, Repos: []string{"repo-a"},
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
