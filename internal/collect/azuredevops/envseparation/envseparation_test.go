package envseparation

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/collect/azuredevops/adofixture"
	"github.com/sioakim/attestward/internal/model"
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
