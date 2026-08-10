package repoprotection

import (
	"context"
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

func repoPath(org, repo string) string {
	return "/api/v1/repos/" + org + "/" + repo
}

func branchesPath(org, repo string) string {
	return repoPath(org, repo) + "/branches"
}

func collaboratorsPath(org, repo string) string {
	return repoPath(org, repo) + "/collaborators"
}

// normalRepo registers a fixture for an ordinary, non-empty, non-mirror,
// non-fork repo whose default branch genuinely appears in its own branch
// list — the baseline every other scenario in this file varies from.
func normalRepo(fx *gogsfixture.Transport, org, repo string, overrides map[string]any) {
	body := map[string]any{
		"private":        false,
		"fork":           false,
		"mirror":         false,
		"empty":          false,
		"default_branch": "main",
	}
	for k, v := range overrides {
		body[k] = v
	}
	fx.Set("GET", repoPath(org, repo), gogsfixture.Response{Status: 200, Body: body})
	fx.Set("GET", branchesPath(org, repo), gogsfixture.Response{Status: 200, Body: []map[string]any{
		{"name": "main"},
	}})
	fx.Set("GET", collaboratorsPath(org, repo), gogsfixture.Response{Status: 200, Body: []map[string]any{
		{"login": "alice"}, {"login": "bob"},
	}})
}

func collectWith(t *testing.T, fx *gogsfixture.Transport, org string, repos ...string) []model.CheckResult {
	t.Helper()
	c := NewForTest(baseURL, "token", func() (*gogscollect.Client, error) {
		return gogscollect.NewClientForTest(baseURL, "token", fx)
	})
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: repos})
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
// or "the scanner stopped early". Every one of these six checks can only
// ever be not-checkable, and they must still all appear, for every repo.
func TestCollect_AlwaysEmitsEveryCheckID(t *testing.T) {
	fx := gogsfixture.New()
	normalRepo(fx, "acme", "widget", nil)

	got := byID(collectWith(t, fx, "acme", "widget"))
	for _, id := range checkIDs {
		if _, ok := got[id]; !ok {
			t.Errorf("result for %s missing entirely", id)
		}
	}
	if len(got) != len(checkIDs) {
		t.Errorf("got %d distinct check IDs, want %d", len(got), len(checkIDs))
	}
}

// TestCollect_NormalRepoIsNotCheckableWithPlatformReason is the ordinary
// case: repo and default branch both resolve fine, and every check is
// not-checkable purely because Gogs has no API for branch protection —
// never verified-fail, which would assert an absence never observed.
func TestCollect_NormalRepoIsNotCheckableWithPlatformReason(t *testing.T) {
	fx := gogsfixture.New()
	normalRepo(fx, "acme", "widget", nil)

	got := byID(collectWith(t, fx, "acme", "widget"))
	for _, id := range checkIDs {
		r := got[id]
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q (%s), want not-checkable", id, r.Status, r.Reason)
		}
		if r.Facts["mirror"] != false {
			t.Errorf("%s mirror fact = %v, want false", id, r.Facts["mirror"])
		}
		if r.Facts["default_branch"] != "main" {
			t.Errorf("%s default_branch fact = %v, want main", id, r.Facts["default_branch"])
		}
		if r.Facts["write_collaborator_count"] != 2 {
			t.Errorf("%s write_collaborator_count fact = %v, want 2", id, r.Facts["write_collaborator_count"])
		}
		if len(r.Provenance) == 0 {
			t.Errorf("%s carries no provenance, want the repo/branches/collaborators calls recorded", id)
		}
	}
}

// TestCollect_MirrorIsSurfacedAsItsOwnFact: a mirror's real protection
// posture lives on its upstream, not here — a materially different
// attestation story from an ordinary repo Gogs simply can't report on, and
// the Reason must say so explicitly rather than reading identically to the
// non-mirror case.
func TestCollect_MirrorIsSurfacedAsItsOwnFact(t *testing.T) {
	fx := gogsfixture.New()
	normalRepo(fx, "acme", "widget", map[string]any{"mirror": true})

	got := byID(collectWith(t, fx, "acme", "widget"))
	r := got[idProtectionExists]
	if r.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", r.Status)
	}
	if r.Facts["mirror"] != true {
		t.Errorf("mirror fact = %v, want true", r.Facts["mirror"])
	}
	if !strings.Contains(r.Reason, "mirror") {
		t.Errorf("reason = %q, want it to call out the repo being a mirror", r.Reason)
	}
}

// TestCollect_ForkIsSurfacedAsAFactWithNoSpecialReason: a fork is just a
// normal repo whose protection Gogs can't report on either — its Facts say
// so, but its Reason doesn't need special-case prose the way mirror's does.
func TestCollect_ForkIsSurfacedAsAFactWithNoSpecialReason(t *testing.T) {
	fx := gogsfixture.New()
	normalRepo(fx, "acme", "widget", map[string]any{"fork": true})

	got := byID(collectWith(t, fx, "acme", "widget"))
	r := got[idProtectionExists]
	if r.Facts["fork"] != true {
		t.Errorf("fork fact = %v, want true", r.Facts["fork"])
	}
	if r.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", r.Status)
	}
}

// TestCollect_EmptyRepoIsNotCheckableForItsOwnReason: an empty repo has no
// default branch to protect at all — a different, more specific reason
// than "Gogs can't report protection", and must not be confused with it.
func TestCollect_EmptyRepoIsNotCheckableForItsOwnReason(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", repoPath("acme", "widget"), gogsfixture.Response{Status: 200, Body: map[string]any{
		"private": false, "fork": false, "mirror": false, "empty": true, "default_branch": "",
	}})

	got := byID(collectWith(t, fx, "acme", "widget"))
	for _, id := range checkIDs {
		r := got[id]
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if !strings.Contains(r.Reason, "empty") {
			t.Errorf("%s reason = %q, want it to explain the repo is empty", id, r.Reason)
		}
	}
	for _, call := range fx.Calls() {
		if call == "GET "+branchesPath("acme", "widget") {
			t.Errorf("called the branches endpoint for an empty repo, want it skipped: %v", fx.Calls())
		}
	}
}

// TestCollect_404RepoIsNotCheckableNotAbsence is this codebase's recurring
// defect class: a repo the token can't see must never be reported as if
// its protection were observed and found absent.
func TestCollect_404RepoIsNotCheckableNotAbsence(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", repoPath("acme", "ghost"), gogsfixture.Response{Status: 404, RawBody: []byte{}})

	got := byID(collectWith(t, fx, "acme", "ghost"))
	for _, id := range checkIDs {
		r := got[id]
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if !strings.Contains(r.Reason, "not found") {
			t.Errorf("%s reason = %q, want it to say the repo was not found", id, r.Reason)
		}
		if r.Facts != nil {
			t.Errorf("%s facts = %v, want nil — nothing was observed about this repo", id, r.Facts)
		}
	}
}

// TestCollect_5xxIsNotCheckableNotAbsence: a transient server failure
// (surviving retry) establishes nothing about the repo either.
func TestCollect_5xxIsNotCheckableNotAbsence(t *testing.T) {
	fx := gogsfixture.New()
	for i := 0; i < 4; i++ { // retryTransport retries a 5xx up to maxRetries times
		fx.SetSequence("GET", repoPath("acme", "widget"), gogsfixture.Response{
			Status: 500, Body: map[string]any{"message": "internal server error"},
		})
	}

	got := byID(collectWith(t, fx, "acme", "widget"))
	for _, id := range checkIDs {
		r := got[id]
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if !strings.Contains(r.Reason, "could not read repository") {
			t.Errorf("%s reason = %q, want it to describe a read failure", id, r.Reason)
		}
	}
}

// TestCollect_DefaultBranchMissingFromBranchListIsNotCheckableForItsOwnReason
// covers a repo whose own default_branch value doesn't appear in its
// branches list — an inconsistency this collector can detect even though
// it can never check protection either way, and it must report a reason
// distinct from both the empty-repo and the ordinary platform-limitation
// cases.
func TestCollect_DefaultBranchMissingFromBranchListIsNotCheckableForItsOwnReason(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", repoPath("acme", "widget"), gogsfixture.Response{Status: 200, Body: map[string]any{
		"private": false, "fork": false, "mirror": false, "empty": false, "default_branch": "trunk",
	}})
	fx.Set("GET", branchesPath("acme", "widget"), gogsfixture.Response{Status: 200, Body: []map[string]any{
		{"name": "main"},
	}})

	got := byID(collectWith(t, fx, "acme", "widget"))
	for _, id := range checkIDs {
		r := got[id]
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if !strings.Contains(r.Reason, "trunk") || !strings.Contains(r.Reason, "not present") {
			t.Errorf("%s reason = %q, want it to name the missing default branch", id, r.Reason)
		}
	}
}

// TestCollect_BranchesReadFailureIsNotCheckableNotAbsence: if the branches
// list itself can't be read, this collector must not assume the default
// branch exists — the same defect class as the repo-read failure, one
// call deeper.
func TestCollect_BranchesReadFailureIsNotCheckableNotAbsence(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", repoPath("acme", "widget"), gogsfixture.Response{Status: 200, Body: map[string]any{
		"private": false, "fork": false, "mirror": false, "empty": false, "default_branch": "main",
	}})
	for i := 0; i < 4; i++ {
		fx.SetSequence("GET", branchesPath("acme", "widget"), gogsfixture.Response{
			Status: 500, Body: map[string]any{"message": "internal server error"},
		})
	}

	got := byID(collectWith(t, fx, "acme", "widget"))
	for _, id := range checkIDs {
		r := got[id]
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if !strings.Contains(r.Reason, "could not confirm the default branch exists") {
			t.Errorf("%s reason = %q, want it to describe the branches-read failure", id, r.Reason)
		}
	}
}

// TestCollect_CollaboratorReadFailureOmitsFactWithoutChangingStatus: no
// check's status ever depends on collaborator data, so a failure reading
// it must not escalate anything to a different not-checkable reason — it
// simply means one Fact is absent.
func TestCollect_CollaboratorReadFailureOmitsFactWithoutChangingStatus(t *testing.T) {
	fx := gogsfixture.New()
	fx.Set("GET", repoPath("acme", "widget"), gogsfixture.Response{Status: 200, Body: map[string]any{
		"private": false, "fork": false, "mirror": false, "empty": false, "default_branch": "main",
	}})
	fx.Set("GET", branchesPath("acme", "widget"), gogsfixture.Response{Status: 200, Body: []map[string]any{
		{"name": "main"},
	}})
	fx.Set("GET", collaboratorsPath("acme", "widget"), gogsfixture.Response{Status: http.StatusForbidden, RawBody: []byte{}})

	got := byID(collectWith(t, fx, "acme", "widget"))
	r := got[idProtectionExists]
	if r.Status != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable", r.Status)
	}
	if _, ok := r.Facts["write_collaborator_count"]; ok {
		t.Errorf("write_collaborator_count = %v, want the key absent — the collaborators read failed", r.Facts["write_collaborator_count"])
	}
	if r.Facts["default_branch"] != "main" {
		t.Errorf("default_branch fact = %v, want it still populated from the successful repo/branches reads", r.Facts["default_branch"])
	}
}

// TestCollect_CanceledContextIsNotCheckable: a scan canceled before a
// repo's turn came up must not silently skip the repo's results.
func TestCollect_CanceledContextIsNotCheckable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fx := gogsfixture.New()
	c := NewForTest(baseURL, "token", func() (*gogscollect.Client, error) {
		return gogscollect.NewClientForTest(baseURL, "token", fx)
	})
	results, err := c.Collect(ctx, collect.Scope{Org: "acme", Repos: []string{"widget"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := byID(results)
	for _, id := range checkIDs {
		r := got[id]
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", id, r.Status)
		}
		if !strings.Contains(r.Reason, "canceled") {
			t.Errorf("%s reason = %q, want it to mention cancellation", id, r.Reason)
		}
	}
	if len(fx.Calls()) != 0 {
		t.Errorf("made %d calls after cancellation, want none: %v", len(fx.Calls()), fx.Calls())
	}
}

// TestCollect_MultipleRepos proves per-repo isolation: one repo's error
// doesn't bleed into another's facts or reason.
func TestCollect_MultipleRepos(t *testing.T) {
	fx := gogsfixture.New()
	normalRepo(fx, "acme", "widget", nil)
	fx.Set("GET", repoPath("acme", "ghost"), gogsfixture.Response{Status: 404, RawBody: []byte{}})

	results := collectWith(t, fx, "acme", "widget", "ghost")
	if len(results) != 2*len(checkIDs) {
		t.Fatalf("got %d results, want %d (two repos x %d checks)", len(results), 2*len(checkIDs), len(checkIDs))
	}

	for _, r := range results {
		switch r.Scope.Repo {
		case "widget":
			if r.Facts == nil {
				t.Errorf("widget %s: facts were lost", r.CheckID)
			}
			if strings.Contains(r.Reason, "not found") {
				t.Errorf("widget %s: reason leaked ghost's not-found reason: %q", r.CheckID, r.Reason)
			}
		case "ghost":
			if r.Facts != nil {
				t.Errorf("ghost %s: facts = %v, want nil — nothing was observed about this repo", r.CheckID, r.Facts)
			}
			if !strings.Contains(r.Reason, "not found") {
				t.Errorf("ghost %s: reason = %q, want it to say the repo was not found", r.CheckID, r.Reason)
			}
		default:
			t.Fatalf("unexpected scope repo %q", r.Scope.Repo)
		}
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue #10).
//
// This collector is the simplest case in the tree and the guard is still worth
// having. Gogs exposes no branch-protection API at all, so every check here is
// always not-checkable and every rubric documents only that. The guard's value
// is therefore forward-looking: the day someone adds a real status — because
// Gogs gained an endpoint, or because a check started inferring something — it
// fails unless the rubric gains an entry to match. That is exactly the drift
// that shipped undetected three times in the gitlab and github trees.
//
// Two states, since a repo that reads and one that does not are the only
// distinguishable inputs when the answer is always the same.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	var all []model.CheckResult

	readable := gogsfixture.New()
	normalRepo(readable, "org", "repo", nil)
	all = append(all, collectWith(t, readable, "org", "repo")...)

	unreadable := gogsfixture.New()
	unreadable.Set("GET", repoPath("org", "repo"), gogsfixture.Response{Status: 404, Body: map[string]any{}})
	all = append(all, collectWith(t, unreadable, "org", "repo")...)

	collecttest.AssertRubricsMatchObservedBehaviour(t, platform, collectorID, all)
}
