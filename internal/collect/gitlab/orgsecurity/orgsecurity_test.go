package orgsecurity

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// realGroupBody is the shape GET /groups/{id} actually returns, taken from a
// live gitlab.com group on 2026-08-10 and trimmed to the fields read here.
// Recorded rather than invented so the parsing is tested against what GitLab
// really sends, including the fields this collector deliberately ignores.
const realGroupBody = `{
  "id": 139323237,
  "full_path": "qloud-ltd-group",
  "visibility": "private",
  "require_two_factor_authentication": %t,
  "two_factor_grace_period": 48,
  "project_creation_level": %q,
  "prevent_forking_outside_group": false,
  "share_with_group_lock": false,
  "lfs_enabled": true
}`

func collectAgainst(t *testing.T, status int, body string) []model.CheckResult {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)

	c := NewForTest(srv.URL, "tok", func() (*gitlabcollect.Client, error) {
		return gitlabcollect.NewClient(srv.URL, "tok")
	})
	res, err := c.Collect(context.Background(), collect.Scope{Org: "qloud-ltd-group"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return res
}

func find(t *testing.T, res []model.CheckResult, id string) model.CheckResult {
	t.Helper()
	for _, r := range res {
		if r.CheckID == id {
			return r
		}
	}
	t.Fatalf("no result for %s", id)
	return model.CheckResult{}
}

func TestTwoFactorEnforcementIsReadFromTheGroup(t *testing.T) {
	off := collectAgainst(t, 200, fmt.Sprintf(realGroupBody, false, "developer"))
	if got := find(t, off, idTwoFactorRequired); got.Status != model.StatusVerifiedFail {
		t.Errorf("2fa off: status = %q, want verified-fail", got.Status)
	}
	on := collectAgainst(t, 200, fmt.Sprintf(realGroupBody, true, "developer"))
	if got := find(t, on, idTwoFactorRequired); got.Status != model.StatusVerifiedPass {
		t.Errorf("2fa on: status = %q, want verified-pass", got.Status)
	}
}

func TestProjectCreationLevelMapsToMemberCreationCheck(t *testing.T) {
	// Creation level only decides this in a PUBLIC group. In a private or
	// internal one the visibility ceiling makes public projects impossible, so
	// asserting creation-level mapping there was testing the conflation this
	// check used to contain rather than the control it claims to measure.
	for level, want := range map[string]model.Status{
		"developer":  model.StatusVerifiedFail,
		"maintainer": model.StatusVerifiedPass,
		"noone":      model.StatusVerifiedPass,
		"martian":    model.StatusNotCheckable, // unknown value: refuse to guess
	} {
		body := strings.Replace(fmt.Sprintf(realGroupBody, true, level),
			`"visibility": "private"`, `"visibility": "public"`, 1)
		if got := find(t, collectAgainst(t, 200, body), idMembersCreatePublic); got.Status != want {
			t.Errorf("public group, project_creation_level=%q: status = %q, want %q", level, got.Status, want)
		}
	}
}

// TestMembersWithout2FAIsAlwaysNotCheckable pins the package's central honesty
// claim: GitLab exposes no per-user 2FA state, so this must never be inferred
// from enforcement — which would be wrong in both directions.
func TestMembersWithout2FAIsAlwaysNotCheckable(t *testing.T) {
	for _, enforced := range []bool{true, false} {
		res := collectAgainst(t, 200, fmt.Sprintf(realGroupBody, enforced, "maintainer"))
		got := find(t, res, idMembersWithout2FA)
		if got.Status != model.StatusNotCheckable {
			t.Errorf("enforcement=%v: status = %q, want not-checkable — enforcement is not evidence of enrolment", enforced, got.Status)
		}
	}
}

// TestPermissionFailuresAreNotSecurityFindings pins that a credential problem
// never becomes a verified-fail. A 403 says something about the token; saying
// it about the group would put a false finding into a signed attestation.
func TestPermissionFailuresAreNotSecurityFindings(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusNotFound} {
		res := collectAgainst(t, code, `{"message":"denied"}`)
		if len(res) != 4 {
			t.Fatalf("HTTP %d: got %d results, want all 4 still reported", code, len(res))
		}
		for _, r := range res {
			if r.Status != model.StatusNotCheckable {
				t.Errorf("HTTP %d: %s = %q, want not-checkable", code, r.CheckID, r.Status)
			}
		}
	}
}

// TestEveryResultCarriesProvenance pins that a pack can prove what was read.
func TestEveryResultCarriesProvenance(t *testing.T) {
	res := collectAgainst(t, 200, fmt.Sprintf(realGroupBody, true, "maintainer"))
	for _, r := range res {
		if len(r.Provenance) == 0 {
			t.Errorf("%s carries no provenance", r.CheckID)
		}
	}
}

// TestPrivateGroupCannotHavePublicProjects pins review finding 4: a private or
// internal group applies visibility as a ceiling, so no member can create a
// public project whatever project_creation_level says. Reading creation level
// alone fabricated a verified-fail for every private group on the default
// setting — an ordinary, safe configuration.
func TestPrivateGroupCannotHavePublicProjects(t *testing.T) {
	for _, vis := range []string{"private", "internal"} {
		body := fmt.Sprintf(realGroupBody, true, "developer")
		body = strings.Replace(body, `"visibility": "private"`, fmt.Sprintf(`"visibility": %q`, vis), 1)
		got := find(t, collectAgainst(t, 200, body), idMembersCreatePublic)
		if got.Status != model.StatusVerifiedPass {
			t.Errorf("%s group with project_creation_level=developer: got %q, want verified-pass — "+
				"public projects are impossible inside it", vis, got.Status)
		}
	}
}

// TestPublicGroupStillHonoursCreationLevel guards the other direction: in a
// public group the creation level genuinely does decide this.
func TestPublicGroupStillHonoursCreationLevel(t *testing.T) {
	body := strings.Replace(fmt.Sprintf(realGroupBody, true, "developer"),
		`"visibility": "private"`, `"visibility": "public"`, 1)
	if got := find(t, collectAgainst(t, 200, body), idMembersCreatePublic); got.Status != model.StatusVerifiedFail {
		t.Errorf("public group + developer creation = %q, want verified-fail", got.Status)
	}
}

// TestUnknownVisibilityIsNotCheckable pins the I2 regression case directly.
// Every named visibility was covered; the fall-through was not, which is
// exactly where the defect lived — an unrecognised value reached reasons that
// asserted the group "is public", stating a visibility never observed and
// turning a parsing gap into a finding against the producer.
func TestUnknownVisibilityIsNotCheckable(t *testing.T) {
	for _, vis := range []string{"", "martian", "Public"} {
		body := fmt.Sprintf(realGroupBody, true, "developer")
		body = strings.Replace(body, `"visibility": "private"`, fmt.Sprintf(`"visibility": %q`, vis), 1)
		got := find(t, collectAgainst(t, 200, body), idMembersCreatePublic)
		if got.Status != model.StatusNotCheckable {
			t.Errorf("visibility %q = %q, want not-checkable", vis, got.Status)
		}
		if strings.Contains(got.Reason, "is public") {
			t.Errorf("visibility %q produced a reason asserting the group is public: %s", vis, got.Reason)
		}
	}
}

// TestUnknownVisibilityIsNotADefaultPermissionPass pins issue #5. The sibling
// check already refused to guess on this field; this one read every non-public
// value as private-or-internal, so an unrecognised visibility became a pass
// whose reason quoted a value it had not understood.
//
// A false pass is the worst outcome available to this tool: it tells a producer
// a control holds, inside a signed attestation, on the strength of something
// the build could not interpret.
func TestUnknownVisibilityIsNotADefaultPermissionPass(t *testing.T) {
	for _, vis := range []string{"", "martian", "Private"} {
		body := fmt.Sprintf(realGroupBody, true, "developer")
		body = strings.Replace(body, `"visibility": "private"`, fmt.Sprintf(`"visibility": %q`, vis), 1)
		got := find(t, collectAgainst(t, 200, body), idDefaultPermission)
		if got.Status != model.StatusNotCheckable {
			t.Errorf("visibility %q = %q, want not-checkable", vis, got.Status)
		}
		if got.Status == model.StatusVerifiedPass {
			t.Errorf("visibility %q produced a PASS — a control asserted as holding from an uninterpreted value", vis)
		}
	}
}

// TestKnownVisibilitiesStillDecide guards the other direction: the refusal must
// not swallow the cases the check exists to answer.
func TestKnownVisibilitiesStillDecide(t *testing.T) {
	for vis, want := range map[string]model.Status{
		"private":  model.StatusVerifiedPass,
		"internal": model.StatusVerifiedPass,
		"public":   model.StatusVerifiedFail,
	} {
		body := fmt.Sprintf(realGroupBody, true, "developer")
		body = strings.Replace(body, `"visibility": "private"`, fmt.Sprintf(`"visibility": %q`, vis), 1)
		if got := find(t, collectAgainst(t, 200, body), idDefaultPermission); got.Status != want {
			t.Errorf("visibility %q = %q, want %q", vis, got.Status, want)
		}
	}
}
