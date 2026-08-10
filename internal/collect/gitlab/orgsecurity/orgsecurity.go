// Package orgsecurity implements C01 org-security for a GitLab group (#1).
//
// GitLab's group object carries the whole of this control area in one
// response — GET /groups/{id} returns require_two_factor_authentication,
// project_creation_level and visibility together — so a scan costs a single
// call and every result here is backed by the same fetched bytes.
//
// # One of the four checks is genuinely not answerable, and that is evidenced
//
// C01.org.members-without-2fa asks which members lack 2FA. GitHub answers it
// with ?filter=2fa_disabled on the members endpoint. GitLab does not: the
// group members response was inspected on 2026-08-10 and carries id,
// username, name, state, access_level, expires_at, membership_state, locked,
// avatar_url, public_email and web_url — and no per-user two-factor field of
// any kind.
//
// So this check reports not-checkable with that as the reason, rather than
// inferring from require_two_factor_authentication. Inferring would be
// wrong in both directions: enforcement being on does not prove every
// existing member has enrolled (GitLab grants a grace period, visible here as
// two_factor_grace_period), and enforcement being off does not mean nobody
// has it.
//
// # Why access to the group object is not assumed
//
// A token scoped to a project, or a member below the required role, gets 403
// or 404 on the group endpoint. That is not a finding about the group's
// security posture — it is a fact about the credential — so it produces
// not-checkable naming the permission, never verified-fail.
package orgsecurity

import (
	"context"
	"fmt"
	"net/http"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const (
	platform    = "gitlab"
	collectorID = "C01.org-security"

	idTwoFactorRequired   = "C01.org.2fa-required"
	idDefaultPermission   = "C01.org.default-repo-permission"
	idMembersCreatePublic = "C01.org.members-can-create-public"
	idMembersWithout2FA   = "C01.org.members-without-2fa"
)

// group is the subset of GET /groups/{id} this collector reads. Deliberately
// narrow: Facts must carry the minimal data that justified a decision, never
// a whole API payload.
type group struct {
	Path                           string `json:"full_path"`
	RequireTwoFactorAuthentication bool   `json:"require_two_factor_authentication"`
	TwoFactorGracePeriod           int    `json:"two_factor_grace_period"`
	ProjectCreationLevel           string `json:"project_creation_level"`
	Visibility                     string `json:"visibility"`
	PreventForkingOutsideGroup     bool   `json:"prevent_forking_outside_group"`
}

// Collector reads a GitLab group's security settings.
type Collector struct {
	baseURL string
	token   string

	newClient func() (*gitlabcollect.Client, error)
}

// New builds a Collector against baseURL (empty means gitlab.com).
func New(baseURL, token string) *Collector {
	c := &Collector{baseURL: baseURL, token: token}
	c.newClient = func() (*gitlabcollect.Client, error) {
		return gitlabcollect.NewClient(baseURL, token)
	}
	return c
}

// NewForTest injects a client factory so tests need no network.
func NewForTest(baseURL, token string, newClient func() (*gitlabcollect.Client, error)) *Collector {
	return &Collector{baseURL: baseURL, token: token, newClient: newClient}
}

// ID returns the collector identifier recorded on every result it emits.
func (c *Collector) ID() string { return collectorID }

// Collect reads the group and returns one result per registered check.
// Permission and tier failures become not-checkable, never findings.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	client, err := c.newClient()
	if err != nil {
		return notCheckableAll(scope.Org, fmt.Sprintf("could not build a GitLab client: %v", err)), nil
	}

	var g group
	err = gitlabcollect.GetJSON(ctx, client, "/groups/"+pathEscape(scope.Org), nil, &g)
	prov := client.Provenance()
	if err != nil {
		return withProvenance(notCheckableAll(scope.Org, describeGroupError(scope.Org, err)), prov), nil
	}

	results := []model.CheckResult{
		twoFactorResult(scope.Org, g),
		defaultPermissionResult(scope.Org, g),
		membersCreatePublicResult(scope.Org, g),
		membersWithout2FAResult(scope.Org),
	}
	return withProvenance(results, prov), nil
}

// describeGroupError turns a failed group read into a reason that names the
// cause. A 403/404 here is a statement about the token, not about the group.
func describeGroupError(org string, err error) string {
	code, ok := gitlabcollect.StatusCodeOf(err)
	switch {
	case ok && code == http.StatusNotFound:
		return fmt.Sprintf("group %q was not found, or the token cannot see it — GitLab returns 404 rather than 403 "+
			"for a private group the credential has no access to, so this cannot distinguish the two. "+
			"It is a fact about the credential or the group path, not about the group's security posture", org)
	case ok && code == http.StatusForbidden:
		return fmt.Sprintf("the token is not permitted to read group %q (HTTP 403). Reading group settings needs at "+
			"least Reporter on the group; a project-scoped token cannot do it at all", org)
	default:
		return fmt.Sprintf("could not read group %q: %v", org, err)
	}
}

func twoFactorResult(org string, g group) model.CheckResult {
	if g.RequireTwoFactorAuthentication {
		return result(idTwoFactorRequired, "Org requires two-factor authentication", model.StatusVerifiedPass, org,
			fmt.Sprintf("group %q sets require_two_factor_authentication=true, with a %d-hour enrolment grace period",
				g.Path, g.TwoFactorGracePeriod),
			map[string]any{"require_two_factor_authentication": true, "two_factor_grace_period_hours": g.TwoFactorGracePeriod})
	}
	return result(idTwoFactorRequired, "Org requires two-factor authentication", model.StatusVerifiedFail, org,
		fmt.Sprintf("group %q sets require_two_factor_authentication=false, so members can authenticate with a "+
			"password alone", g.Path),
		map[string]any{"require_two_factor_authentication": false})
}

// defaultPermissionResult reads the group's visibility, which is GitLab's
// nearest equivalent to GitHub's org-wide default repository permission: it
// is the ceiling every project inherits at creation.
func defaultPermissionResult(org string, g group) model.CheckResult {
	status := model.StatusVerifiedPass
	reason := fmt.Sprintf("group %q defaults new projects to %q visibility", g.Path, g.Visibility)
	if g.Visibility == "public" {
		status = model.StatusVerifiedFail
		reason = fmt.Sprintf("group %q is public, so projects created in it are visible to anyone by default", g.Path)
	}
	return result(idDefaultPermission, "Org default repository permission is restrictive", status, org, reason,
		map[string]any{"visibility": g.Visibility, "prevent_forking_outside_group": g.PreventForkingOutsideGroup})
}

// membersCreatePublicResult maps project_creation_level, which decides who
// may create projects at all. GitLab's values are "noone", "maintainer" and
// "developer"; "developer" is the permissive end.
func membersCreatePublicResult(org string, g group) model.CheckResult {
	// A private or internal group cannot contain a public project at all —
	// GitLab enforces the group's visibility as a ceiling on every project
	// inside it. So project_creation_level is irrelevant here: no member can
	// create a public project regardless of who may create projects.
	//
	// Reading creation level alone produced a fabricated verified-fail for
	// every private group using the default "developer" setting, which is an
	// ordinary and safe configuration.
	if g.Visibility == "private" || g.Visibility == "internal" {
		return result(idMembersCreatePublic, "Members cannot create public repositories", model.StatusVerifiedPass, org,
			fmt.Sprintf("group %q is %s, and GitLab applies group visibility as a ceiling on the projects inside it, "+
				"so no member can create a public project there whatever project_creation_level says (it is %q)",
				g.Path, g.Visibility, g.ProjectCreationLevel),
			map[string]any{"visibility": g.Visibility, "project_creation_level": g.ProjectCreationLevel,
				"public_projects_possible": false})
	}
	// Only in a PUBLIC group does creation level decide this. An unrecognised
	// or empty visibility must not fall through to reasons that assert the
	// group "is public" — that would state a visibility never observed.
	if g.Visibility != "public" {
		return result(idMembersCreatePublic, "Members cannot create public repositories", model.StatusNotCheckable, org,
			fmt.Sprintf("group %q reported visibility %q, which this build does not recognise; whether a member could "+
				"create a public project depends on it, and guessing would assert a visibility never observed",
				g.Path, g.Visibility), map[string]any{"visibility": g.Visibility})
	}
	switch g.ProjectCreationLevel {
	case "noone", "maintainer":
		return result(idMembersCreatePublic, "Members cannot create public repositories", model.StatusVerifiedPass, org,
			fmt.Sprintf("group %q is public, but project_creation_level=%q so ordinary members cannot create projects in it",
				g.Path, g.ProjectCreationLevel),
			map[string]any{"visibility": g.Visibility, "project_creation_level": g.ProjectCreationLevel})
	case "developer":
		return result(idMembersCreatePublic, "Members cannot create public repositories", model.StatusVerifiedFail, org,
			fmt.Sprintf("group %q is public and project_creation_level=\"developer\", so any member at Developer or "+
				"above can create a project in it that is visible to anyone", g.Path),
			map[string]any{"visibility": g.Visibility, "project_creation_level": g.ProjectCreationLevel})
	default:
		return result(idMembersCreatePublic, "Members cannot create public repositories", model.StatusNotCheckable, org,
			fmt.Sprintf("group %q is public and reported project_creation_level=%q, which this build does not "+
				"recognise; refusing to guess whether it is permissive", g.Path, g.ProjectCreationLevel), nil)
	}
}

// membersWithout2FAResult is always not-checkable — see the package doc. The
// reason names the inspected response so a reader can verify the claim rather
// than take it on trust.
func membersWithout2FAResult(org string) model.CheckResult {
	return result(idMembersWithout2FA, "No members without two-factor authentication", model.StatusNotCheckable, org,
		"GitLab's group members API exposes no per-user two-factor field (GET /groups/{id}/members returns id, "+
			"username, name, state, access_level, expires_at, membership_state, locked, avatar_url, public_email "+
			"and web_url — verified 2026-08-10). Enforcement state is not a substitute: a grace period means "+
			"enforcement can be on while members are still unenrolled, and enforcement being off does not mean "+
			"nobody has 2FA", nil)
}

func result(id, title string, status model.Status, org, reason string, facts map[string]any) model.CheckResult {
	return model.CheckResult{
		CheckID: id,
		Title:   title,
		Status:  status,
		Reason:  reason,
		Scope:   model.ScopeRef{Org: org, Platform: platform},
		Facts:   facts,
		// Empty, never nil: nil marshals to JSON null and the pack schema
		// requires an array, so a bad --gitlab-url used to make the whole
		// scan fail validation instead of degrading to not-checkable.
		Provenance: []model.Provenance{},
	}
}

func notCheckableAll(org, reason string) []model.CheckResult {
	ids := []struct{ id, title string }{
		{idTwoFactorRequired, "Org requires two-factor authentication"},
		{idDefaultPermission, "Org default repository permission is restrictive"},
		{idMembersCreatePublic, "Members cannot create public repositories"},
		{idMembersWithout2FA, "No members without two-factor authentication"},
	}
	out := make([]model.CheckResult, 0, len(ids))
	for _, c := range ids {
		out = append(out, result(c.id, c.title, model.StatusNotCheckable, org, reason, nil))
	}
	return out
}

func withProvenance(results []model.CheckResult, prov []model.Provenance) []model.CheckResult {
	for i := range results {
		results[i].Provenance = prov
	}
	return results
}

// pathEscape percent-encodes a group path so a nested group ("a/b/c") is sent
// as a single URL-encoded id, which is how GitLab addresses subgroups.
func pathEscape(s string) string {
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			out = append(out, '%', '2', 'F')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

func init() {
	reg := func(id, title, remediation string, rubric map[model.Status]string) {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: title, Collector: collectorID,
			TokenScope:  "read_api (Reporter or above on the group)",
			Remediation: remediation, Rubric: rubric,
			Endpoints:  []string{"GET /groups/{id}"},
			FixtureRef: "internal/collect/gitlab/orgsecurity/orgsecurity_test.go",
		})
	}
	reg(idTwoFactorRequired, "Org requires two-factor authentication",
		"Group → Settings → General → Permissions and group features → enable \"Require all users in this group to set up two-factor authentication\". Note the grace period: enforcement starts applying only after it elapses.",
		map[model.Status]string{
			model.StatusVerifiedPass: "GET /groups/{id} returned require_two_factor_authentication=true.",
			model.StatusVerifiedFail: "GET /groups/{id} returned require_two_factor_authentication=false.",
			model.StatusNotCheckable: "The group object could not be read — the token lacks group access, or the path does not resolve.",
		})
	reg(idDefaultPermission, "Org default repository permission is restrictive",
		"Group → Settings → General → set the group's visibility to Private or Internal so new projects do not default to public.",
		map[model.Status]string{
			model.StatusVerifiedPass: "Group visibility is private or internal, so projects created in it are not world-readable by default.",
			model.StatusVerifiedFail: "Group visibility is public.",
			model.StatusNotCheckable: "The group object could not be read.",
		})
	reg(idMembersCreatePublic, "Members cannot create public repositories",
		"Either set the group's visibility to Private or Internal — which caps every project inside it and settles this regardless of who may create projects — or, in a public group, set Group → Settings → General → Permissions → \"Roles allowed to create projects\" to Maintainers or No one.",
		map[model.Status]string{
			model.StatusVerifiedPass: "Either the group is private or internal, in which case its visibility is a ceiling on every project inside it and no member can create a public one whatever their role, or the group is public and project_creation_level is \"maintainer\" or \"noone\". Note the first case passes even when project_creation_level is \"developer\": that setting governs who may create projects, not how public they may be.",
			model.StatusVerifiedFail: "The group is public AND project_creation_level is \"developer\", so an ordinary member can create a world-readable project. Both conditions are required — a permissive creation level inside a private or internal group is not a finding.",
			model.StatusNotCheckable: "The group object could not be read, or reported a visibility or creation level this build does not recognise.",
		})
	reg(idMembersWithout2FA, "No members without two-factor authentication",
		"Not evidenceable on GitLab: the members API exposes no per-user two-factor state. Enforce 2FA at the group level and confirm enrolment through your identity provider or GitLab admin area instead.",
		map[model.Status]string{
			model.StatusNotCheckable: "GitLab's group members API carries no per-user two-factor field, so the question cannot be answered from the API at all.",
		})
}
