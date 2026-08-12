// Package secretshygiene implements one new, GitLab-only check under C04
// secrets-hygiene: C04.vars.secret-masking. The other five C04 check IDs
// (scanning-enabled, push-protection, advanced-security, dependabot-alerts,
// org-security-defaults) stay in internal/collect/gitlab/unsupported,
// unmoved — they depend on GitLab's paid-tier Secret Detection and
// Dependency Scanning, a genuinely different, still-ungated capability
// this check doesn't touch at all.
//
// This mirrors the shape of Azure DevOps's own C04.vars.secret-hygiene (see
// internal/collect/azuredevops/secretshygiene's package doc comment): a
// sixth, platform-only check with no cross-platform twin, registered under
// the same Collector string ("C04.secrets-hygiene") as the five mirrored
// checks so it still groups under the same C04 heading in
// docs/checks-reference.md. It is deliberately registered under its OWN
// check ID rather than reusing "C04.vars.secret-hygiene" — several
// cross-cutting invariant tests in cmd/attestward (a registry Total count,
// a project-scoped-ID pin list, a "5 of C04's six IDs are shared, this one
// isn't" comment) assert that ID appears on exactly one platform, and this
// isn't the shared-ID-across-platforms model issue #34 established for the
// other five checks — it's a structurally analogous but NOT identical
// property. See checkSecretMasking's own doc comment for why.
//
// GET /projects/:id/variables (verified live 2026-08-13 against
// gitlab.com/sioakeim/attestward-scratch: created a plaintext sensitive-
// named variable, a masked sensitive-named variable, a masked+protected
// one, a non-sensitive plaintext one, and one created with hidden=true —
// the last came back hidden:false with its value fully present, so this
// build treats hidden as unobserved-in-practice on this instance rather
// than adding dead code for a state it has never actually seen; an empty
// Value already reads as "nothing stored" regardless of why it's empty, so
// a genuinely hidden value in a future GitLab release would fail safe as
// not-flagged, never as a false verified-fail) is a Free-tier, real
// endpoint. Each returned object was confirmed to carry the actual, full
// `value` field regardless of its `masked` or `protected` flags — masking
// in GitLab only affects what appears in CI/CD job console output, it does
// not change what an API caller with sufficient project access can read.
package secretshygiene

import (
	"context"
	"fmt"
	"regexp"
	"sort"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const platform = "gitlab"
const collectorID = "C04.secrets-hygiene"
const idSecretMasking = "C04.vars.secret-masking"

const checkTitle = "Sensitive-named CI/CD variables are masked in job logs"

const checkTokenScope = "Maintainer role on the project — docs.gitlab.com documents Maintainer as required " +
	"to manage CI/CD variables, and this build's own verification token held that role; a lower-privileged " +
	"token's exact response against this endpoint (an empty list vs. a 403) was not independently observed"

const checkEndpoint = "GET /projects/{id}/variables"

const fixtureRef = "internal/collect/gitlab/secretshygiene/secretshygiene_test.go"

// checkRemediation quotes docs.gitlab.com's own masking value requirements
// verbatim (single line, no spaces, 8+ characters, must not match an
// existing variable name) rather than paraphrasing them, since a
// remediation a reader can't actually satisfy is worse than none — and
// carries GitLab's own caveat that masking is a log-redaction control, not
// a hard access boundary.
const checkRemediation = "Open the flagged variable (Settings -> CI/CD -> Variables) and enable \"Mask " +
	"variable\". GitLab requires the value to \"be a single line with no spaces\", \"be 8 characters or " +
	"longer\", and \"not match the name of an existing predefined or custom CI/CD variable\" — rotate the " +
	"value first if it doesn't qualify. Note GitLab's own caution: \"Masking a CI/CD variable is not a " +
	"guaranteed way to prevent malicious users from accessing variable values\" — masking redacts a value " +
	"from job console output, it does not change who can read it via the API or UI."

var checkRubric = map[model.Status]string{
	model.StatusVerifiedPass: "no CI/CD variable in the project has both a name matching " +
		"(?i)(password|passwd|pwd|secret|credentials?|token|api[_-]?key|connstr|connection[_-]?string) and " +
		"masked=false with a non-empty value",
	model.StatusVerifiedFail: "at least one CI/CD variable has a sensitive-looking name, masked=false, and " +
		"a non-empty value — GitLab will show that value unredacted in any job's console output. The " +
		"offending variable name(s) are recorded in Facts, never the value",
	model.StatusNotCheckable: "the project's CI/CD variables list couldn't be read (403/404/other API error " +
		"— a 403 here commonly means the token lacks Maintainer role on this project, which GitLab requires " +
		"to read CI/CD variables at all)",
}

func init() {
	collect.Register(collect.CheckMeta{
		ID: idSecretMasking, Platform: platform, Title: checkTitle, Collector: collectorID,
		TokenScope: checkTokenScope, Remediation: checkRemediation, Rubric: checkRubric,
		Endpoints: []string{checkEndpoint}, FixtureRef: fixtureRef,
	})
}

// sensitiveVariableNameRE is reproduced verbatim from Azure DevOps's own
// SensitiveVariableNameRE (internal/collect/azuredevops/secretshygiene) —
// duplicated per ADR-0005 rather than imported, since the naming
// convention it matches is platform-neutral even though what "masked"
// means differs by platform.
var sensitiveVariableNameRE = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|credentials?|token|api[_-]?key|connstr|connection[_-]?string)`)

// variableRaw is the subset of GitLab's Project-level Variable shape this
// needs (docs.gitlab.com/api/project_level_variables/, verified live
// against attestward-scratch — see the package doc comment).
type variableRaw struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Masked bool   `json:"masked"`
}

// offendingVariable names one masked=false, sensitive-named variable — KEY
// only, deliberately no Value field on this type at all, so there is
// nothing for a caller to accidentally forward into Facts even by a
// future refactor. Same discipline as Azure DevOps's own
// offendingVariable (internal/collect/azuredevops/secretshygiene).
type offendingVariable struct {
	Key string
}

// fetchVariables lists every CI/CD variable in a project via GET
// /projects/:id/variables.
func fetchVariables(ctx context.Context, client *gitlabcollect.Client, projID string) ([]variableRaw, error) {
	return gitlabcollect.GetJSONPaged[variableRaw](ctx, client, "/projects/"+projID+"/variables", nil)
}

// checkSecretMasking is C04.vars.secret-masking — see the package doc
// comment for why it registers under its own ID rather than reusing Azure
// DevOps's C04.vars.secret-hygiene.
//
// The property this verifies is deliberately NOT "is this value encrypted
// at rest" the way ADO's isSecret is: docs.gitlab.com states every CI/CD
// variable value, masked or not, "are encrypted using aes-256-cbc and
// stored in the database" — at-rest encryption is unconditional on
// GitLab, so masked=false can never mean "stored in plaintext" the way
// ADO's isSecret=false genuinely does. What masked=true actually buys is
// narrower: GitLab replaces the value with "[MASKED]" in job console
// output. So a sensitive-named, masked=false variable is flagged for the
// real risk it carries on GitLab — its value appearing unredacted in any
// job's log, readable by anyone with job-log access — not for a storage
// property GitLab doesn't have.
func checkSecretMasking(org, repo string, vars []variableRaw, prov []model.Provenance) model.CheckResult {
	var offending []offendingVariable
	for _, v := range vars {
		if !sensitiveVariableNameRE.MatchString(v.Key) {
			continue
		}
		if v.Masked {
			continue
		}
		if v.Value == "" {
			continue // nothing stored — masking an empty value protects nothing
		}
		offending = append(offending, offendingVariable{Key: v.Key})
	}
	sort.Slice(offending, func(i, j int) bool { return offending[i].Key < offending[j].Key })

	factOffending := make([]string, 0, len(offending))
	for _, o := range offending {
		factOffending = append(factOffending, o.Key)
	}
	facts := map[string]any{"offending_variables": factOffending, "offending_count": len(offending)}

	if len(offending) > 0 {
		return model.CheckResult{
			CheckID: idSecretMasking, Title: checkTitle, Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("%d sensitive-named CI/CD variable(s) are not masked — see "+
				"Facts.offending_variables for the variable names, never the values", len(offending)),
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov, Facts: facts,
		}
	}
	return model.CheckResult{
		CheckID: idSecretMasking, Title: checkTitle, Status: model.StatusVerifiedPass,
		Reason: "no sensitive-named CI/CD variable in this project is unmasked",
		Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov, Facts: facts,
	}
}

// Collector implements C04.vars.secret-masking for GitLab.
type Collector struct {
	baseURL, token string
	newClient      func() (*gitlabcollect.Client, error)
}

// New builds the collector against a live GitLab instance.
func New(baseURL, token string) *Collector {
	c := &Collector{baseURL: baseURL, token: token}
	c.newClient = func() (*gitlabcollect.Client, error) { return gitlabcollect.NewClient(baseURL, token) }
	return c
}

// NewForTest builds the collector against an arbitrary base URL and
// round-tripper, so tests exercise the same client production assembles.
func NewForTest(baseURL, token string, newClient func() (*gitlabcollect.Client, error)) *Collector {
	return &Collector{baseURL: baseURL, token: token, newClient: newClient}
}

// ID returns the collector identifier recorded on every result it emits.
func (c *Collector) ID() string { return collectorID }

// Collect reads each repo's CI/CD variables and returns one result per
// repo. A client is built fresh per repo, not once for the whole scope —
// this avoids the cross-repo Provenance() bleed a shared client produces
// when reused across scope.Repos (issue #14), the same convention
// internal/collect/gitlab/repoprotection already uses.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	var out []model.CheckResult
	for _, repo := range scope.Repos {
		out = append(out, c.collectRepo(ctx, scope.Org, repo)...)
	}
	return out, nil
}

func (c *Collector) collectRepo(ctx context.Context, org, repo string) []model.CheckResult {
	client, err := c.newClient()
	if err != nil {
		return []model.CheckResult{{
			CheckID: idSecretMasking, Title: checkTitle, Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not build a GitLab client: %v", err),
			Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform},
		}}
	}

	id := projectID(org, repo)
	vars, err := fetchVariables(ctx, client, id)
	prov := client.Provenance()
	if err != nil {
		return []model.CheckResult{{
			CheckID: idSecretMasking, Title: checkTitle, Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("could not read CI/CD variables: %v", err),
			Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform}, Provenance: prov,
		}}
	}

	return []model.CheckResult{checkSecretMasking(org, repo, vars, prov)}
}

func projectID(org, repo string) string {
	return escapePath(org) + "%2F" + escapePath(repo)
}

func escapePath(s string) string {
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
