package actionssecurity

import (
	"context"
	"net/url"
	"regexp"
	"sort"
	"strings"

	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gopkg.in/yaml.v3"
)

// projectRaw is the subset of GET /projects/:id this collector reads.
//
// AllowForkPipelinesInParent is a *bool, not a bool, and that is the whole
// point of this type. GitLab omits ci_allow_fork_pipelines_to_run_in_parent_
// project entirely from the project payload for a caller below Maintainer —
// verified live 2026-08-13 by fetching gitlab.com/sioakeim/attestward
// unauthenticated, which returned only 21 keys (visibility and
// default_branch among them) and none of the CI settings. Decoded into a
// plain bool that absence is indistinguishable from the field being false,
// which is this collector's SAFEST value and would therefore have produced a
// confident verified-pass for a project whose setting was never read. A nil
// pointer forces the not-checkable path instead.
type projectRaw struct {
	Visibility                 string `json:"visibility"`
	AllowForkPipelinesInParent *bool  `json:"ci_allow_fork_pipelines_to_run_in_parent_project"`
}

// jobTokenScopeRaw is GET /projects/:id/job_token_scope. Only
// InboundEnabled is read: outbound_enabled is deprecated on
// docs.gitlab.com ("Deprecated and planned for removal in GitLab 18.0") and
// was false on this build's own verification project while inbound was true,
// so reading it would report on a control GitLab is retiring.
type jobTokenScopeRaw struct {
	InboundEnabled bool `json:"inbound_enabled"`
}

// runnerRaw is one entry of GET /projects/:id/runners. RunnerType is
// "instance_type", "group_type" or "project_type"; this collector only ever
// requests the latter two (see fetchSelfManagedRunners).
type runnerRaw struct {
	ID          int    `json:"id"`
	Description string `json:"description"`
	RunnerType  string `json:"runner_type"`
}

// variableRaw is the subset of GET /projects/:id/variables needed to spot a
// stored long-lived cloud credential. Value is read ONLY to tell "a
// credential is stored here" from "the variable exists but is empty" — it is
// never copied into a Reason or into Facts.
//
// Hidden matters on its own: GitLab returns Value as null (decodes to "") for
// a masked-and-hidden variable — Ci::VariableValue#evaluate returns nil
// whenever the variable is hidden, regardless of what's actually stored.
// internal/collect/gitlab/secretshygiene's variableRaw omits Hidden safely,
// because it checks Masked before ever looking at Value (hidden implies
// masked, so that check never reaches the empty-value branch) — this
// package has no such check, so treating hidden the same as genuinely-empty
// would read a masked-and-hidden AWS key, exactly the case a careful team
// would configure, as "nothing stored" and ship a false verified-pass.
type variableRaw struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Hidden bool   `json:"hidden"`
}

// ciInclude is one entry of the CI Lint API's `includes` array.
//
// Verified live 2026-08-13 against gitlab.com/sioakeim/attestward-scratch by
// linting configs that used every include form GitLab documents:
//
//	include: project:+ref:+file:  -> type "file",      extra.ref = the ref AS WRITTEN
//	include: component:           -> type "component", location  = "path@version"
//	include: remote:              -> type "remote",    location  = the URL
//	include: local:               -> type "local"
//	include: template:            -> type "template"
//
// extra.ref is what makes this endpoint the right evidence for pinning
// rather than the raw file: it reports the ref the author wrote ("main", a
// full SHA, or "HEAD" when ref: was omitted) even though `blob`/`raw`
// alongside it have already been resolved to the commit that ref pointed at
// when the lint ran. Reading the raw .gitlab-ci.yml instead would see only
// the top-level include: block; this array is resolved transitively (a
// template that itself includes another template appears here too, with a
// null context_project) and honours the project's ci_config_path.
type ciInclude struct {
	Type     string         `json:"type"`
	Location string         `json:"location"`
	Extra    ciIncludeExtra `json:"extra"`
	// ContextProject is the project whose CI config wrote this include, or
	// "" for one pulled in by an already-included file. Recorded in Facts
	// so a reader can tell an include this project is responsible for from
	// one it inherited.
	ContextProject string `json:"context_project"`
}

// ciIncludeExtra is the per-include-type detail block. Only Project/Ref are
// modeled here, which is all this package reads — `extra` isn't limited to
// `include: project:` entries the way an earlier draft of this comment
// claimed: a live lint of gitlab-org/gitlab-runner returned a non-empty
// `extra` (a `rules` block) for a `local:` include too. Project/Ref are
// populated specifically and only for type "file" (`include: project:`),
// which is the one case this package needs — see ciInclude's doc comment.
type ciIncludeExtra struct {
	Project string `json:"project"`
	Ref     string `json:"ref"`
}

// ciLintRaw is GET /projects/:id/ci/lint.
//
// Includes is a *[]ciInclude because null and [] mean different things here
// and both occur: [] is "the config resolved and referenced no external
// file", null is "GitLab could not resolve the config at all" — either
// because the project has no CI configuration ("Please provide content of
// .gitlab-ci.yml") or because an include itself failed to resolve. Only the
// second reading is safe to treat as evidence of nothing being included, so
// the two must stay distinguishable. Both cases were reproduced live.
type ciLintRaw struct {
	Valid      bool         `json:"valid"`
	Errors     []string     `json:"errors"`
	MergedYAML string       `json:"merged_yaml"`
	Includes   *[]ciInclude `json:"includes"`
}

func fetchProject(ctx context.Context, client *gitlabcollect.Client, projID string) (projectRaw, error) {
	var p projectRaw
	err := gitlabcollect.GetJSON(ctx, client, "/projects/"+projID, nil, &p)
	return p, err
}

func fetchCILint(ctx context.Context, client *gitlabcollect.Client, projID string) (ciLintRaw, error) {
	var l ciLintRaw
	err := gitlabcollect.GetJSON(ctx, client, "/projects/"+projID+"/ci/lint", nil, &l)
	return l, err
}

func fetchJobTokenScope(ctx context.Context, client *gitlabcollect.Client, projID string) (jobTokenScopeRaw, error) {
	var s jobTokenScopeRaw
	err := gitlabcollect.GetJSON(ctx, client, "/projects/"+projID+"/job_token_scope", nil, &s)
	return s, err
}

// fetchSelfManagedRunners lists the runners this project brings of its own,
// asking for the two self-managed types explicitly rather than filtering the
// unfiltered listing client-side. On gitlab.com that listing returned 125
// entries across 2 pages for a project with a single project runner — every
// other entry was one of GitLab's own shared instance runners — so the
// filter is what keeps this from paging through the SaaS runner fleet on
// every repo in scope.
func fetchSelfManagedRunners(ctx context.Context, client *gitlabcollect.Client, projID string) ([]runnerRaw, error) {
	var all []runnerRaw
	for _, runnerType := range []string{"project_type", "group_type"} {
		page, err := gitlabcollect.GetJSONPaged[runnerRaw](ctx, client, "/projects/"+projID+"/runners", url.Values{"type": {runnerType}})
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
	}
	return all, nil
}

func fetchVariables(ctx context.Context, client *gitlabcollect.Client, projID string) ([]variableRaw, error) {
	return gitlabcollect.GetJSONPaged[variableRaw](ctx, client, "/projects/"+projID+"/variables", nil)
}

// -----------------------------------------------------------------------
// include classification
// -----------------------------------------------------------------------

// fullSHAPattern matches a full-length SHA-1 commit SHA, the only commit
// object format GitLab.com serves. SHA-256 repositories (64 hex characters)
// are an experimental GitLab feature that this build has never observed, so
// no branch exists for them here — the same judgment internal/collect/gitlab/
// secretshygiene made about the `hidden` variable flag. A 64-character ref
// would be reported as unpinned; that is a known, deliberate limit rather
// than an oversight.
var fullSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func isFullSHA(ref string) bool { return fullSHAPattern.MatchString(ref) }

// remoteURLCommitSHASegment matches a full commit SHA appearing as its own
// path segment of a remote include's URL — the "/-/raw/<sha>/<file>" form
// GitLab (and GitHub) serve a blob at a specific commit under. That form is
// the ONLY way a `remote:` include can be immutable, since the include
// itself carries no ref or version to pin, so recognizing it is what keeps
// this check from reporting a genuinely pinned remote include as unpinned.
// Verified live: linting `remote: https://gitlab.com/sioakeim/attestward/-/
// raw/<sha>/.gitlab-ci.yml` resolved successfully and came back as type
// "remote" with that URL as its location.
var remoteURLCommitSHASegment = regexp.MustCompile(`(?:^|/)[0-9a-fA-F]{40}(?:/|$)`)

// includeClass is how classifyInclude sorts an entry of the lint response's
// `includes` array.
type includeClass string

const (
	// classPinnable is an include that names external CI configuration and
	// carries a ref/version this check can judge.
	classPinnable includeClass = "pinnable"
	// classNotPinnable is an include with no pinning mechanism to judge and
	// no external-supply-chain exposure to flag: `local:` (a file in this
	// same repo, already fixed by the repo's own commit) and `template:`
	// (shipped by the GitLab instance itself, addressed by name with no ref
	// at all — flagging it would report a finding with no possible
	// remediation).
	classNotPinnable includeClass = "not-pinnable"
	// classUnknown is an include type this build does not recognize.
	// GitLab has added include types over time, and treating an unfamiliar
	// one as safe is how a check silently narrows; it caps the result at
	// partial instead.
	classUnknown includeClass = "unknown"
)

// includeFinding is one classified include, carrying only what Facts and the
// Reason need.
type includeFinding struct {
	Class          includeClass
	Type           string
	Location       string
	Ref            string
	Pinned         bool
	ContextProject string
}

// classifyInclude decides whether one resolved include is pinned to an
// immutable commit.
//
// The three pinnable forms are judged on different fields because GitLab
// addresses them differently:
//
//   - type "file" (an `include: project:` entry) carries the ref as written
//     in extra.ref — a branch, a tag, a full SHA, or the literal "HEAD"
//     when the author omitted ref: entirely. Only a full SHA is pinned;
//     "HEAD" resolves to the target project's default branch and moves with
//     every push to it.
//   - type "component" carries "<path>@<version>" in location. A catalog
//     release version ("@1.2.0") is a tag, and a tag can be moved, so only
//     a full SHA counts here too.
//   - type "remote" carries a bare URL and has no ref or version field at
//     all; see remoteURLCommitSHASegment for the one URL shape that is
//     nonetheless immutable.
func classifyInclude(inc ciInclude) includeFinding {
	f := includeFinding{Type: inc.Type, Location: inc.Location, ContextProject: inc.ContextProject}
	switch inc.Type {
	case "file":
		f.Class = classPinnable
		f.Ref = inc.Extra.Ref
		f.Pinned = isFullSHA(inc.Extra.Ref)
	case "component":
		f.Class = classPinnable
		if at := strings.LastIndex(inc.Location, "@"); at >= 0 {
			f.Ref = inc.Location[at+1:]
		}
		f.Pinned = isFullSHA(f.Ref)
	case "remote":
		f.Class = classPinnable
		f.Pinned = remoteURLHasCommitSHA(inc.Location)
	case "local", "template":
		f.Class = classNotPinnable
	default:
		f.Class = classUnknown
	}
	return f
}

// remoteURLHasCommitSHA reports whether a remote include's URL addresses a
// specific commit. Only the PATH is examined: a SHA in a query string or
// fragment does not make the URL's response immutable, and a URL this build
// cannot parse is treated as unpinned rather than guessed at.
func remoteURLHasCommitSHA(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return remoteURLCommitSHASegment.MatchString(u.Path)
}

func classifyIncludes(includes []ciInclude) []includeFinding {
	out := make([]includeFinding, 0, len(includes))
	for _, inc := range includes {
		out = append(out, classifyInclude(inc))
	}
	return out
}

func includeFindingsToFacts(findings []includeFinding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]any{
			"type": f.Type, "location": f.Location, "ref": f.Ref,
			"pinned": f.Pinned, "context_project": f.ContextProject,
		})
	}
	return out
}

// -----------------------------------------------------------------------
// merged CI configuration
// -----------------------------------------------------------------------

// idTokenJobs returns the names of every top-level entry in the merged CI
// configuration that declares an `id_tokens:` block — GitLab's OIDC keyword.
//
// It scans top-level entries generically instead of enumerating job names
// because `id_tokens:` is valid both on a job and in the `default:` section
// that jobs inherit from, and the merged YAML the lint API returns keeps
// them separate rather than folding default: into each job (verified live:
// a config with `default: id_tokens:` plus a per-job one came back with
// both intact). Anything else at the top level — stages:, variables:,
// workflow:, include: — simply has no id_tokens key, so no reserved-word
// list is needed to skip them.
//
// A merged document that does not parse yields no names and no error: it is
// GitLab's own output, so a parse failure here means this build's YAML
// expectations are wrong rather than the project's config being bad, and
// silently reporting "no OIDC configured" is the wrong response. Callers
// therefore take the parse-failure signal from ok, not from the slice.
func idTokenJobs(mergedYAML string) (names []string, ok bool) {
	if strings.TrimSpace(mergedYAML) == "" {
		return nil, false
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(mergedYAML), &doc); err != nil {
		return nil, false
	}
	for key, value := range doc {
		body, isMap := value.(map[string]any)
		if !isMap {
			continue
		}
		if _, declared := body["id_tokens"]; declared {
			names = append(names, key)
		}
	}
	// Sorted because the source is a Go map: without this the same config
	// would produce a different Facts ordering on every run, and a pack is
	// meant to be comparable between scans.
	sort.Strings(names)
	return names, true
}

// staticCloudCredentialVariables are the exact CI/CD variable names that
// hold a long-lived cloud credential because a cloud SDK reads that
// environment variable by that name. Each is a documented convention of the
// consumer named alongside it, not a naming guess — which is why this is an
// exact-match set rather than the fuzzy (?i)(secret|token|key) pattern
// internal/collect/gitlab/secretshygiene uses for its own, different
// question ("is this masked in job logs"). A variable called MY_API_TOKEN is
// a secret but tells you nothing about how this project authenticates to a
// cloud; AWS_SECRET_ACCESS_KEY tells you exactly that.
//
// Case-sensitive on purpose: these are consumed as process environment
// variables, which are case-sensitive on the Linux runners GitLab CI uses,
// so a lowercase variant would not actually be picked up by the SDK and is
// not evidence of static-credential authentication.
var staticCloudCredentialVariables = map[string]string{
	"AWS_ACCESS_KEY_ID":              "aws",
	"AWS_SECRET_ACCESS_KEY":          "aws",
	"AZURE_CLIENT_SECRET":            "azure",
	"GOOGLE_APPLICATION_CREDENTIALS": "gcp",
	"GOOGLE_CREDENTIALS":             "gcp",
}

// staticCredentialFinding names one stored long-lived cloud credential —
// the variable's KEY and which cloud reads it, with no Value field on the
// type at all so no future refactor can forward a credential into Facts.
type staticCredentialFinding struct {
	Key   string
	Cloud string
}

// findStaticCloudCredentials returns the stored long-lived cloud
// credentials among a project's own CI/CD variables. A genuinely empty,
// unhidden value is skipped: the variable exists but holds nothing, so
// nothing is stored to be long-lived. A hidden variable is never skipped on
// that basis — GitLab always returns Value == "" for one regardless of what
// it holds (see variableRaw's doc comment), and GitLab enforces the masking
// minimum length at creation, so a hidden variable definitionally holds a
// value.
func findStaticCloudCredentials(vars []variableRaw) []staticCredentialFinding {
	var out []staticCredentialFinding
	for _, v := range vars {
		cloud, recognized := staticCloudCredentialVariables[v.Key]
		if !recognized || (v.Value == "" && !v.Hidden) {
			continue
		}
		out = append(out, staticCredentialFinding{Key: v.Key, Cloud: cloud})
	}
	return out
}

func staticCredentialFindingsToFacts(findings []staticCredentialFinding) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, map[string]any{"key": f.Key, "cloud": f.Cloud})
	}
	return out
}
