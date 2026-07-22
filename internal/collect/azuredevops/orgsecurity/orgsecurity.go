// Package orgsecurity implements C01 org-security for Azure DevOps: the same
// four check IDs internal/collect/github/orgsecurity registers (issue #34's
// check-identity model — same ID, per-platform everything else), each
// re-derived from ADO's own surfaces instead of GitHub's org object.
//
// This is the epic's flagship "honest degradation" collector, and it reads
// noticeably worse than its GitHub twin on purpose:
//
//   - C01.org.2fa-required can never reach verified-pass here, only
//     verified-fail/partial/not-checkable. ADO itself has no
//     "require 2FA for the org" toggle to read — the closest observable
//     proxy is the Graph API's per-identity `origin` field. An `msa`
//     (Microsoft/personal) identity sits entirely outside any Microsoft
//     Entra tenant's Conditional Access policies, so its presence is a
//     genuine, verifiable fail. But an org where every classifiable human
//     identity is `aad` only proves the org is Entra-backed — whether that
//     tenant actually *requires* MFA lives in Conditional Access, a
//     Microsoft Graph/Entra surface no `vso.*` PAT scope reaches. Asserting
//     verified-pass from `aad`-only evidence would be a claim this tool
//     can't back up, so the best that case gets is partial — a deliberate
//     under-claim (epic #34 open decision 3), not a gap to be "fixed" later
//     without a real Entra/Graph integration. Two further origin values
//     matter here: `vsts` (Azure DevOps' own build-service identities,
//     which present as subjectKind=="user" despite being service accounts,
//     not humans) is excluded from the aad/msa count entirely, the same as
//     a servicePrincipal/group subjectKind would be. `ghb` (GitHub-linked
//     human accounts — a real ADO sign-up path) and any other unrecognized
//     origin ARE human but can't be classified as Entra-backed or not, so
//     their presence forces not-checkable rather than a silently-rounded
//     partial claim — see check2FARequired and graphClassification's own
//     doc comments.
//   - C01.org.members-without-2fa and C01.org.default-repo-permission are
//     not-checkable always, by design, with no API call of their own —
//     the same shape as
//     internal/collect/github/auditlogging's C09.audit.log-streaming: no
//     endpoint exists for either question at all (per-user MFA registration
//     state is an Entra/Graph concept; default repository access in ADO is
//     security-group/ACL-based, and ACL reads are out of scope for v0.2 —
//     see issue #34's non-goals), so there is nothing for a future version
//     of this collector to "start calling" without a scope decision this
//     issue explicitly defers.
//   - C01.org.members-can-create-public asks the closest ADO analogue of
//     GitHub's repo-visibility policy: project visibility. It can prove a
//     genuine fail (a public project exists) but never a genuine pass: zero
//     public projects is consistent with "the org disallows creating them"
//     and with "the org allows it but nobody has used it yet", and the
//     org-policy setting that would tell them apart lives behind an
//     undocumented API this tool does not call (ADR-0004/CLAUDE.md: no
//     write calls, and separately, no undocumented-endpoint calls either).
package orgsecurity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/model"
)

// collectorID matches the GitHub twin's exactly (collect.Register panics if
// two platforms register the same check ID under different Collector
// strings — see registry.go's own doc comment) — this is what lets
// checksref group both platforms' metadata under one "C01.org-security"
// heading instead of two unrelated ones.
const collectorID = "C01.org-security"

const (
	id2FARequired            = "C01.org.2fa-required"
	idMembersWithout2FA      = "C01.org.members-without-2fa"
	idDefaultRepoPermission  = "C01.org.default-repo-permission"
	idMembersCanCreatePublic = "C01.org.members-can-create-public"
)

// checkTitles gives each check ID this platform's own Title — allowed to
// differ from the GitHub twin's wording (epic #34 open decision 4: same ID,
// per-platform Title), since ADO's actual subject differs even where the ID
// is shared (e.g. "public projects", not "public repositories" — ADO's
// visibility control lives at the project level, not per-repository).
var checkTitles = map[string]string{
	id2FARequired:            "Org requires two-factor authentication",
	idMembersWithout2FA:      "Count of members without two-factor authentication",
	idDefaultRepoPermission:  "Default repository permission for members",
	idMembersCanCreatePublic: "Whether members can create public projects",
}

var checkRemediations = map[string]string{
	id2FARequired: "Azure DevOps has no direct \"require 2FA\" organization toggle. MFA enforcement is a " +
		"Microsoft Entra ID Conditional Access policy applied to the tenant backing this org: in the Microsoft " +
		"Entra admin center, create (or verify) a Conditional Access policy requiring MFA for all users, and " +
		"migrate any Microsoft Account (MSA, origin=msa) members to Entra-backed (aad) identities — Organization " +
		"Settings -> Users, or by moving the org under a Microsoft Entra tenant if it isn't backed by one " +
		"already. If this check instead reports not-checkable because members have an origin this tool doesn't " +
		"recognize (e.g. GitHub-linked \"ghb\" accounts), the same migration to an Entra-backed (aad) identity " +
		"removes the ambiguity, independent of whatever this tool later decides that origin should count as.",
	idMembersWithout2FA: "Not remediable via this tool: per-user MFA registration state is a Microsoft Entra " +
		"ID / Microsoft Graph concept, not exposed through any Azure DevOps API or vso.* PAT scope. Review MFA " +
		"registration in the Microsoft Entra admin center (Users -> Per-user MFA, or the Conditional Access " +
		"sign-in logs) instead.",
	idDefaultRepoPermission: "Not remediable via this tool: Azure DevOps grants default repository access " +
		"through security groups and ACLs (Project Settings -> Permissions, and per-repository Security tabs), " +
		"not a single org-level field. Review the \"Project Collection Valid Users\" / per-project " +
		"\"Contributors\" group's default permissions directly in the ADO UI.",
	idMembersCanCreatePublic: "Organization Settings -> Policies -> turn off \"Allow public projects\" (or, " +
		"per project, set visibility to Private under Project Settings -> Overview) so members can't create or " +
		"keep a publicly visible project without an explicit, separately reviewed change.",
}

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce. Two of these four checks (id2FARequired,
// idMembersCanCreatePublic) deliberately can never reach verified-pass — see
// the package doc comment for why an aad-only org or a zero-public-project
// org each stop at a weaker claim instead. The other two
// (idMembersWithout2FA, idDefaultRepoPermission) can only ever produce
// not-checkable, mirroring
// internal/collect/github/auditlogging's C09.audit.log-streaming precedent
// for a check with no backing API at all.
var checkRubrics = map[string]map[model.Status]string{
	id2FARequired: {
		model.StatusVerifiedFail: "at least one org identity returned by the Graph Users list " +
			"(subjectKind==\"user\") has origin==\"msa\" — a Microsoft/personal account, which sits entirely " +
			"outside any Microsoft Entra tenant's MFA/Conditional Access enforcement, so 2FA cannot be assumed " +
			"for that member at all (the exact count is recorded in Facts; member names/identities are " +
			"deliberately never recorded)",
		model.StatusPartial: "no org identity has origin==\"msa\", at least one has origin==\"aad\", and none " +
			"have any other unrecognized origin among subjectKind==\"user\" entries (origin==\"vsts\" service " +
			"identities are excluded from this count entirely, not treated as unrecognized — see " +
			"Facts.vsts_service_identity_count) — every human identity this tool could classify authenticates " +
			"via Microsoft Entra ID. This states only what was verified, not full MFA enforcement: that lives " +
			"in Microsoft Entra Conditional Access, a surface no vso.* PAT scope reaches, so this cannot exceed " +
			"partial (epic #34 open decision 3)",
		model.StatusNotCheckable: "the Graph Users list (GET vssps.dev.azure.com/{org}/_apis/graph/users) " +
			"couldn't be read (403/404/other API error); or it read successfully but at least one " +
			"subjectKind==\"user\" identity has an origin this tool doesn't classify as aad or msa (e.g. " +
			"GitHub-linked \"ghb\" accounts — see Facts.other_origin_user_count), so it can't assert the org is " +
			"uniformly Entra-backed; or zero identities with a recognized human origin were found at all, " +
			"leaving nothing to evaluate",
	},
	idMembersWithout2FA: {
		model.StatusNotCheckable: "always — per-user two-factor/MFA registration state lives in Microsoft " +
			"Entra ID / Microsoft Graph, a different API and service than anything a vso.* PAT scope reaches; " +
			"no Azure DevOps endpoint exposes it. Facts carries msa_user_count as context only, borrowed from " +
			"the same Graph Users call C01.org.2fa-required makes (see that check's own Endpoints) when that " +
			"call succeeded — it is not evidence this check itself gathered",
	},
	idDefaultRepoPermission: {
		model.StatusNotCheckable: "always — Azure DevOps has no single org-level default-repository-permission " +
			"field; repository access is governed per security-group/ACL " +
			"(_apis/accesscontrollists), out of scope for v0.2 (issue #34's non-goals) — there is no API this " +
			"tool calls to determine a default permission",
	},
	idMembersCanCreatePublic: {
		model.StatusVerifiedFail: "at least one project returned by GET dev.azure.com/{org}/_apis/projects has " +
			"visibility==\"public\" (Facts records which project(s) and how many)",
		model.StatusNotCheckable: "either the org's project list couldn't be read (403/404/other API error), " +
			"or it read successfully but zero projects are currently public — a policy that disallows public " +
			"projects and a policy that allows it but is simply unused look identical from this endpoint alone " +
			"(the org-policy setting itself lives behind an undocumented API this tool does not call), so a " +
			"genuine pass can't be told apart from an unused allowance",
	},
}

// checkEndpoints lists which REST endpoint(s) actually back each check's
// status. idMembersWithout2FA and idDefaultRepoPermission are deliberately
// nil: neither makes any API call of its own at all, so nothing backs their
// (permanently fixed) not-checkable status — see checkRubrics' own doc
// comment. Unlike the GitHub twin's path-only convention, these strings
// include the host (matching model.Provenance.Endpoint's own host+path
// convention here — see internal/collect/azuredevops/transport.go's doc
// comment): a single ADO scan spans multiple hosts, so a path alone would
// be ambiguous about which one a check's evidence actually came from.
var checkEndpoints = map[string][]string{
	id2FARequired:            {"GET vssps.dev.azure.com/{org}/_apis/graph/users"},
	idMembersWithout2FA:      nil,
	idDefaultRepoPermission:  nil,
	idMembersCanCreatePublic: {"GET dev.azure.com/{org}/_apis/projects"},
}

// checkTokenScopes gives each check's token-permission story. All four are
// documented even though two checks make no call at all (matching
// auditlogging's identical choice for C09.audit.log-streaming/
// retention-awareness) — a reader digging into why a check is permanently
// not-checkable may still want to know what surface (if any) would need to
// exist for it to ever become verifiable.
var checkTokenScopes = map[string]string{
	id2FARequired: "vso.graph (Graph Users - List)",
	idMembersWithout2FA: "none — per-user MFA registration state has no vso.* scope at all; it lives in " +
		"Microsoft Entra ID / Microsoft Graph, a separate service with its own (non-ADO) auth model",
	idDefaultRepoPermission: "none — default repository permission has no vso.* scope; ADO exposes no " +
		"org-level field for it at all (see this check's Rubric)",
	idMembersCanCreatePublic: "vso.project (Projects - List)",
}

const fixtureRef = "internal/collect/azuredevops/orgsecurity/orgsecurity_test.go"

func init() {
	for id, title := range checkTitles {
		collect.Register(collect.CheckMeta{
			ID:          id,
			Platform:    "azuredevops",
			Title:       title,
			Collector:   collectorID,
			TokenScope:  checkTokenScopes[id],
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
}

// Collector implements C01 org-security for Azure DevOps.
type Collector struct {
	client *azuredevops.Client
}

// New returns a C01 collector using client for all API calls. As with the
// GitHub twin, give each collector instance its own Client — Client.Provenance()
// reflects every call made through it, and this collector attributes
// provenance to individual CheckResults by diffing that log, which only
// stays correct if nothing else issues calls through the same Client
// concurrently.
func New(client *azuredevops.Client) *Collector {
	return &Collector{client: client}
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error: an org-level API failure becomes a not-checkable result
// for the specific check(s) that depended on it, so the rollup engine can
// still resolve every other check against mappings/ssdf-800-218.yaml's
// checks[] lists — the same reasoning the GitHub twin's Collect doc comment
// gives for why a generic collector-level error would be worse than four
// individually-attributed ones.
//
// Unlike the GitHub twin, there is no personal-account short-circuit here:
// collect.Scope.AccountType is a GitHub-specific concept (an Azure DevOps
// organization has no "personal account" counterpart at this level), so it
// is never consulted.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	graphStart := len(c.client.Provenance())
	users, graphErr := fetchGraphUsers(ctx, c.client)
	graphProv := tailProvenance(c.client.Provenance(), graphStart)

	var class graphClassification
	if graphErr == nil {
		class = classifyGraphUsers(users)
	}

	projStart := len(c.client.Provenance())
	projects, projErr := fetchProjects(ctx, c.client)
	projProv := tailProvenance(c.client.Provenance(), projStart)

	return []model.CheckResult{
		check2FARequired(scope, class, graphErr, graphProv),
		checkMembersWithout2FA(scope, class, graphErr),
		checkDefaultRepoPermission(scope),
		checkMembersCanCreatePublic(scope, projects, projErr, projProv),
	}, nil
}

// graphUserRaw is the subset of Azure DevOps Graph's GraphUser shape (Users
// - List) this package needs: subjectKind distinguishes a real user from a
// group/service principal/other subject kind, and origin (only meaningful
// for subjectKind=="user") is the identity provider backing it — "aad"
// (Microsoft Entra ID) or "msa" (Microsoft/personal account).
type graphUserRaw struct {
	SubjectKind string `json:"subjectKind"`
	Origin      string `json:"origin"`
}

const (
	subjectKindUser = "user"
	originAAD       = "aad"
	originMSA       = "msa"
	// originVSTS is Azure DevOps' own build-service/service identities —
	// these arrive in the Graph Users list as subjectKind=="user" (not a
	// distinct subjectKind ADO could be filtered on), per Microsoft's own
	// documented sample response, so they have to be excluded by origin
	// instead — see graphClassification's own doc comment.
	originVSTS = "vsts"
)

// fetchGraphUsers lists every subject in the org's Graph via GET
// vssps.dev.azure.com/{org}/_apis/graph/users (scope vso.graph), paginating
// via GetJSON's X-MS-ContinuationToken handling. No subjectKind/origin
// filter is sent as a query parameter — this project's own [fixture-verify]
// posture is to filter client-side (classifyGraphUsers) against the
// documented response shape, the same choice
// internal/collect/azuredevops/pipelinehistory makes for its own filtering
// (e.g. category matching after the fact, not via an unverified query
// parameter).
func fetchGraphUsers(ctx context.Context, client *azuredevops.Client) ([]graphUserRaw, error) {
	path := fmt.Sprintf("/%s/_apis/graph/users", client.Org())
	query := url.Values{"api-version": {"7.1-preview.1"}}

	var raw []graphUserRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostGraph, path, query, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// graphClassification is the origin-based counts classifyGraphUsers derives
// from one Graph Users fetch — counts only, never the identities themselves
// (the evidence pack may be shared with agencies; see check2FARequired's
// own Facts). aadCount/msaCount feed 2fa-required's fail/partial logic
// directly; vstsServiceIdentityCount and otherOriginUserCount exist so an
// identity this tool can't (or, for vsts, shouldn't) fold into aad/msa is
// tracked rather than silently dropped — see each field's own doc comment.
type graphClassification struct {
	aadCount int
	msaCount int
	// vstsServiceIdentityCount counts subjectKind=="user" identities whose
	// origin is "vsts" — Azure DevOps' own build-service/service identities,
	// which present as subjectKind=="user" despite not being a human
	// account at all (see originVSTS's own doc comment). Excluded from
	// aad/msa entirely, and NOT folded into otherOriginUserCount below: a
	// recognized service identity and a genuinely-unclassifiable human
	// identity mean different things for 2fa-required's rubric, so they're
	// counted separately rather than blurred together.
	vstsServiceIdentityCount int
	// otherOriginUserCount counts subjectKind=="user" identities whose
	// origin is anything other than aad/msa/vsts — most notably "ghb"
	// (GitHub-linked human accounts, a first-class ADO sign-up flow) or any
	// origin value this collector doesn't yet recognize. Unlike vsts,
	// these ARE human identities this tool simply can't classify as
	// Entra-backed or not — see check2FARequired's own doc comment for why
	// their presence forces not-checkable rather than a guess.
	otherOriginUserCount int
}

// classifyGraphUsers buckets every subjectKind=="user" identity by origin.
// Every other subjectKind (servicePrincipal, group, aggregate, ...) is
// excluded structurally, matching issue #150's spec text ("svc/imp
// excluded") — those have no personal MFA posture to classify at all. That
// spec text undersells one real case, though: within subjectKind=="user",
// origin=="vsts" identities are ALSO service-like (Azure DevOps' own
// build-service accounts arrive this way — see originVSTS's own doc
// comment) and have to be excluded here, by origin, since ADO's Graph API
// gives them no distinct subjectKind to filter on structurally. Anything
// left over (an origin this collector doesn't recognize, e.g. "ghb") is
// counted, not silently dropped: earlier code discarded these, which let
// an org made entirely of unrecognized-origin identities render a vacuous
// "0 human members, all aad" partial claim in signed evidence — see
// check2FARequired's own doc comment for how otherOriginUserCount is used
// to refuse that claim instead.
func classifyGraphUsers(users []graphUserRaw) graphClassification {
	var c graphClassification
	for _, u := range users {
		if u.SubjectKind != subjectKindUser {
			continue
		}
		switch u.Origin {
		case originAAD:
			c.aadCount++
		case originMSA:
			c.msaCount++
		case originVSTS:
			c.vstsServiceIdentityCount++
		default:
			c.otherOriginUserCount++
		}
	}
	return c
}

// projectRaw is the subset of Azure DevOps's Project shape (Projects -
// List) checkMembersCanCreatePublic needs.
type projectRaw struct {
	Name       string `json:"name"`
	Visibility string `json:"visibility"`
}

const projectVisibilityPublic = "public"

// fetchProjects lists every project in the org via GET
// dev.azure.com/{org}/_apis/projects (scope vso.project).
func fetchProjects(ctx context.Context, client *azuredevops.Client) ([]projectRaw, error) {
	path := fmt.Sprintf("/%s/_apis/projects", client.Org())
	query := url.Values{"api-version": {"7.1"}}

	var raw []projectRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// check2FARequired never reaches verified-pass — see the package doc
// comment for the full rationale. It also never rounds an org with
// unclassifiable human identities up to partial: partial asserts "every
// human identity this tool could classify authenticates via Entra ID
// (aad)", and that claim isn't available when otherOriginUserCount > 0 (an
// origin such as "ghb" — GitHub-linked accounts — or anything else this
// collector doesn't recognize). Those cases fall through to not-checkable
// instead, naming exactly what's unclassifiable, rather than being folded
// silently into either count — that silent fold was the actual bug: an org
// made entirely of such identities used to read as "0 human members, all
// aad" and pass through to partial anyway. Whether an unrecognized/"ghb"
// origin should instead be treated like "msa" (also outside any Entra
// tenant's Conditional Access) is an open question for the epic owner —
// see issue #150 — not decided here; this only refuses to overclaim while
// that's unresolved.
func check2FARequired(scope collect.Scope, class graphClassification, graphErr error, prov []model.Provenance) model.CheckResult {
	const id = id2FARequired
	if graphErr != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason:     apiErrorReason(graphErr, "org Graph users"),
			Scope:      model.ScopeRef{Org: scope.Org},
			Provenance: prov,
		}
	}

	facts := map[string]any{
		"aad_user_count":              class.aadCount,
		"msa_user_count":              class.msaCount,
		"vsts_service_identity_count": class.vstsServiceIdentityCount,
		"other_origin_user_count":     class.otherOriginUserCount,
	}

	if class.msaCount > 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("%d org member(s) authenticate via a Microsoft/personal account (origin=msa), "+
				"which sits entirely outside any Microsoft Entra tenant's MFA/Conditional Access enforcement", class.msaCount),
			Scope: model.ScopeRef{Org: scope.Org}, Provenance: prov, Facts: facts,
		}
	}

	if class.aadCount > 0 && class.otherOriginUserCount == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusPartial,
			Reason: fmt.Sprintf("no org member authenticates via a Microsoft/personal account (msa), and every "+
				"one of the %d human member(s) this tool could classify authenticates via Microsoft Entra ID "+
				"(aad) — MFA enforcement itself lives in Microsoft Entra Conditional Access, which this tool "+
				"cannot inspect, so this states only what was verified and caps at partial rather than "+
				"verified-pass", class.aadCount),
			Scope: model.ScopeRef{Org: scope.Org}, Provenance: prov, Facts: facts,
		}
	}

	reason := "no org member with a recognized human origin (aad or msa) was found among the Graph Users " +
		"list's subjectKind==\"user\" entries — nothing to evaluate"
	if class.otherOriginUserCount > 0 {
		reason = fmt.Sprintf("%d org member(s) have an origin this tool doesn't classify as Microsoft Entra ID "+
			"(aad) or a Microsoft/personal account (msa) — e.g. GitHub-linked (origin=ghb) accounts, or another "+
			"value this collector doesn't yet recognize — so whether the org is uniformly Entra-backed can't be "+
			"determined (see Facts.other_origin_user_count)", class.otherOriginUserCount)
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: reason,
		Scope:  model.ScopeRef{Org: scope.Org}, Provenance: prov, Facts: facts,
	}
}

// checkMembersWithout2FA is not-checkable always — see the package doc
// comment and this check's own Rubric entry for why no API call could ever
// change that. facts carries msa_user_count only when the Graph fetch
// backing C01.org.2fa-required itself succeeded (graphErr == nil) — when it
// failed, there is no borrowed context to offer either, and the map stays
// empty (omitted from the marshaled result via Facts' omitempty tag).
func checkMembersWithout2FA(scope collect.Scope, class graphClassification, graphErr error) model.CheckResult {
	const id = idMembersWithout2FA
	facts := map[string]any{}
	if graphErr == nil {
		facts["msa_user_count"] = class.msaCount
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "per-user two-factor/MFA registration state lives in Microsoft Entra ID / Microsoft Graph — a " +
			"different API and service than any vso.* PAT scope reaches; no Azure DevOps endpoint exposes it",
		Scope: model.ScopeRef{Org: scope.Org}, Provenance: []model.Provenance{},
		Facts: facts,
	}
}

// checkDefaultRepoPermission is not-checkable always, with no API call at
// all — see the package doc comment and this check's own Rubric entry.
func checkDefaultRepoPermission(scope collect.Scope) model.CheckResult {
	const id = idDefaultRepoPermission
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "Azure DevOps has no single org-level default-repository-permission field; repository access " +
			"is governed by security groups and ACLs (_apis/accesscontrollists), out of scope for v0.2 (issue " +
			"#34's non-goals) — there is no API this tool calls to determine a default permission",
		Scope: model.ScopeRef{Org: scope.Org}, Provenance: []model.Provenance{},
	}
}

// checkMembersCanCreatePublic never reaches verified-pass — see the package
// doc comment for the full rationale (zero public projects today doesn't
// distinguish a real policy-off org from an unused policy-on one).
func checkMembersCanCreatePublic(scope collect.Scope, projects []projectRaw, err error, prov []model.Provenance) model.CheckResult {
	const id = idMembersCanCreatePublic
	if err != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason:     apiErrorReason(err, "org projects"),
			Scope:      model.ScopeRef{Org: scope.Org},
			Provenance: prov,
		}
	}

	var publicNames []string
	for _, p := range projects {
		if p.Visibility == projectVisibilityPublic {
			publicNames = append(publicNames, p.Name)
		}
	}

	if len(publicNames) > 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
			Reason: fmt.Sprintf("%d project(s) are publicly visible: %s", len(publicNames), strings.Join(publicNames, ", ")),
			Scope:  model.ScopeRef{Org: scope.Org}, Provenance: prov,
			Facts: map[string]any{"public_project_count": len(publicNames), "public_project_names": publicNames},
		}
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "zero projects are currently public — a policy that disallows public projects and one that " +
			"allows it but is simply unused look identical from this endpoint alone (the underlying org-policy " +
			"setting lives behind an undocumented API this tool does not call), so a genuine pass can't be told " +
			"apart from an unused allowance",
		Scope: model.ScopeRef{Org: scope.Org}, Provenance: prov,
		Facts: map[string]any{"public_project_count": 0},
	}
}

// apiErrorReason turns a GetJSON/GetJSONObject failure into a Reason string,
// naming the exact permission/existence problem when err is a
// *azuredevops.StatusError with a 403 or 404 status — the same
// distinguish-what-we-can approach the GitHub twin's notCheckableReason
// takes — and falling back to the raw error otherwise (transport failure,
// a status this function doesn't special-case, or decode error).
func apiErrorReason(err error, what string) string {
	var statusErr *azuredevops.StatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read %s (403)", what)
		case http.StatusNotFound:
			return fmt.Sprintf("%s not found (404) — the org may not exist, or this resource is unreachable", what)
		}
	}
	return fmt.Sprintf("could not read %s: %v", what, err)
}

// tailProvenance returns the entries of prov after the first skip of them,
// as a non-nil slice (schema invariant: Provenance must never be nil) — the
// same helper the GitHub twin uses to attribute only the calls a specific
// check triggered, not the whole client's cumulative log.
func tailProvenance(prov []model.Provenance, skip int) []model.Provenance {
	if skip >= len(prov) {
		return []model.Provenance{}
	}
	return prov[skip:]
}
