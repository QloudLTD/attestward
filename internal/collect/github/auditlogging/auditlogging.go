// Package auditlogging implements C09 audit-logging: whether the org's
// audit log is reachable via the API, whether audit-log export/streaming
// is configured, GitHub's documented audit-log retention window (context
// only, not verified against the org), and whether repo webhooks export
// push/release/deployment events to an external destination (SSDF PO.5.1
// — matches CISA form clause 1b, "logging, monitoring, and auditing trust
// relationships", which cites PO.5.1 directly).
//
// This collector is expected to report not-checkable more often than any
// other: GitHub's org audit-log API is Enterprise-only in practice, and
// audit-log streaming configuration has no organization-scoped API
// surface at all (it exists exclusively at the Enterprise-account level,
// which this tool has no concept of — see checkLogStreaming). That's
// correct, honest behavior, not a gap in this collector — the
// self-attestation questionnaire (issue #23) is where a documented
// fallback ("we export logs to X with retention Y") belongs.
package auditlogging

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	ghgithub "github.com/google/go-github/v75/github"

	"github.com/sioakim/ssdf/internal/collect"
	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/model"
)

const collectorID = "C09.audit-logging"

const (
	orgLogAvailableID    = "C09.audit.org-log-available"
	logStreamingID       = "C09.audit.log-streaming"
	retentionAwarenessID = "C09.audit.retention-awareness"
	webhooksID           = "C09.repo.webhooks"
)

var checkTitles = map[string]string{
	orgLogAvailableID:    "Organization audit log is reachable via the API",
	logStreamingID:       "Audit-log export/streaming is configured",
	retentionAwarenessID: "Audit-log retention window (informational)",
	webhooksID:           "A webhook exports push/release/deployment events",
}

var orgCheckIDs = []string{orgLogAvailableID, logStreamingID, retentionAwarenessID}

var checkIDs = append(append([]string{}, orgCheckIDs...), webhooksID)

// checkRemediations covers all four checks for consistency with every
// other collector's registry entry, though three of the four
// (log-streaming, retention-awareness, and effectively org-log-available
// — see each check's own doc comment) can never actually reach
// verified-fail/partial, so a poam.md finding for them never exists to
// render this text against. It's still worth documenting: a reader
// digging into *why* a check is permanently not-checkable may want to
// know what would make the underlying control checkable/better, even
// though this tool can't verify it directly.
var checkRemediations = map[string]string{
	orgLogAvailableID: "This check can only ever report verified-pass or not-checkable, never a fail — " +
		"if it's not-checkable, either the org's plan doesn't include GitHub Enterprise Cloud's audit-log " +
		"API, or the token isn't an org owner with the read:audit_log scope. Upgrading the plan or " +
		"granting that scope is what would make this check verifiable.",
	logStreamingID: "Not remediable via this tool's own checks: audit-log streaming/export only exists " +
		"at the GitHub Enterprise account level (Enterprise Settings -> Audit log -> Log streaming), not " +
		"the organization level, so this check can never verify it directly. If streaming is configured, " +
		"document it in the self-attestation questionnaire (SA.audit-log-export-fallback) instead.",
	retentionAwarenessID: "No remediation applicable — this check is purely informational (documents " +
		"GitHub's 180-day audit-log retention window) and never reports a fail. If longer retention is " +
		"required, configure audit-log export/streaming (see C09.audit.log-streaming) and document the " +
		"destination and retention period in the self-attestation questionnaire.",
	webhooksID: "Repo Settings -> Webhooks -> Add webhook -> subscribe to at least Push, Release, and " +
		"Deployment events (or the wildcard \"Send me everything\") pointing at your log/SIEM ingestion " +
		"endpoint.",
}

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce — see the check functions above for the pass/fail
// logic each rubric below summarizes. Unlike every other collector in
// this codebase, C09 has no shared cross-check not-checkable gate at
// all: each of the four checks is independently computed (collectOrg
// calls all three org-scoped checks unconditionally, with no early
// return on any one's failure), so there's no sharedUpstreamFetchFailureRubric
// here. logStreamingID and retentionAwarenessID are further notable:
// each can ONLY ever produce not-checkable — never pass, fail, or
// partial — since neither makes any API call at all (see their own doc
// comments for why no such call could exist).
var checkRubrics = map[string]map[model.Status]string{
	orgLogAvailableID: {
		model.StatusVerifiedPass: "GET /orgs/{org}/audit-log succeeded — the endpoint is reachable; this " +
			"check never inspects the returned entries themselves, only whether the call succeeded",
		model.StatusNotCheckable: "the call failed — a plan-gated response (402/404: the org's plan " +
			"doesn't include GitHub Enterprise Cloud's audit-log API, or the token lacks the " +
			"`read:audit_log` scope; GitHub returns the same status for both, so this can't be told apart " +
			"from the response alone), a 403 (token lacks org-owner status or the `read:audit_log` scope), " +
			"or another API error",
	},
	logStreamingID: {
		model.StatusNotCheckable: "always — audit-log streaming/export configuration exists exclusively " +
			"at the GitHub Enterprise account level (`/enterprises/{enterprise}/audit-log/streams`), never " +
			"the organization level; no org/repo-scoped endpoint exists for this tool to query, so this " +
			"check can never reach any other status",
	},
	retentionAwarenessID: {
		model.StatusNotCheckable: "always — this check is purely informational; no GitHub API reports an " +
			"org's actually-applied audit-log retention, so there is nothing to verify. Facts carry " +
			"GitHub's documented 180-day retention window as context only",
	},
	webhooksID: {
		model.StatusVerifiedPass: "at least one active webhook on this repo subscribes to `push`, " +
			"`release`, `deployment`, or the `*` wildcard event",
		model.StatusVerifiedFail: "no active webhook on this repo subscribes to any of `push`, `release`, " +
			"`deployment`, or the wildcard event — includes the case where the repo has zero webhooks at " +
			"all (a definitive \"no\", not a gap). Scoped to per-repo webhooks only: a repo covered solely " +
			"by an org-level webhook (a different, unevaluated endpoint) will still show fail here even " +
			"though event export genuinely happens elsewhere",
		model.StatusNotCheckable: "the webhook-listing call itself failed (403/404/other API error)",
	},
}

var checkEndpoints = map[string][]string{
	orgLogAvailableID: {"GET /orgs/{org}/audit-log"},
	// logStreamingID and retentionAwarenessID are deliberately empty:
	// neither makes any API call at all, so no endpoint backs their
	// (permanently fixed) status — see checkRubrics' own doc comment.
	logStreamingID:       nil,
	retentionAwarenessID: nil,
	webhooksID:           {"GET /repos/{owner}/{repo}/hooks"},
}

const fixtureRef = "internal/collect/github/auditlogging/auditlogging_test.go"

func init() {
	for _, id := range orgCheckIDs {
		collect.Register(collect.CheckMeta{
			ID:        id,
			Title:     checkTitles[id],
			Collector: collectorID,
			TokenScope: "read:audit_log (classic OAuth/PAT scope) — the authenticated user must also be an " +
				"organization owner; GitHub's docs don't distinguish a missing scope from a plan that doesn't " +
				"include the Enterprise Cloud audit-log API in the response this collector sees, both surface " +
				"identically (see C09.audit.org-log-available's Reason wording)",
			Remediation: checkRemediations[id],
			Rubric:      checkRubrics[id],
			Endpoints:   checkEndpoints[id],
			FixtureRef:  fixtureRef,
		})
	}
	collect.Register(collect.CheckMeta{
		ID:        webhooksID,
		Title:     checkTitles[webhooksID],
		Collector: collectorID,
		TokenScope: "repo (classic) or Webhooks: read-only (fine-grained) — exact fine-grained category not " +
			"independently verified against GitHub's docs, see C05's TokenScope for the same kind of hedge",
		Remediation: checkRemediations[webhooksID],
		Rubric:      checkRubrics[webhooksID],
		Endpoints:   checkEndpoints[webhooksID],
		FixtureRef:  fixtureRef,
	})
}

// Collector implements C09 audit-logging.
type Collector struct {
	token string

	// newClientForTest overrides how each Client is constructed — see
	// secretshygiene.Collector's identical field for why.
	newClientForTest func(token string) *ghcollect.Client
}

// New returns a C09 collector authenticated with token. The three
// org-scoped checks share one dedicated Client (a single Collect call
// never runs them concurrently, so provenance attribution stays simple);
// C09.repo.webhooks fans out per-repo via ForEachRepo, each with its own
// fresh Client, for the same provenance-isolation reason as every other
// per-repo collector in this codebase.
func New(token string) *Collector {
	return &Collector{token: token}
}

func (c *Collector) newClient() *ghcollect.Client {
	if c.newClientForTest != nil {
		return c.newClientForTest(c.token)
	}
	return ghcollect.NewClient(c.token)
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. It never returns a non-nil
// top-level error for a per-repo API failure — see org-security's Collect
// doc comment for why that matters for the rollup.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	orgResults := collectOrg(ctx, c.newClient(), scope.Org)

	repoResults := ghcollect.ForEachRepo(ctx, scope.Repos, ghcollect.DefaultConcurrency, func(ctx context.Context, repo string) ([]model.CheckResult, error) {
		client := c.newClient()
		return []model.CheckResult{checkRepoWebhooks(ctx, client, scope.Org, repo)}, nil
	})

	all := append([]model.CheckResult{}, orgResults...)
	for _, r := range repoResults {
		if r.Err != nil {
			all = append(all, notCheckableResult(webhooksID, scope.Org, r.Repo, fmt.Sprintf("scan canceled before this repo's checks ran: %v", r.Err), []model.Provenance{}))
			continue
		}
		all = append(all, r.Value...)
	}
	return all, nil
}

// collectOrg resolves the three org-scoped checks. Only
// checkOrgLogAvailable makes any API call; checkLogStreaming and
// checkRetentionAwareness are fixed, evidence-free results (see their own
// doc comments for why no call could ever change their answer).
func collectOrg(ctx context.Context, client *ghcollect.Client, org string) []model.CheckResult {
	return []model.CheckResult{
		checkOrgLogAvailable(ctx, client, org),
		checkLogStreaming(org),
		checkRetentionAwareness(org),
	}
}

func notCheckableResult(id, org, repo, reason string, prov []model.Provenance) model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
	}
}

// checkOrgLogAvailable probes GET /orgs/{org}/audit-log?per_page=1 — the
// cheapest possible call that proves the endpoint is reachable without
// pulling real audit data into the evidence pack (audit entries can
// contain sensitive detail; ADR-0004/threat-model.md's "no raw response
// bodies" rule applies here too, so this check only ever records whether
// the call succeeded, never the entries themselves). A plan-gated
// response (402/404, see ghcollect.IsPlanGated — this exact endpoint is
// the case its doc comment names) and a permission-gated one (403,
// missing org-owner status or the read:audit_log scope) are reported
// distinctly, but GitHub itself doesn't reliably distinguish "wrong plan"
// from "wrong scope" for this endpoint, so 402/404's Reason names both
// possibilities rather than asserting one with false confidence.
func checkOrgLogAvailable(ctx context.Context, client *ghcollect.Client, org string) model.CheckResult {
	const id = orgLogAvailableID

	_, resp, err := client.REST.Organizations.GetAuditLog(ctx, org, &ghgithub.GetAuditLogOptions{
		ListCursorOptions: ghgithub.ListCursorOptions{PerPage: 1},
	})
	plan, planKnown := fetchOrgPlanName(ctx, client, org)
	prov := client.Provenance()

	facts := map[string]any{}
	if planKnown {
		facts["org_plan"] = plan
	}

	if err == nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
			Reason: "the organization audit log is reachable via GET /orgs/{org}/audit-log",
			Scope:  model.ScopeRef{Org: org}, Provenance: prov, Facts: facts,
		}
	}

	reason := fmt.Sprintf("could not query the organization audit log: %v", err)
	switch {
	case resp != nil && ghcollect.IsPlanGated(resp.StatusCode):
		reason = fmt.Sprintf(
			"GET /orgs/{org}/audit-log returned %d — either the org's plan doesn't include GitHub Enterprise "+
				"Cloud's audit-log API, or the token lacks the read:audit_log scope (GitHub returns the same "+
				"status for both, so this can't be told apart from the response alone)", resp.StatusCode)
	case resp != nil && resp.StatusCode == http.StatusForbidden:
		reason = "token lacks permission to read the organization audit log (must be an org owner with the read:audit_log scope)"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable, Reason: reason,
		Scope: model.ScopeRef{Org: org}, Provenance: prov, Facts: facts,
	}
}

// fetchOrgPlanName reads the org's plan name purely as a context fact —
// tolerated failing (Organizations.Get needs no special scope beyond what
// every other org-level check in this codebase already assumes, but this
// call's own failure must never cascade into checkOrgLogAvailable's
// result, which has already determined its own status by the time this
// runs).
func fetchOrgPlanName(ctx context.Context, client *ghcollect.Client, org string) (string, bool) {
	o, _, err := client.REST.Organizations.Get(ctx, org)
	if err != nil || o == nil || o.Plan == nil {
		return "", false
	}
	return o.GetPlan().GetName(), true
}

// checkLogStreaming always returns not-checkable, with no API call at
// all: GitHub's audit-log streaming/export configuration (to S3, Splunk,
// Datadog, Azure, etc.) lives exclusively at
// /enterprises/{enterprise}/audit-log/streams — confirmed against
// GitHub's own REST API docs, which scope every stream-configuration
// endpoint to an enterprise account, never an organization. This tool's
// data model has no concept of an enterprise account (only Org/Repos, see
// collect.Scope) and no such endpoint exists to probe at the org level
// regardless — there is no evidence-gathering version of this check that
// could ever be built without adding an enterprise-account scope to the
// whole tool. The self-attestation questionnaire (issue #23) is the
// intended place for a documented fallback answer.
func checkLogStreaming(org string) model.CheckResult {
	const id = logStreamingID
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "audit-log streaming/export is configured exclusively at the GitHub Enterprise account level " +
			"(/enterprises/{enterprise}/audit-log/streams), not the organization level — there is no API this " +
			"org/repo-scoped tool can query to determine whether it's configured",
		Scope: model.ScopeRef{Org: org}, Provenance: []model.Provenance{},
	}
}

// checkRetentionAwareness always returns not-checkable with no API call:
// no GitHub API reports an org's actually-applied audit-log retention, so
// there is nothing to verify — only GitHub's own documented policy to
// surface as context. Facts carry that documented figure (confirmed
// against GitHub's docs at authoring time; see the source URL in Facts)
// so a reader of the report knows what evidence window exists without
// this tool overstating verification it can't perform. Never upgrades to
// any other status — see the package doc comment.
func checkRetentionAwareness(org string) model.CheckResult {
	const id = retentionAwarenessID
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "informational only — GitHub's documented audit-log retention window is provided as context; " +
			"no API exposes what retention actually applies to this specific org",
		Scope: model.ScopeRef{Org: org}, Provenance: []model.Provenance{},
		Facts: map[string]any{
			"documented_retention_days": 180,
			"source_url":                "https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization",
			"note":                      "GitHub's docs state the audit log lists events from the last 180 days. Exporting/streaming (Enterprise-only, see C09.audit.log-streaming) is GitHub's documented mechanism for retention beyond that window.",
		},
	}
}

// checkRepoWebhooks passes when at least one active webhook subscribes to
// push, release, deployment, or the "*" wildcard — real, verifiable
// event-export capability, not an unknown: GitHub returns 200 with an
// empty list when a repo genuinely has no webhooks, a definitive "no",
// not a gap in what this check could determine (unlike, say, "no
// releases in the lookback window" elsewhere in this codebase, which is
// about absent *data* the check needed, not the check's own subject).
// Facts record hostname + event list only, never the raw webhook URL —
// query strings/paths on a webhook URL commonly carry a bearer token or
// signing secret, and unlike the ghp_/AKIA-shaped strings
// model.CheckResult.Scrub already catches, an arbitrary webhook token has
// no fixed shape the generic scrubber could recognize — so this
// extraction has to happen here, at the source, not rely on scrubbing
// downstream.
//
// Scoped to this repo's own webhooks only — an org-level webhook
// (Organizations.ListHooks, a different endpoint) that covers every repo
// in the org isn't evaluated here; a repo relying solely on an org-level
// webhook will show verified-fail even though event export genuinely
// happens. A real, deliberate scope limit for this issue's pass, not an
// oversight — see the check's Reason wording for how a fixture ever hits
// this needs to document it.
func checkRepoWebhooks(ctx context.Context, client *ghcollect.Client, org, repo string) model.CheckResult {
	const id = webhooksID

	hooks, resp, err := client.REST.Repositories.ListHooks(ctx, org, repo, &ghgithub.ListOptions{PerPage: 100})
	prov := client.Provenance()
	if err != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: webhooksNotCheckableReason(resp, err, org, repo),
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	facts := make([]map[string]any, 0, len(hooks))
	covered := map[string]bool{}
	for _, h := range hooks {
		if !h.GetActive() {
			continue
		}
		events := h.Events
		for _, e := range events {
			covered[e] = true
		}
		facts = append(facts, map[string]any{
			"hostname": hostnameOf(h.GetConfig().GetURL()),
			"events":   events,
		})
	}

	status := model.StatusVerifiedFail
	reason := "no active webhook subscribes to push, release, or deployment events"
	if covered["push"] || covered["release"] || covered["deployment"] || covered["*"] {
		status = model.StatusVerifiedPass
		reason = "at least one active webhook exports push, release, or deployment events to an external destination"
	}

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"webhooks": facts},
	}
}

// hostnameOf extracts just the host component of a webhook target URL —
// see checkRepoWebhooks' doc comment for why the rest (path, query,
// userinfo) must never reach Facts. An unparseable or empty URL yields
// "" rather than panicking or leaking the raw string.
func hostnameOf(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func webhooksNotCheckableReason(resp *ghgithub.Response, err error, org, repo string) string {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to list webhooks on %s/%s (needs admin-level repo access)", org, repo)
		case http.StatusNotFound:
			return fmt.Sprintf("%s/%s not found, or not visible to this token", org, repo)
		}
	}
	return fmt.Sprintf("could not list webhooks on %s/%s: %v", org, repo, err)
}
