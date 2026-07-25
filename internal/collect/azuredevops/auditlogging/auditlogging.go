// Package auditlogging implements Azure DevOps's C09 audit-logging — the
// ADO counterpart to internal/collect/github/auditlogging — and, per issue
// #154 (v0.2 epic #34's S8), the collector this project's per-platform
// rubric design (issue #148's S2) exists to show off: Azure DevOps exposes
// audit-log streaming at the *organization* level, an API surface GitHub
// only exposes at the *Enterprise account* level (a concept this tool has
// no notion of at all). C09.audit.log-streaming therefore gains real
// verified-pass/verified-fail lines here that GitHub's own rubric can never
// produce (see checkLogStreaming's own doc comment) — the clearest
// parity-matrix win in the whole v0.2 epic.
//
// C09.audit.org-log-available keeps GitHub's honest three-way
// indistinguishable not-checkable reason, restated for Azure DevOps's own
// gating: the organization isn't Azure AD (Entra ID)-backed, the org's "Log
// Audit Events" policy is off (off by default; the feature is in public
// preview), or the token lacks the vso.auditlog scope or View-audit-log
// permission — Azure DevOps returns the same gated response (see
// azuredevops.IsAuditGated) for all three, so this collector can't tell
// them apart any more than the GitHub twin can tell apart its own trio.
//
// C09.audit.retention-awareness stays informational-only on both
// platforms (no API on either reports an org's actually-applied
// retention), citing Azure DevOps's documented 90-day window instead of
// GitHub's 180 and pointing at log-streaming as the documented way past it.
//
// C09.repo.webhooks becomes an org-level service-hook-subscription check:
// Azure DevOps has no per-repo webhook concept the way GitHub does: service
// hook subscriptions are always org-scoped, optionally narrowed to one
// project via publisherInputs.projectId.
//
// CRITICAL security note: both the Streams - List and Subscriptions - List
// APIs carry live secrets in an object field named consumerInputs —
// Microsoft's own documented sample responses show a Splunk event-collector
// token and plaintext webhook passwords/API tokens there, respectively.
// auditStreamRaw and serviceHookSubscriptionRaw have no field for
// consumerInputs at all — not merely "extraction skips it" — so it
// structurally cannot reach this collector's Facts; encoding/json silently
// drops unknown JSON keys on decode, which is exactly the property this
// depends on. Facts for the streams check carry only consumerType counts.
//
// Deviations from issue #154's literal wording, called out here rather
// than left implicit in the check functions alone:
//   - C09.repo.webhooks resolves scope.Project's name to a GUID via one
//     extra Projects - Get call before matching — the story says "matches
//     the scanned project", but Subscriptions - List's own
//     publisherInputs.projectId is documented as always a GUID, never a
//     name, so a name-vs-GUID comparison would never match anything.
//   - Both C09.audit.log-streaming's and C09.repo.webhooks' status
//     comparisons treat an absent/empty status field the same as
//     "enabled" (see isSubscriptionActive's own doc comment) and compare
//     case-insensitively (see auditStreamStatus's own doc comment) —
//     narrower than the story's literal `status=="enabled"`, but
//     well-supported by Microsoft's own documented sample responses and
//     recorded in each check's own Rubric.
package auditlogging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/model"
)

// collectorID must equal the GitHub twin's Collector string exactly — the
// registry (internal/collect/registry.go's Register) panics if two
// platforms register the same check ID under different Collector strings,
// and internal/checksref groups a check's per-platform subsections by this
// same identity.
const collectorID = "C09.audit-logging"

const (
	orgLogAvailableID    = "C09.audit.org-log-available"
	logStreamingID       = "C09.audit.log-streaming"
	retentionAwarenessID = "C09.audit.retention-awareness"
	webhooksID           = "C09.repo.webhooks"
)

var checkTitles = map[string]string{
	orgLogAvailableID:    "Organization audit log is reachable via the API",
	logStreamingID:       "Audit-log streaming to an external destination is enabled",
	retentionAwarenessID: "Audit-log retention window (informational)",
	webhooksID:           "A service hook subscription exports push/build events",
}

var checkIDs = []string{orgLogAvailableID, logStreamingID, retentionAwarenessID, webhooksID}

// checkRemediations covers all four checks for consistency with every other
// collector's registry entry, though retention-awareness (never anything
// but not-checkable, purely informational) never has a poam.md finding to
// render this text against — see checkRubrics' own doc comment.
var checkRemediations = map[string]string{
	orgLogAvailableID: "This check can only ever report verified-pass or not-checkable, never a fail — if " +
		"it's not-checkable: confirm the organization is backed by Azure AD (Entra ID), not a Microsoft " +
		"Account; have an Organization Administrator turn on Organization Settings -> Auditing -> \"Log " +
		"Audit Events\" (off by default; the feature is in public preview); and use a PAT with the " +
		"vso.auditlog scope from a user with View-audit-log permission.",
	logStreamingID: "Organization Settings -> Auditing -> Streams -> Add stream, configure a supported " +
		"consumer (Splunk, Azure Event Grid, Azure Monitor Logs, etc.), and confirm its status shows " +
		"Enabled — a stream left Disabled by the system (e.g. after repeated delivery failures) or by a " +
		"user still fails this check.",
	retentionAwarenessID: "No remediation applicable — this check is purely informational (documents Azure " +
		"DevOps's 90-day audit-log retention window) and never reports a fail. If longer retention is " +
		"required, configure audit-log streaming (see C09.audit.log-streaming), Azure DevOps's documented " +
		"mechanism for retention beyond 90 days.",
	webhooksID: "Organization Settings -> Service Hooks -> Create subscription -> choose the \"Code pushed\" " +
		"(git.push) or \"Build completed\" (build.complete) event, and scope it to (or leave unscoped, " +
		"covering every project in) the project being scanned.",
}

// checkRubrics gives each check's own concrete meaning for every status it
// can actually produce. logStreamingID is the notable departure from the
// GitHub twin: there, this check can only ever report not-checkable (audit
// streaming lives exclusively at the Enterprise-account level, a concept
// this tool has no notion of); here, Azure DevOps exposes streaming
// configuration at the organization level this tool already scans, so it
// gets real verified-pass/verified-fail lines instead.
var checkRubrics = map[string]map[model.Status]string{
	orgLogAvailableID: {
		model.StatusVerifiedPass: "GET .../_apis/audit/auditlog?batchSize=1 succeeded — the endpoint is " +
			"reachable; this check never inspects the returned entries themselves, only whether the call " +
			"succeeded",
		model.StatusNotCheckable: "the call failed with a gated response (see azuredevops.IsAuditGated) — " +
			"one of three indistinguishable causes: the org isn't Azure AD (Entra ID)-backed, the org's " +
			"\"Log Audit Events\" policy is off (off by default; the feature is in public preview), or the " +
			"token lacks the vso.auditlog scope or the caller lacks View-audit-log permission — Azure " +
			"DevOps returns the same status for all three, so this can't be told apart from the response " +
			"alone — or another API error",
	},
	logStreamingID: {
		model.StatusVerifiedPass: "GET .../_apis/audit/streams returned at least one stream with " +
			"status==\"enabled\" — unlike GitHub, where this check can only ever report not-checkable " +
			"(audit-log streaming lives exclusively at the Enterprise-account level, a concept this tool has " +
			"no notion of), Azure DevOps exposes streaming configuration at the organization level this tool " +
			"already scans, making this a real, verifiable pass/fail here",
		model.StatusVerifiedFail: "GET .../_apis/audit/streams returned zero streams, or every returned " +
			"stream's status is something other than \"enabled\" (disabledByUser, disabledBySystem, " +
			"deleted, backfilling, or unknown)",
		model.StatusNotCheckable: "the call failed with a gated response (see azuredevops.IsAuditGated) — " +
			"the org isn't Entra-backed, audit logging isn't enabled for it, or the token lacks the " +
			"vso.auditlog scope — or another API error",
	},
	retentionAwarenessID: {
		model.StatusNotCheckable: "always — this check is purely informational; no Azure DevOps API reports " +
			"an org's actually-applied audit-log retention, so there is nothing to verify. Facts carry " +
			"Azure DevOps's documented 90-day retention window as context only",
	},
	webhooksID: {
		model.StatusVerifiedPass: "at least one enabled (status==\"enabled\", or status absent — Azure " +
			"DevOps's own documented sample responses show several subscriptions omitting the field " +
			"entirely, which this collector treats as the enum's default/enabled state) org-level service " +
			"hook subscription has eventType git.push or build.complete, and its publisherInputs.projectId " +
			"either matches the scanned project or is empty/absent (an all-projects subscription counts)",
		model.StatusVerifiedFail: "no enabled service hook subscription with eventType git.push or " +
			"build.complete is scoped to this project (or to all projects) — includes the case where the " +
			"org has zero subscriptions at all",
		model.StatusNotCheckable: "the scanned project couldn't be resolved to a project id, or the " +
			"subscriptions-listing call itself failed (403/404/other API error)",
	},
}

// checkEndpoints strings are host-first ("GET <host>/{org}/...") — the same
// convention every other ADO collector's Endpoints entries use (issue #179;
// this package and vdp's were the only two path-first-with-a-host-
// parenthetical holdouts). checksWithNoEndpoint (test file) exempts
// retentionAwarenessID from the completeness check's non-empty requirement,
// same as the GitHub twin.
var checkEndpoints = map[string][]string{
	orgLogAvailableID: {"GET auditservice.dev.azure.com/{org}/_apis/audit/auditlog?batchSize=1"},
	logStreamingID:    {"GET auditservice.dev.azure.com/{org}/_apis/audit/streams"},
	// retentionAwarenessID is deliberately nil: it makes no API call at
	// all, so no endpoint backs its (permanently fixed) not-checkable
	// status — see checkRubrics' own doc comment.
	retentionAwarenessID: nil,
	webhooksID: {
		"GET dev.azure.com/{org}/_apis/projects/{project}",
		"GET dev.azure.com/{org}/_apis/hooks/subscriptions",
	},
}

const fixtureRef = "internal/collect/azuredevops/auditlogging/auditlogging_test.go"

func init() {
	collect.Register(collect.CheckMeta{
		ID:        orgLogAvailableID,
		Platform:  "azuredevops",
		Title:     checkTitles[orgLogAvailableID],
		Collector: collectorID,
		TokenScope: "vso.auditlog — the Audit Log API additionally requires the org to be Azure AD (Entra " +
			"ID)-backed and the caller to have View-audit-log permission; Azure DevOps returns the same " +
			"gated status whether the cause is missing scope, missing permission, or org type, so none of " +
			"the three can be independently confirmed from this token alone (see this check's own Reason " +
			"wording)",
		Remediation: checkRemediations[orgLogAvailableID],
		Rubric:      checkRubrics[orgLogAvailableID],
		Endpoints:   checkEndpoints[orgLogAvailableID],
		FixtureRef:  fixtureRef,
	})
	collect.Register(collect.CheckMeta{
		ID:          logStreamingID,
		Platform:    "azuredevops",
		Title:       checkTitles[logStreamingID],
		Collector:   collectorID,
		TokenScope:  "vso.auditlog",
		Remediation: checkRemediations[logStreamingID],
		Rubric:      checkRubrics[logStreamingID],
		Endpoints:   checkEndpoints[logStreamingID],
		FixtureRef:  fixtureRef,
	})
	collect.Register(collect.CheckMeta{
		ID:          retentionAwarenessID,
		Platform:    "azuredevops",
		Title:       checkTitles[retentionAwarenessID],
		Collector:   collectorID,
		TokenScope:  "vso.auditlog (informational only — this check makes no API call of its own, see its own doc comment)",
		Remediation: checkRemediations[retentionAwarenessID],
		Rubric:      checkRubrics[retentionAwarenessID],
		Endpoints:   checkEndpoints[retentionAwarenessID],
		FixtureRef:  fixtureRef,
	})
	collect.Register(collect.CheckMeta{
		ID:        webhooksID,
		Platform:  "azuredevops",
		Title:     checkTitles[webhooksID],
		Collector: collectorID,
		TokenScope: "vso.project (Projects - Get, to resolve the scanned project to its id) plus vso.build " +
			"and/or vso.code (Subscriptions - List's own documented scopes are vso.work, vso.build, and " +
			"vso.code; only vso.build/vso.code appear elsewhere in this epic's scope list — issue #34 — so " +
			"vso.work isn't claimed as already-held here). All three named scopes are already part of this " +
			"project's epic-wide ADO token-scope set, so this check needs nothing beyond that",
		Remediation: checkRemediations[webhooksID],
		Rubric:      checkRubrics[webhooksID],
		Endpoints:   checkEndpoints[webhooksID],
		FixtureRef:  fixtureRef,
	})
}

// Collector implements C09 audit-logging for Azure DevOps.
type Collector struct {
	client *azuredevops.Client
}

// New returns a C09 collector using client for all API calls. Give each
// collector instance its own Client (never share one across
// concurrently-run collectors) — Client.Provenance() reflects every call
// made through it, and this collector attributes provenance to individual
// CheckResults by diffing that log around each check's own call(s) (see
// tailProvenance), which only stays correct if nothing else issues calls
// through the same client concurrently. All four checks here run
// sequentially within one Collect call, so one shared Client is safe, the
// same reasoning the GitHub twin's three org-scoped checks rely on.
func New(client *azuredevops.Client) *Collector {
	return &Collector{client: client}
}

// ID implements collect.Collector.
func (c *Collector) ID() string { return collectorID }

// Collect implements collect.Collector. Every check here is org-scoped —
// unlike the GitHub twin, C09.repo.webhooks is also an org-level check on
// Azure DevOps (service hook subscriptions have no per-repo concept), so
// Collect never fans out per-repo and scope.Repos is never consulted.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	return []model.CheckResult{
		c.checkOrgLogAvailable(ctx, scope.Org),
		c.checkLogStreaming(ctx, scope.Org),
		c.checkRetentionAwareness(scope.Org),
		c.checkRepoWebhooks(ctx, scope.Org, scope.Project),
	}, nil
}

// tailProvenance returns only the provenance entries recorded since skip —
// see New's doc comment for why a shared Client needs this to attribute
// provenance to the right check.
func tailProvenance(prov []model.Provenance, skip int) []model.Provenance {
	if skip >= len(prov) {
		return []model.Provenance{}
	}
	return prov[skip:]
}

// checkOrgLogAvailable probes GET .../_apis/audit/auditlog?batchSize=1 — the
// cheapest possible call that proves the endpoint is reachable without
// pulling real audit data into the evidence pack (audit entries can
// contain sensitive detail; ADR-0004/threat-model.md's "no raw response
// bodies" rule applies here too). The response is decoded into a discarded
// `any` — this check only ever records whether the call succeeded, never
// the entries themselves, matching the GitHub twin's identical discipline.
func (c *Collector) checkOrgLogAvailable(ctx context.Context, org string) model.CheckResult {
	const id = orgLogAvailableID
	start := len(c.client.Provenance())

	path := fmt.Sprintf("/%s/_apis/audit/auditlog", c.client.Org())
	query := url.Values{"batchSize": {"1"}, "api-version": {"7.1-preview.1"}}

	var discarded any
	err := azuredevops.GetJSONObject(ctx, c.client, azuredevops.HostAudit, path, query, &discarded)
	prov := tailProvenance(c.client.Provenance(), start)

	if err == nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
			Reason:     "GET .../_apis/audit/auditlog succeeded — the organization audit log is reachable via the API",
			Scope:      model.ScopeRef{Org: org},
			Provenance: prov,
		}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason:     orgLogAvailableNotCheckableReason(err),
		Scope:      model.ScopeRef{Org: org},
		Provenance: prov,
	}
}

// orgLogAvailableNotCheckableReason names the three-way indistinguishable
// cause (see the package doc comment) when the response is gated, and
// otherwise falls back to a generic transport/decode error message.
func orgLogAvailableNotCheckableReason(err error) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) && azuredevops.IsAuditGated(se.StatusCode) {
		return fmt.Sprintf(
			"GET .../_apis/audit/auditlog returned %d — one of three indistinguishable causes: the "+
				"organization isn't backed by Azure AD (Entra ID), the org's \"Log Audit Events\" policy is "+
				"off (off by default; the feature is in public preview), or the token lacks the vso.auditlog "+
				"scope or the caller lacks View-audit-log permission — Azure DevOps returns the same status "+
				"for all three, so this can't be told apart from the response alone", se.StatusCode)
	}
	return fmt.Sprintf("could not query the organization audit log: %v", err)
}

// auditStreamStatus decodes an Azure DevOps AuditStreamStatus value,
// tolerating both the enum's documented string names (unknown, enabled,
// disabledByUser, disabledBySystem, deleted, backfilling — the actual wire
// contract every other enum in the ADO REST surface this project has
// verified uses) and a raw ordinal integer, which is what Microsoft's own
// Streams - List reference page's sample response shows verbatim
// ("status": 1).
//
// [fixture-verify] (issue #34's fixture-verify list): the reference page's
// prose never actually states that sample stream is enabled — the mapping
// from 1 to "enabled" here rests entirely on the enum's documented member
// order (unknown is listed first, matching the ordinary .NET idiom that an
// enum's zero/unset value is its first declared member) plus the ordinary
// assumption that a documentation sample depicts a working, enabled
// stream, not on any confirmed response. This project has no live
// Entra-backed, audit-licensed org to record a real response against and
// resolve this properly. Decoding straight into a plain string field would
// make every check against an org that truly serializes the numeric form
// fail outright (a decode error, not a status misclassification), turning
// a real pass into a false not-checkable, so this tolerant type exists to
// avoid that failure mode without pretending the ambiguity has been
// resolved — confirm against a recorded response before trusting the
// ordinal mapping specifically.
//
// Comparisons against this type are case-insensitive (UnmarshalJSON
// lowercases the string form on decode): the audit service demonstrably
// doesn't always match its own documented casing (see
// isSubscriptionActive's identical hedge for Subscriptions - List's status
// field), so a live "Enabled" must not produce a false verified-fail here.
type auditStreamStatus string

const auditStreamStatusEnabled auditStreamStatus = "enabled"

// auditStreamStatusByOrdinal mirrors the AuditStreamStatus enum's
// documented member order exactly — the only basis this project has for
// mapping the sample response's raw "status": 1 to a name at all (see
// auditStreamStatus's own [fixture-verify] doc comment).
var auditStreamStatusByOrdinal = []auditStreamStatus{
	"unknown", "enabled", "disabledByUser", "disabledBySystem", "deleted", "backfilling",
}

// UnmarshalJSON implements json.Unmarshaler — see auditStreamStatus's own
// doc comment for why this accepts both a string and a number, and why the
// string form is lowercased (case-insensitive comparison).
func (s *auditStreamStatus) UnmarshalJSON(data []byte) error {
	var asString string
	if err := json.Unmarshal(data, &asString); err == nil {
		*s = auditStreamStatus(strings.ToLower(asString))
		return nil
	}
	var asOrdinal int
	if err := json.Unmarshal(data, &asOrdinal); err == nil {
		if asOrdinal >= 0 && asOrdinal < len(auditStreamStatusByOrdinal) {
			*s = auditStreamStatusByOrdinal[asOrdinal]
			return nil
		}
		*s = "unknown"
		return nil
	}
	return fmt.Errorf("collect/azuredevops/auditlogging: stream status is neither a string nor a number: %s", string(data))
}

// auditStreamRaw is the subset of Azure DevOps's AuditStream shape this
// check needs. It deliberately has no field for consumerInputs or
// displayName — see the package doc comment's CRITICAL security note:
// consumerInputs can carry a live SIEM connection secret verbatim, and
// omitting the field here means encoding/json can never decode it into
// this collector's memory in the first place, not merely that later
// extraction code chooses to ignore it.
type auditStreamRaw struct {
	ConsumerType string            `json:"consumerType"`
	Status       auditStreamStatus `json:"status"`
}

// checkLogStreaming queries GET .../_apis/audit/streams via GetJSON, the
// same generic {count,value}-envelope decode path every other documented
// list endpoint in this project goes through.
//
// Corrected in review (issue #154/#155): an earlier version of this
// function decoded straight into a bare `[]auditStreamRaw` via
// GetJSONObject, on the theory (recorded in internal/collect/azuredevops's
// own now-corrected page doc comment) that "the audit-service family
// doesn't even share this shape." That was an unhedged assertion, not a
// tagged [fixture-verify] guess — stated as settled fact with no caveat
// at all — and it was still wrong: a live scan against a real
// Entra-backed org proved it false. The first real recorded response —
// `GET auditservice.dev.azure.com/{org}/_apis/audit/streams` →
// `{"count":0,"value":[]}` — is the ordinary envelope, and the bare-array
// assumption was producing a decode error (surfacing as not-checkable,
// "cannot unmarshal object into Go value of type []auditlogging.auditStreamRaw")
// on literally every real org, including the simplest zero-streams case,
// which this check's own rubric says should read verified-fail. Contrast
// this with auditStreamStatus's own ordinal-vs-string ambiguity, which
// DOES carry a genuine [fixture-verify] tag — that one stays, since this
// project still hasn't observed a POPULATED stream object to confirm
// which form (or whether Azure DevOps even still uses the ordinal form at
// all) a real stream's status field takes.
//
// This is the one check in this package whose result genuinely depends on
// Azure DevOps organization state rather than being a fixed fact — see the
// package doc comment for why that's the whole point of this collector.
func (c *Collector) checkLogStreaming(ctx context.Context, org string) model.CheckResult {
	const id = logStreamingID
	start := len(c.client.Provenance())

	path := fmt.Sprintf("/%s/_apis/audit/streams", c.client.Org())
	query := url.Values{"api-version": {"7.1-preview.1"}}

	var streams []auditStreamRaw
	err := azuredevops.GetJSON(ctx, c.client, azuredevops.HostAudit, path, query, &streams)
	prov := tailProvenance(c.client.Provenance(), start)
	if err != nil {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason:     logStreamingNotCheckableReason(err),
			Scope:      model.ScopeRef{Org: org},
			Provenance: prov,
		}
	}

	consumerTypeCounts := map[string]int{}
	enabledCount := 0
	for _, s := range streams {
		consumerTypeCounts[s.ConsumerType]++
		if s.Status == auditStreamStatusEnabled {
			enabledCount++
		}
	}
	// Facts carries consumerType counts only — never consumerInputs (see
	// the package doc comment). auditStreamRaw has no field to decode that
	// key into at all, so there is nothing here that could leak it even
	// by mistake.
	facts := map[string]any{
		"stream_count":   len(streams),
		"enabled_count":  enabledCount,
		"consumer_types": consumerTypeCounts,
	}

	if enabledCount > 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedPass,
			Reason:     fmt.Sprintf("%d of %d audit-log stream(s) have status \"enabled\"", enabledCount, len(streams)),
			Scope:      model.ScopeRef{Org: org},
			Provenance: prov,
			Facts:      facts,
		}
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusVerifiedFail,
		Reason:     "no audit-log stream has status \"enabled\" (zero streams configured, or every configured stream is disabled)",
		Scope:      model.ScopeRef{Org: org},
		Provenance: prov,
		Facts:      facts,
	}
}

func logStreamingNotCheckableReason(err error) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) && azuredevops.IsAuditGated(se.StatusCode) {
		return fmt.Sprintf(
			"GET .../_apis/audit/streams returned %d — the organization isn't Azure AD (Entra ID)-backed, "+
				"audit logging isn't available for it, or the token lacks the vso.auditlog scope (Azure "+
				"DevOps returns the same status for all three, so this can't be told apart from the "+
				"response alone)", se.StatusCode)
	}
	return fmt.Sprintf("could not query audit-log streams: %v", err)
}

// checkRetentionAwareness always returns not-checkable with no API call: no
// Azure DevOps API reports an org's actually-applied audit-log retention,
// so there is nothing to verify — only Azure DevOps's own documented
// policy to surface as context, same as the GitHub twin (180 days there,
// 90 here).
func (c *Collector) checkRetentionAwareness(org string) model.CheckResult {
	const id = retentionAwarenessID
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
		Reason: "informational only — Azure DevOps's documented audit-log retention window is provided as " +
			"context; no API exposes what retention actually applies to this specific org",
		Scope:      model.ScopeRef{Org: org},
		Provenance: []model.Provenance{},
		Facts: map[string]any{
			"documented_retention_days": 90,
			"source_url":                "https://learn.microsoft.com/en-us/azure/devops/organizations/audit/azure-devops-auditing",
			"note": "Azure DevOps's docs state audit events are stored for 90 days by default, after which " +
				"they're deleted. Configuring a stream (see C09.audit.log-streaming) is the documented " +
				"mechanism for retention beyond that window.",
		},
	}
}

// teamProjectRaw is the subset of Azure DevOps's TeamProject shape needed
// to resolve a project name to the GUID publisherInputs.projectId compares
// against (Subscriptions - List's publisherInputs.projectId is always a
// project GUID, never a name — confirmed against Microsoft's own
// documented sample response).
type teamProjectRaw struct {
	ID string `json:"id"`
}

// resolveProjectID calls GET .../_apis/projects/{project} (Projects - Get,
// whose {projectId} path parameter accepts either a project name or a
// GUID) to resolve the scanned project's name to its GUID.
func (c *Collector) resolveProjectID(ctx context.Context, project string) (string, error) {
	path := fmt.Sprintf("/%s/_apis/projects/%s", c.client.Org(), url.PathEscape(project))
	query := url.Values{"api-version": {"7.1"}}

	var proj teamProjectRaw
	if err := azuredevops.GetJSONObject(ctx, c.client, azuredevops.HostCore, path, query, &proj); err != nil {
		return "", err
	}
	if proj.ID == "" {
		return "", fmt.Errorf("resolved project %q but its response had no id field", project)
	}
	return proj.ID, nil
}

// serviceHookSubscriptionRaw is the subset of Azure DevOps's Subscription
// shape this check needs. PublisherInputs is public request-shaping
// metadata (which project/branch/build definition a subscription is
// scoped to) and is kept generic since its exact key set varies by
// eventType. There is deliberately no field for consumerInputs — same
// reasoning as auditStreamRaw: Subscriptions - List's own documented
// sample response shows plaintext webhook passwords and API tokens there,
// and this type must never be able to decode that key into memory.
type serviceHookSubscriptionRaw struct {
	EventType       string         `json:"eventType"`
	Status          string         `json:"status"`
	PublisherInputs map[string]any `json:"publisherInputs"`
}

// isSubscriptionActive treats an empty status the same as "enabled" —
// Microsoft's own documented Subscriptions - List sample response shows
// several subscriptions omitting the status field entirely while every
// disabled/onProbation one shows it explicitly, consistent with "enabled"
// being the enum's unset/default value rather than every subscription in
// the sample happening to omit a value. This is a deliberate deviation
// from issue #154's literal `status=="enabled"` wording, not an oversight
// — see the package doc comment's deviations for why an absent field is
// treated the same. The comparison itself is case-insensitive (see
// auditStreamStatus's identical hedge): the audit service demonstrably
// doesn't always match its own documented casing.
func isSubscriptionActive(status string) bool {
	return status == "" || strings.EqualFold(status, "enabled")
}

// checkRepoWebhooks resolves project to its GUID (Azure DevOps has no
// per-repo webhook concept, so this is genuinely org-scoped, not
// per-repo — see the package doc comment), then lists org-level service
// hook subscriptions and looks for at least one enabled git.push or
// build.complete subscription whose publisherInputs.projectId matches that
// GUID or is empty/absent (an all-projects subscription).
func (c *Collector) checkRepoWebhooks(ctx context.Context, org, project string) model.CheckResult {
	const id = webhooksID
	start := len(c.client.Provenance())

	projectID, err := c.resolveProjectID(ctx, project)
	if err != nil {
		prov := tailProvenance(c.client.Provenance(), start)
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason:     projectResolutionNotCheckableReason(project, err),
			Scope:      model.ScopeRef{Org: org},
			Provenance: prov,
		}
	}

	path := fmt.Sprintf("/%s/_apis/hooks/subscriptions", c.client.Org())
	query := url.Values{"api-version": {"7.1"}}
	var subs []serviceHookSubscriptionRaw
	if err := azuredevops.GetJSON(ctx, c.client, azuredevops.HostCore, path, query, &subs); err != nil {
		prov := tailProvenance(c.client.Provenance(), start)
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason:     webhooksNotCheckableReason(err),
			Scope:      model.ScopeRef{Org: org},
			Provenance: prov,
		}
	}
	prov := tailProvenance(c.client.Provenance(), start)

	matches := make([]map[string]any, 0)
	for _, s := range subs {
		if !isSubscriptionActive(s.Status) {
			continue
		}
		if s.EventType != "git.push" && s.EventType != "build.complete" {
			continue
		}
		subProjectID, _ := s.PublisherInputs["projectId"].(string)
		if subProjectID != "" && subProjectID != projectID {
			continue
		}
		matches = append(matches, map[string]any{
			"event_type":   s.EventType,
			"all_projects": subProjectID == "",
		})
	}

	status := model.StatusVerifiedFail
	reason := "no enabled service-hook subscription with eventType git.push or build.complete is scoped to this project (or to all projects)"
	if len(matches) > 0 {
		status = model.StatusVerifiedPass
		reason = "at least one enabled service-hook subscription exports git.push or build.complete events scoped to this project (or to all projects)"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope:      model.ScopeRef{Org: org},
		Provenance: prov,
		Facts:      map[string]any{"matching_subscriptions": matches},
	}
}

func projectResolutionNotCheckableReason(project string, err error) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusNotFound:
			return fmt.Sprintf("project %q not found (or not visible to this token) — can't resolve it to a project id to match service-hook subscriptions against", project)
		case http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read project %q — can't resolve it to a project id", project)
		}
	}
	return fmt.Sprintf("could not resolve project %q to a project id: %v", project, err)
}

func webhooksNotCheckableReason(err error) string {
	var se *azuredevops.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusForbidden:
			return "token lacks permission to list org-level service hook subscriptions"
		case http.StatusNotFound:
			return "org-level service hook subscriptions endpoint not found"
		}
	}
	return fmt.Sprintf("could not list org-level service hook subscriptions: %v", err)
}
