// Package auditlogging implements C09 audit-logging for GitLab.
//
// Three of its four checks are, and will stay, always not-checkable:
// GitLab's Audit Events API — org-level log streaming, the org audit log
// itself, and its retention window — is a paid-tier feature (Premium and
// above). A Free project has no audit stream to read, so its absence is a
// tier limitation, not a finding, and this build does not read the paid API
// yet regardless.
//
// The fourth, C09.repo.webhooks, is not gated by that at all. GitLab's
// Project Webhooks API (GET /projects/:id/hooks) is a stable, documented,
// Free-tier endpoint with no relationship to Audit Events — it is how a
// project pushes its own event stream out, independent of GitLab's own
// audit trail. Before this package existed, all four checks were registered
// through internal/collect/gitlab/unsupported with one shared "paid-tier"
// reason string copied across all of them, which made this check's rubric
// wrong: it described a tier limitation that has nothing to do with what the
// check actually reads.
package auditlogging

import (
	"context"

	"gitlab.com/sioakeim/attestward/internal/collect"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const platform = "gitlab"
const collectorID = "C09.audit-logging"

const (
	idLogStreaming    = "C09.audit.log-streaming"
	idOrgLogAvailable = "C09.audit.org-log-available"
	idRetentionAware  = "C09.audit.retention-awareness"
	idRepoWebhooks    = "C09.repo.webhooks"
)

// auditPaidTierReason is shared by the three checks that genuinely are gated
// on GitLab's paid Audit Events API. C09.repo.webhooks does NOT use this —
// see the package doc comment for why conflating them was the bug.
const auditPaidTierReason = "GitLab's audit events API is a paid-tier feature; on a free project there is no " +
	"audit stream to read at all, so absence of events is a tier limitation rather than a finding. This build " +
	"does not read the paid API yet."

// Collector implements C09 audit-logging for GitLab.
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

// Collect emits the three fixed org-level facts once per scan (they carry no
// per-repo information — GitLab's Audit Events API, were it read, would be
// org-scoped) and C09.repo.webhooks once per repo in scope.
func (c *Collector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	var out []model.CheckResult
	out = append(out,
		notCheckableAlways(idLogStreaming, "Audit-log export/streaming is configured", scope.Org, "", auditPaidTierReason),
		notCheckableAlways(idOrgLogAvailable, "Organization audit log is reachable via the API", scope.Org, "", auditPaidTierReason),
		notCheckableAlways(idRetentionAware, "Audit-log retention window (informational)", scope.Org, "", auditPaidTierReason),
	)

	for _, repo := range scope.Repos {
		out = append(out, c.webhooksResult(ctx, scope.Org, repo))
	}
	return out, nil
}

func notCheckableAlways(id, title, org, repo, reason string) model.CheckResult {
	return model.CheckResult{
		CheckID:    id,
		Title:      title,
		Status:     model.StatusNotCheckable,
		Reason:     reason,
		Scope:      model.ScopeRef{Org: org, Repo: repo, Platform: platform},
		Provenance: []model.Provenance{},
	}
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

func init() {
	reg := func(id, title, tokenScope, remediation string, rubric map[model.Status]string, endpoints []string) {
		collect.Register(collect.CheckMeta{
			ID: id, Platform: platform, Title: title, Collector: collectorID,
			TokenScope:  tokenScope,
			Remediation: remediation, Rubric: rubric, Endpoints: endpoints,
			FixtureRef: "internal/collect/gitlab/auditlogging/auditlogging_test.go",
		})
	}

	// Matches the wording gogs/unsupported and the other always-not-checkable
	// packages use for the same shape of check — no API call, so no token
	// scope is spent regardless of what the caller's token can reach.
	const noAPICall = "none — no API call backs this check. A GitLab token is still needed for the scan as a " +
		"whole, but nothing about this result depends on what it can reach"
	auditGatedRubric := map[model.Status]string{
		model.StatusNotCheckable: auditPaidTierReason,
	}
	auditGatedRemediation := "Not evaluable by this build on GitLab yet. Until a collector lands, answer the " +
		"corresponding self-attestation question, or evidence the control from whichever system actually " +
		"enforces it."

	reg(idLogStreaming, "Audit-log export/streaming is configured", noAPICall, auditGatedRemediation, auditGatedRubric, nil)
	reg(idOrgLogAvailable, "Organization audit log is reachable via the API", noAPICall, auditGatedRemediation, auditGatedRubric, nil)
	reg(idRetentionAware, "Audit-log retention window (informational)", noAPICall, auditGatedRemediation, auditGatedRubric, nil)

	reg(idRepoWebhooks, webhooksTitle, "read_api (Reporter or above on the project)",
		"Project → Settings → Webhooks → add a webhook subscribing to Push events, Releases events, or "+
			"Deployment events, and confirm its Alert status is not showing a delivery failure — GitLab "+
			"automatically stops delivering to a webhook after repeated failures.",
		map[model.Status]string{
			model.StatusVerifiedPass: "at least one project webhook has alert_status \"executable\" (currently " +
				"delivering, not in backoff or permanently disabled) and subscribes to push, releases, or " +
				"deployment events.",
			model.StatusVerifiedFail: "no webhook is both executable and subscribed to one of those event types " +
				"— includes the case of zero webhooks configured, which is a definitive absence, not a gap.",
			model.StatusNotCheckable: "the project's webhooks could not be read (403/404/other API error), or a " +
				"webhook's alert_status held a value this build does not recognise (GitLab documents exactly " +
				"three: executable, temporarily_disabled, disabled) — guessing whether an unrecognised state " +
				"means the hook is currently delivering would assert something never observed.",
		}, []string{"GET /projects/{id}/hooks"})
}
