package auditlogging

import (
	"context"
	"fmt"
	"net/http"

	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

const webhooksTitle = "A webhook exports push/release/deployment events"

// GitLab's three documented alert_status values (app/models/concerns/
// web_hooks/auto_disabling.rb): a hook backs off on its 4th consecutive
// delivery failure and is permanently disabled on its 40th (GitLab's own
// source compares with recent_failures > 3 and > 39, and its own comment
// there says "on its 40th failure"). There is no wildcard "all events"
// subscription on GitLab the way GitHub has one —
// every event type is its own boolean, so this checks the three GitLab
// carries that this control cares about directly.
const (
	alertExecutable          = "executable"
	alertTemporarilyDisabled = "temporarily_disabled"
	alertDisabled            = "disabled"
)

// hook is the subset of GitLab's project-webhook shape this check reasons
// about, verified 2026-08-10 against a live GET /projects/:id/hooks
// response and a hook created and deleted for that purpose.
type hook struct {
	ID               int    `json:"id"`
	URL              string `json:"url"`
	AlertStatus      string `json:"alert_status"`
	PushEvents       bool   `json:"push_events"`
	ReleasesEvents   bool   `json:"releases_events"`
	DeploymentEvents bool   `json:"deployment_events"`
}

// exportsRelevantEvents reports whether the hook subscribes to any event
// type this check treats as event export — push, releases, or deployment.
// GitLab has no wildcard event subscription to also check for.
func (h hook) exportsRelevantEvents() bool {
	return h.PushEvents || h.ReleasesEvents || h.DeploymentEvents
}

// webhooksResult builds its own client per repo rather than sharing one
// across scope.Repos. Client.Provenance() is cumulative over every call ever
// made through that client instance, so a shared one attributed an earlier
// repo's API calls to a later repo's CheckResult.Provenance — evidence citing
// a project the result is not about (issue #15, the same defect as #14). Same
// convention as internal/collect/gitlab/repoprotection and .../secretshygiene.
func (c *Collector) webhooksResult(ctx context.Context, org, repo string) model.CheckResult {
	client, err := c.newClient()
	if err != nil {
		return notCheckableAlways(idRepoWebhooks, webhooksTitle, org, repo,
			fmt.Sprintf("could not build a GitLab client: %v", err))
	}

	id := projectID(org, repo)
	hooks, err := gitlabcollect.GetJSONPaged[hook](ctx, client, "/projects/"+id+"/hooks", nil)
	prov := client.Provenance()
	if err != nil {
		return withProv(notCheckableAlways(idRepoWebhooks, webhooksTitle, org, repo,
			describeReadFailure(err)), prov)
	}

	if len(hooks) == 0 {
		return withProv(model.CheckResult{
			CheckID: idRepoWebhooks, Title: webhooksTitle, Status: model.StatusVerifiedFail,
			Reason: "the project has zero webhooks configured, so nothing exports push, release or " +
				"deployment events",
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform},
			Facts: map[string]any{"webhook_count": 0},
		}, prov)
	}

	// A confirmed executable, event-exporting hook is a pass regardless of
	// what any other hook's state is — the property only needs one to hold.
	// An unrecognised alert_status elsewhere in the list cannot spoil an
	// already-established pass.
	unrecognised := 0
	for _, h := range hooks {
		if h.AlertStatus == alertExecutable && h.exportsRelevantEvents() {
			return withProv(model.CheckResult{
				CheckID: idRepoWebhooks, Title: webhooksTitle, Status: model.StatusVerifiedPass,
				Reason: fmt.Sprintf("webhook %d is executable and subscribes to an event-export type", h.ID),
				Scope:  model.ScopeRef{Org: org, Repo: repo, Platform: platform},
				Facts:  map[string]any{"webhook_count": len(hooks), "matching_webhook_id": h.ID},
			}, prov)
		}
		switch h.AlertStatus {
		case alertExecutable, alertTemporarilyDisabled, alertDisabled:
		default:
			unrecognised++
		}
	}

	if unrecognised > 0 {
		// No pass was found, and at least one hook's status was never
		// interpreted — it might have been the one that qualifies. Refusing
		// to guess here is the same rule applied to gitlab group visibility
		// and GitHub's default-repo-permission: an unrecognised value must
		// never decide a verdict against the producer.
		return withProv(model.CheckResult{
			CheckID: idRepoWebhooks, Title: webhooksTitle, Status: model.StatusNotCheckable,
			Reason: fmt.Sprintf("%d of %d webhook(s) reported an alert_status this build does not recognise, "+
				"so whether an event-exporting webhook is currently active cannot be determined", unrecognised, len(hooks)),
			Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform},
			Facts: map[string]any{"webhook_count": len(hooks), "unrecognised_alert_status_count": unrecognised},
		}, prov)
	}

	return withProv(model.CheckResult{
		CheckID: idRepoWebhooks, Title: webhooksTitle, Status: model.StatusVerifiedFail,
		Reason: fmt.Sprintf("%d webhook(s) configured, but none is both executable and subscribed to push, "+
			"releases, or deployment events", len(hooks)),
		Scope: model.ScopeRef{Org: org, Repo: repo, Platform: platform},
		Facts: map[string]any{"webhook_count": len(hooks)},
	}, prov)
}

// describeReadFailure names the cause a 403 here almost always has. This
// endpoint is Free-tier, so — unlike most gated reads in this repo — a 403 is
// not a tier signal: it means the token sits below Maintainer (measured live,
// issue #19). Reporting the bare error left an operator to guess between a
// paywall, a missing project and an under-scoped token, and the tier guess is
// the one the package doc makes tempting.
func describeReadFailure(err error) string {
	if code, ok := gitlabcollect.StatusCodeOf(err); ok && code == http.StatusForbidden {
		return fmt.Sprintf("the project's webhooks could not be read: %v. This endpoint is Free-tier but "+
			"requires Maintainer — it returns 403 at Reporter — so an under-scoped token, not the project's "+
			"plan, is the usual cause", err)
	}
	return fmt.Sprintf("the project's webhooks could not be read: %v", err)
}

func withProv(r model.CheckResult, prov []model.Provenance) model.CheckResult {
	if prov == nil {
		prov = []model.Provenance{}
	}
	r.Provenance = prov
	return r
}
