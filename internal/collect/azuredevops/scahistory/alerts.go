package scahistory

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sioakim/attestward/internal/collect/azuredevops"
)

const (
	alertSeverityCritical = "critical"
	alertStateActive      = "active"
	alertTypeDependency   = "dependency"
)

// alertRaw is the subset of Azure DevOps's Alert shape (Alerts - List,
// scope vso.advsec, https://learn.microsoft.com/en-us/rest/api/azure/devops/advancedsecurity/alerts/list)
// fetchActiveCriticalDependencyAlerts needs. severity/state enum values
// ("critical", "active") and the firstSeenDate field name/shape (an
// RFC3339 date-time string) are confirmed directly against that reference.
type alertRaw struct {
	FirstSeenDate string `json:"firstSeenDate"`
	Severity      string `json:"severity"`
	State         string `json:"state"`
}

// fetchActiveCriticalDependencyAlerts lists every currently-active,
// critical-severity, dependency-type alert for one repo via GET
// https://advsec.dev.azure.com/{org}/{project}/_apis/alert/repositories/{repository}/alerts?criteria.alertType=dependency&criteria.states=active&criteria.severities=critical&api-version=7.2-preview.1
// (Alerts - List, scope vso.advsec) — issue #152's own literal query; see
// the package doc comment's judgment call 4 for why this is narrower than
// the GitHub twin's "fetch every open alert, categorize client-side"
// approach.
//
// The response shape is a bare JSON array (Alert[] per Microsoft's own REST
// reference), not the {count,value} envelope azuredevops.GetJSON expects —
// mirrors auditlogging's checkLogStreaming's identical situation for its
// own bare-array AuditStream[] endpoint; this uses GetJSONObject decoding
// straight into a slice instead, the same established pattern.
//
// Pagination (a continuationToken query parameter / x-ms-continuationtoken
// response header pair the same List operation documents) is not followed
// here, matching that same auditStreams precedent: an org's currently
// active, critical-severity, dependency-only alert count is expected to be
// small enough in practice that a single page suffices. If a real scan
// target ever proves that assumption wrong, extending this to page is this
// check's own follow-up, not a correctness bug silently accepted here.
//
// [fixture-verify, issue #34/#155's S9 verify list] A real false-pass edge
// this single-page assumption creates: no orderBy is set here, so results
// come back in the List operation's own default order ("id", per
// Microsoft's reference — not "firstSeen"). If a repo genuinely has more
// active critical alerts than one page returns, the OLDEST one (the one
// that actually determines whether checkAlertsTriaged's triage-window
// check should fail) could land on a page this call never fetches —
// producing a false verified-pass built only from the younger alerts that
// happened to sort first by id. S9 should confirm a real page size for
// this endpoint and, if the assumption above doesn't hold in practice,
// either page through results or set orderBy=firstSeen so the oldest alert
// is always in the first (and, for now, only) page fetched.
func fetchActiveCriticalDependencyAlerts(ctx context.Context, client *azuredevops.Client, project, repositoryID string) ([]alertRaw, error) {
	path := fmt.Sprintf("/%s/%s/_apis/alert/repositories/%s/alerts", client.Org(), project, repositoryID)
	query := url.Values{
		"criteria.alertType":  {alertTypeDependency},
		"criteria.states":     {alertStateActive},
		"criteria.severities": {alertSeverityCritical},
		"api-version":         {"7.2-preview.1"},
	}

	var raw []alertRaw
	if err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostAdvSec, path, query, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// summarizeAlerts is a pure function: no I/O, so its count/age math is
// independently table-driven-testable without a fake API server. It
// re-filters severity/state client-side (case-insensitive) rather than
// trusting the query's own criteria filters blindly — the same defensive
// posture this epic's own case-insensitive-enum precedent established
// (C09's audit-stream statuses, pipelinehistory's build result): Azure
// DevOps services in this project's own experience don't reliably match
// their own documented casing. An alert whose firstSeenDate fails to parse
// as RFC3339 still counts toward criticalCount (it's still a real,
// currently-active critical alert the query returned), but is excluded
// from the oldest-age computation — an unparseable date is a genuine
// unknown, not evidence the alert is either old or new.
//
// oldestAgeKnown is false whenever criticalCount > 0 but not one of those
// alerts' firstSeenDate values parsed — the caller (checkAlertsTriaged)
// must not read the resulting zero-value oldestAgeDays as "0 days old"
// (found in review: an earlier version did exactly that, producing a
// false verified-pass over genuinely unknown ages).
func summarizeAlerts(alerts []alertRaw, now time.Time) (criticalCount int, oldestAgeDays float64, oldestAgeKnown bool) {
	var oldest time.Time
	for _, a := range alerts {
		if !strings.EqualFold(a.Severity, alertSeverityCritical) || !strings.EqualFold(a.State, alertStateActive) {
			continue
		}
		criticalCount++
		seen, err := time.Parse(time.RFC3339, a.FirstSeenDate)
		if err != nil {
			continue
		}
		if oldest.IsZero() || seen.Before(oldest) {
			oldest = seen
		}
	}
	if criticalCount > 0 && !oldest.IsZero() {
		oldestAgeDays = now.Sub(oldest).Hours() / 24
		oldestAgeKnown = true
	}
	return criticalCount, oldestAgeDays, oldestAgeKnown
}
