package scahistory

import (
	"context"
	"strconv"
	"time"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
)

const (
	severityCritical = "critical"
	severityHigh     = "high"
	severityMedium   = "medium"
	severityLow      = "low"
)

// fetchOpenAlerts lists every currently-open Dependabot alert for a repo
// (all pages). Paginates on whichever of resp.NextPage (numeric page
// links) or resp.Cursor (cursor-style links) go-github's Link-header
// parser populated — this endpoint's real pagination style isn't
// independently confirmed against GitHub's docs, so this handles both
// rather than assuming one.
func fetchOpenAlerts(ctx context.Context, client *ghcollect.Client, org, repo string) ([]*ghgithub.DependabotAlert, *ghgithub.Response, error) {
	var all []*ghgithub.DependabotAlert
	opts := &ghgithub.ListAlertsOptions{
		State:             ghgithub.Ptr("open"),
		ListCursorOptions: ghgithub.ListCursorOptions{PerPage: 100},
	}
	for {
		alerts, resp, err := client.REST.Dependabot.ListRepoAlerts(ctx, org, repo, opts)
		if err != nil {
			return nil, resp, err
		}
		all = append(all, alerts...)
		switch {
		case resp.NextPage != 0:
			// ListAlertsOptions embeds both ListOptions (Page int) and
			// ListCursorOptions (Page string) — disambiguate explicitly.
			opts.ListCursorOptions.Page = strconv.Itoa(resp.NextPage)
		case resp.Cursor != "":
			opts.Cursor = resp.Cursor
		default:
			return all, nil, nil
		}
	}
}

// alertSummary is fact-only data derived from a repo's currently-open
// Dependabot alerts — counts and ages, never CVE/GHSA identifiers or
// package names, keeping the evidence pack privacy-lean by default (see
// issue #18: "no CVE details in the pack unless --include-findings
// later").
type alertSummary struct {
	OpenCriticalCount     int
	OpenHighCount         int
	OpenMediumCount       int
	OpenLowCount          int
	OpenTotalCount        int
	OldestOpenAgeDays     float64
	OldestCriticalAgeDays float64
}

// summarizeAlerts is a pure function: no I/O, so its severity/age math is
// independently table-driven-testable without a fake API server.
func summarizeAlerts(alerts []*ghgithub.DependabotAlert, now time.Time) alertSummary {
	var s alertSummary
	var oldestOpen, oldestCritical time.Time

	for _, a := range alerts {
		s.OpenTotalCount++
		createdAt := a.GetCreatedAt().Time
		if oldestOpen.IsZero() || createdAt.Before(oldestOpen) {
			oldestOpen = createdAt
		}

		severity := ""
		if adv := a.GetSecurityAdvisory(); adv != nil {
			severity = adv.GetSeverity()
		}
		switch severity {
		case severityCritical:
			s.OpenCriticalCount++
			if oldestCritical.IsZero() || createdAt.Before(oldestCritical) {
				oldestCritical = createdAt
			}
		case severityHigh:
			s.OpenHighCount++
		case severityMedium:
			s.OpenMediumCount++
		case severityLow:
			s.OpenLowCount++
		}
	}

	if s.OpenTotalCount > 0 {
		s.OldestOpenAgeDays = now.Sub(oldestOpen).Hours() / 24
	}
	if s.OpenCriticalCount > 0 {
		s.OldestCriticalAgeDays = now.Sub(oldestCritical).Hours() / 24
	}
	return s
}
