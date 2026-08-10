package scahistory

import (
	"context"
	"strconv"
	"time"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
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
	OpenCriticalCount int
	OpenHighCount     int
	OpenMediumCount   int
	OpenLowCount      int
	OpenTotalCount    int
	// OpenUnclassifiedCount is alerts whose severity this build could not
	// interpret — a nil SecurityAdvisory (a shape GitHub does return, which is
	// why the read below nil-guards it) or a value not in the known set.
	//
	// Before this existed such an alert incremented only OpenTotalCount, so it
	// vanished from every severity bucket and the triage check reported "no
	// critical alert open" over alerts it had never classified. Counting them
	// explicitly is what lets that check refuse to make the claim.
	OpenUnclassifiedCount int
	OldestOpenAgeDays     float64
	OldestCriticalAgeDays float64
	// OldestUnclassifiedAgeDays lets the triage check say how long an alert it
	// could not classify has been sitting there, which is the difference
	// between "we cannot classify one new alert" and "we cannot classify one
	// that has been open for a year".
	OldestUnclassifiedAgeDays float64
}

// summarizeAlerts is a pure function: no I/O, so its severity/age math is
// independently table-driven-testable without a fake API server.
func summarizeAlerts(alerts []*ghgithub.DependabotAlert, now time.Time) alertSummary {
	var s alertSummary
	var oldestOpen, oldestCritical, oldestUnclassified time.Time

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
		default:
			// No silent bucket. An uninterpreted severity is recorded as such
			// rather than being absorbed into the total, because the total is
			// the one number that cannot distinguish "classified as harmless"
			// from "never classified at all".
			s.OpenUnclassifiedCount++
			if oldestUnclassified.IsZero() || createdAt.Before(oldestUnclassified) {
				oldestUnclassified = createdAt
			}
		}
	}

	if s.OpenTotalCount > 0 {
		s.OldestOpenAgeDays = now.Sub(oldestOpen).Hours() / 24
	}
	if s.OpenCriticalCount > 0 {
		s.OldestCriticalAgeDays = now.Sub(oldestCritical).Hours() / 24
	}
	if s.OpenUnclassifiedCount > 0 {
		s.OldestUnclassifiedAgeDays = now.Sub(oldestUnclassified).Hours() / 24
	}
	return s
}
