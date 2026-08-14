package scahistory

import (
	"strings"
	"testing"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/model"

	ghgithub "github.com/google/go-github/v75/github"
)

func alertDay(n int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, n)
}

func alertAt(severity string, createdAt time.Time) *ghgithub.DependabotAlert {
	return &ghgithub.DependabotAlert{
		CreatedAt:        &ghgithub.Timestamp{Time: createdAt},
		SecurityAdvisory: &ghgithub.DependabotSecurityAdvisory{Severity: ghgithub.Ptr(severity)},
	}
}

func TestSummarizeAlerts(t *testing.T) {
	now := alertDay(100)

	t.Run("no alerts", func(t *testing.T) {
		got := summarizeAlerts(nil, now)
		if got.OpenTotalCount != 0 || got.OldestOpenAgeDays != 0 {
			t.Errorf("summarizeAlerts(nil) = %+v, want all zero", got)
		}
	})

	t.Run("counts by severity", func(t *testing.T) {
		alerts := []*ghgithub.DependabotAlert{
			alertAt(severityCritical, alertDay(90)),
			alertAt(severityCritical, alertDay(50)),
			alertAt(severityHigh, alertDay(80)),
			alertAt(severityMedium, alertDay(70)),
			alertAt(severityLow, alertDay(60)),
		}
		got := summarizeAlerts(alerts, now)
		if got.OpenCriticalCount != 2 {
			t.Errorf("OpenCriticalCount = %d, want 2", got.OpenCriticalCount)
		}
		if got.OpenHighCount != 1 {
			t.Errorf("OpenHighCount = %d, want 1", got.OpenHighCount)
		}
		if got.OpenMediumCount != 1 {
			t.Errorf("OpenMediumCount = %d, want 1", got.OpenMediumCount)
		}
		if got.OpenLowCount != 1 {
			t.Errorf("OpenLowCount = %d, want 1", got.OpenLowCount)
		}
		if got.OpenTotalCount != 5 {
			t.Errorf("OpenTotalCount = %d, want 5", got.OpenTotalCount)
		}
	})

	t.Run("oldest open age is the oldest across all severities", func(t *testing.T) {
		alerts := []*ghgithub.DependabotAlert{
			alertAt(severityLow, alertDay(20)),  // 80 days old
			alertAt(severityHigh, alertDay(10)), // 90 days old, oldest overall
		}
		got := summarizeAlerts(alerts, now)
		if got.OldestOpenAgeDays != 90 {
			t.Errorf("OldestOpenAgeDays = %v, want 90", got.OldestOpenAgeDays)
		}
	})

	t.Run("oldest critical age tracked independently of oldest open age", func(t *testing.T) {
		alerts := []*ghgithub.DependabotAlert{
			alertAt(severityLow, alertDay(0)),       // 100 days old, oldest overall, but not critical
			alertAt(severityCritical, alertDay(70)), // 30 days old — the only critical
		}
		got := summarizeAlerts(alerts, now)
		if got.OldestOpenAgeDays != 100 {
			t.Errorf("OldestOpenAgeDays = %v, want 100 (from the low-severity alert)", got.OldestOpenAgeDays)
		}
		if got.OldestCriticalAgeDays != 30 {
			t.Errorf("OldestCriticalAgeDays = %v, want 30 (must not be dragged down by the older non-critical alert)", got.OldestCriticalAgeDays)
		}
	})

	t.Run("no critical alerts leaves OldestCriticalAgeDays at zero", func(t *testing.T) {
		alerts := []*ghgithub.DependabotAlert{alertAt(severityLow, alertDay(50))}
		got := summarizeAlerts(alerts, now)
		if got.OldestCriticalAgeDays != 0 {
			t.Errorf("OldestCriticalAgeDays = %v, want 0 (no critical alerts)", got.OldestCriticalAgeDays)
		}
	})

	t.Run("unrecognized severity string counts toward total but no bucket", func(t *testing.T) {
		alerts := []*ghgithub.DependabotAlert{alertAt("unknown", alertDay(50))}
		got := summarizeAlerts(alerts, now)
		if got.OpenTotalCount != 1 {
			t.Errorf("OpenTotalCount = %d, want 1", got.OpenTotalCount)
		}
		if got.OpenCriticalCount+got.OpenHighCount+got.OpenMediumCount+got.OpenLowCount != 0 {
			t.Errorf("severity buckets = %+v, want all zero for an unrecognized severity", got)
		}
	})
}

// TestUninterpretedSeverityIsCountedNotAbsorbed pins the false pass this fix
// closes. GitHub does return alerts with a nil SecurityAdvisory — the
// production read nil-guards it, so the shape is observed, not hypothetical —
// and such an alert used to increment only OpenTotalCount. It vanished from
// every severity bucket, and the triage check then reported "no critical alert
// open beyond the window" over an alert it had never classified.
func TestUninterpretedSeverityIsCountedNotAbsorbed(t *testing.T) {
	now := alertDay(100)
	cases := []struct {
		name  string
		alert *ghgithub.DependabotAlert
	}{
		{"nil advisory", &ghgithub.DependabotAlert{CreatedAt: &ghgithub.Timestamp{Time: alertDay(1)}}},
		{"empty severity", alertAt("", alertDay(1))},
		{"unknown severity", alertAt("catastrophic", alertDay(1))},
		{"wrong case", alertAt("Critical", alertDay(1))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := summarizeAlerts([]*ghgithub.DependabotAlert{c.alert}, now)
			if got.OpenUnclassifiedCount != 1 {
				t.Errorf("OpenUnclassifiedCount = %d, want 1 — an uninterpreted severity must be recorded as such, "+
					"not absorbed into the total where it looks classified", got.OpenUnclassifiedCount)
			}
			if got.OpenCriticalCount+got.OpenHighCount+got.OpenMediumCount+got.OpenLowCount != 0 {
				t.Errorf("an uninterpreted severity landed in a severity bucket: %+v", got)
			}
			if got.OldestUnclassifiedAgeDays != 99 {
				t.Errorf("OldestUnclassifiedAgeDays = %v, want 99", got.OldestUnclassifiedAgeDays)
			}
		})
	}
}

// TestSeverityBucketsAlwaysSumToTheTotal is the invariant that makes the
// evidence self-consistent. If it ever fails, a pack's facts contain a
// conclusion its own numbers contradict.
func TestSeverityBucketsAlwaysSumToTheTotal(t *testing.T) {
	now := alertDay(100)
	alerts := []*ghgithub.DependabotAlert{
		alertAt(severityCritical, alertDay(1)),
		alertAt(severityHigh, alertDay(2)),
		alertAt(severityMedium, alertDay(3)),
		alertAt(severityLow, alertDay(4)),
		alertAt("", alertDay(5)),
		{CreatedAt: &ghgithub.Timestamp{Time: alertDay(6)}},
	}
	got := summarizeAlerts(alerts, now)
	sum := got.OpenCriticalCount + got.OpenHighCount + got.OpenMediumCount + got.OpenLowCount + got.OpenUnclassifiedCount
	if sum != got.OpenTotalCount {
		t.Errorf("buckets sum to %d but total is %d — %d alert(s) are unaccounted for, which is exactly how an "+
			"unclassified critical alert used to disappear", sum, got.OpenTotalCount, got.OpenTotalCount-sum)
	}
}

// TestUnclassifiedAlertBlocksTheTriagePass is the finding itself: a critical,
// long-open alert whose severity the build could not read used to produce
// verified-pass — a signed claim that triage was clean, over an alert never
// classified.
func TestUnclassifiedAlertBlocksTheTriagePass(t *testing.T) {
	now := alertDay(100)
	// One unclassified alert, open far beyond the triage window.
	summary := summarizeAlerts([]*ghgithub.DependabotAlert{
		{CreatedAt: &ghgithub.Timestamp{Time: alertDay(1)}},
	}, now)

	got := checkAlertsTriaged("o", "r", nil, nil, summary, collect.Scope{}, nil)
	if got.Status == model.StatusVerifiedPass {
		t.Fatal("verified-pass asserted over an alert whose severity was never interpreted; it may be the critical one")
	}
	if got.Status != model.StatusPartial {
		t.Errorf("status = %q, want partial", got.Status)
	}
	if !strings.Contains(got.Reason, "could not be classified") {
		t.Errorf("reason must say why the claim cannot be made, got: %s", got.Reason)
	}
}

// TestFullyClassifiedAlertsStillPass guards the other direction, so the refusal
// cannot swallow the case the check exists to answer.
func TestFullyClassifiedAlertsStillPass(t *testing.T) {
	now := alertDay(100)
	summary := summarizeAlerts([]*ghgithub.DependabotAlert{
		alertAt(severityLow, alertDay(1)),
		alertAt(severityCritical, alertDay(99)), // critical but inside the window
	}, now)
	if got := checkAlertsTriaged("o", "r", nil, nil, summary, collect.Scope{}, nil); got.Status != model.StatusVerifiedPass {
		t.Errorf("status = %q (%s), want verified-pass — every alert was classified and no critical is stale",
			got.Status, got.Reason)
	}
}

// TestBothFindingsAreNamedTogether pins that the definite finding leading does
// not bury the incomplete one. A reader who fixes the critical alert and
// re-scans should not meet the unclassified finding as a surprise.
func TestBothFindingsAreNamedTogether(t *testing.T) {
	now := alertDay(200)
	summary := summarizeAlerts([]*ghgithub.DependabotAlert{
		alertAt(severityCritical, alertDay(1)),              // stale critical
		{CreatedAt: &ghgithub.Timestamp{Time: alertDay(2)}}, // unclassified
	}, now)
	got := checkAlertsTriaged("o", "r", nil, nil, summary, collect.Scope{}, nil)
	if got.Status != model.StatusPartial {
		t.Fatalf("status = %q, want partial", got.Status)
	}
	if !strings.Contains(got.Reason, "critical alert(s) open") {
		t.Errorf("reason must name the definite finding first, got: %s", got.Reason)
	}
	if !strings.Contains(got.Reason, "could not be classified") {
		t.Errorf("reason must also name the unclassified alerts, got: %s", got.Reason)
	}
}
