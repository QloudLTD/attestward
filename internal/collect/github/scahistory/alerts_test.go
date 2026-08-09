package scahistory

import (
	"testing"
	"time"

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
