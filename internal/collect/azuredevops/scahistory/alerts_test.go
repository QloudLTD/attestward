package scahistory

import (
	"testing"
	"time"
)

// TestSummarizeAlerts_NoAlerts_ZeroCountZeroAge proves the empty case
// produces no false "0 days old" reading, and oldestAgeKnown stays false
// (there's no age to know, not a known age of zero).
func TestSummarizeAlerts_NoAlerts_ZeroCountZeroAge(t *testing.T) {
	count, age, known := summarizeAlerts(nil, time.Now())
	if count != 0 || age != 0 || known {
		t.Errorf("summarizeAlerts(nil) = (%d, %v, %v), want (0, 0, false)", count, age, known)
	}
}

// TestSummarizeAlerts_OldestCriticalWins proves the oldest firstSeenDate
// across multiple critical alerts drives the age calculation, not the most
// recent.
func TestSummarizeAlerts_OldestCriticalWins(t *testing.T) {
	now := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	alerts := []alertRaw{
		{FirstSeenDate: now.AddDate(0, 0, -10).Format(time.RFC3339), Severity: "critical", State: "active"},
		{FirstSeenDate: now.AddDate(0, 0, -45).Format(time.RFC3339), Severity: "critical", State: "active"},
	}
	count, age, known := summarizeAlerts(alerts, now)
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if !known {
		t.Error("known = false, want true (at least one date parsed)")
	}
	if age < 44.9 || age > 45.1 {
		t.Errorf("age = %v, want ~45 days (the older of the two)", age)
	}
}

// TestSummarizeAlerts_NonCriticalOrInactive_ExcludedClientSide proves the
// defensive client-side re-filter (see the package doc comment's judgment
// call 4 and summarizeAlerts' own doc comment) excludes an entry the
// server-side query criteria should already have excluded, rather than
// blindly trusting every returned row.
func TestSummarizeAlerts_NonCriticalOrInactive_ExcludedClientSide(t *testing.T) {
	now := time.Now().UTC()
	alerts := []alertRaw{
		{FirstSeenDate: now.AddDate(0, 0, -60).Format(time.RFC3339), Severity: "high", State: "active"},
		{FirstSeenDate: now.AddDate(0, 0, -60).Format(time.RFC3339), Severity: "critical", State: "fixed"},
		{FirstSeenDate: now.AddDate(0, 0, -1).Format(time.RFC3339), Severity: "CRITICAL", State: "ACTIVE"},
	}
	count, age, known := summarizeAlerts(alerts, now)
	if count != 1 {
		t.Fatalf("count = %d, want 1 (only the case-insensitively critical+active entry)", count)
	}
	if !known {
		t.Error("known = false, want true")
	}
	if age < 0.9 || age > 1.1 {
		t.Errorf("age = %v, want ~1 day", age)
	}
}

// TestSummarizeAlerts_UnparseableDate_StillCountedButExcludedFromAge proves
// a malformed firstSeenDate doesn't drop the alert from the count (it's
// still a real, currently-active critical alert), only from the oldest-age
// computation — and oldestAgeKnown reports false so the caller can't
// mistake the resulting zero-value age for a known "0 days old" (the
// regression this collector's own review round caught: see
// checkAlertsTriaged's doc comment).
func TestSummarizeAlerts_UnparseableDate_StillCountedButExcludedFromAge(t *testing.T) {
	now := time.Now().UTC()
	alerts := []alertRaw{
		{FirstSeenDate: "not-a-date", Severity: "critical", State: "active"},
	}
	count, age, known := summarizeAlerts(alerts, now)
	if count != 1 {
		t.Errorf("count = %d, want 1 (still counted despite the unparseable date)", count)
	}
	if known {
		t.Error("known = true, want false (no valid date parsed — the age is genuinely unknown, not zero)")
	}
	if age != 0 {
		t.Errorf("age = %v, want 0 (the zero value; callers must gate on known, not treat this as a real age)", age)
	}
}

// TestSummarizeAlerts_AllUnparseableAmongMultiple_KnownStaysFalse proves
// the all-unparseable-dates case still holds when there's more than one
// critical alert, none of which parsed.
func TestSummarizeAlerts_AllUnparseableAmongMultiple_KnownStaysFalse(t *testing.T) {
	now := time.Now().UTC()
	alerts := []alertRaw{
		{FirstSeenDate: "garbage", Severity: "critical", State: "active"},
		{FirstSeenDate: "", Severity: "critical", State: "active"},
	}
	count, age, known := summarizeAlerts(alerts, now)
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	if known {
		t.Error("known = true, want false (neither date parsed)")
	}
	if age != 0 {
		t.Errorf("age = %v, want 0", age)
	}
}
