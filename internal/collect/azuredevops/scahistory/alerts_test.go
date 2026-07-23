package scahistory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestAlertsEnvelope_DecodesBareArray proves the documented shape
// (Microsoft's own REST reference for Alerts - List states a bare
// Alert[] response) still decodes correctly — this collector doesn't
// assume it's wrong, only that it isn't the only possibility (see
// fetchActiveCriticalDependencyAlerts' own doc comment, issue #154/#155).
func TestAlertsEnvelope_DecodesBareArray(t *testing.T) {
	var e alertsEnvelope
	if err := json.Unmarshal([]byte(`[{"firstSeenDate":"2026-01-01T00:00:00Z","severity":"critical","state":"active"}]`), &e); err != nil {
		t.Fatalf("Unmarshal bare array: %v", err)
	}
	if len(e.Alerts) != 1 || e.Alerts[0].Severity != "critical" {
		t.Errorf("Alerts = %#v, want one critical alert", e.Alerts)
	}
}

// TestAlertsEnvelope_DecodesCountValueEnvelope is the regression test for
// issue #154/#155's live audit-streams bug applied preemptively to this
// endpoint: since this endpoint's real response has never been observed
// (the live demo org 400s here, unlicensed for GHAzDO) and a sibling
// advsec-adjacent endpoint's identically-sourced "it's a bare array" claim
// from Microsoft's own docs already proved false once, this proves the
// {count,value} envelope — the shape every other verified ADO list
// endpoint in this project actually uses — decodes too. count is
// consistent with a one-element value here, so it doesn't trip the
// wrong-envelope sanity guard (see the two garbage-shape tests below for
// when it does).
func TestAlertsEnvelope_DecodesCountValueEnvelope(t *testing.T) {
	var e alertsEnvelope
	body := `{"count":1,"value":[{"firstSeenDate":"2026-01-01T00:00:00Z","severity":"critical","state":"active"}]}`
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("Unmarshal envelope: %v", err)
	}
	if len(e.Alerts) != 1 || e.Alerts[0].Severity != "critical" {
		t.Errorf("Alerts = %#v, want one critical alert", e.Alerts)
	}
}

// TestAlertsEnvelope_ZeroCountEnvelope proves the exact shape a live
// zero-alerts response would take under the envelope hypothesis —
// `{"count":0,"value":[]}`, mirroring the real recorded audit-streams
// response that exposed this whole class of bug — decodes to an empty,
// non-nil slice rather than erroring. count is 0 here, so the
// wrong-envelope guard (which only fires for count>0 alongside an empty
// value) correctly stays quiet — a real zero-alerts response must not be
// mistaken for a decoding failure.
func TestAlertsEnvelope_ZeroCountEnvelope(t *testing.T) {
	var e alertsEnvelope
	if err := json.Unmarshal([]byte(`{"count":0,"value":[]}`), &e); err != nil {
		t.Fatalf("Unmarshal zero-count envelope: %v", err)
	}
	if len(e.Alerts) != 0 {
		t.Errorf("Alerts = %#v, want empty", e.Alerts)
	}
}

// TestAlertsEnvelope_MismatchedCountEmptyValue_Errors is the regression
// test for the MEDIUM item found in review: without a count sanity
// guard, `{"count":5,"value":[]}` — a real wrong-envelope/decoding
// failure, not five alerts — silently decoded to zero alerts, which
// checkAlertsTriaged would have read as a clean verified-pass ("no
// alert open beyond the window") over what's actually garbage.
func TestAlertsEnvelope_MismatchedCountEmptyValue_Errors(t *testing.T) {
	var e alertsEnvelope
	err := json.Unmarshal([]byte(`{"count":5,"value":[]}`), &e)
	if err == nil {
		t.Fatal("Unmarshal = nil error, want an error for count=5 with an empty value array")
	}
}

// TestAlertsEnvelope_ThirdShapeWrongKey_Errors is the second regression
// case for the same MEDIUM item: a hypothetical third response shape
// using a different key for the list (e.g. "alerts" instead of "value")
// decodes count fine but leaves Value empty via ordinary struct-tag
// field-not-found behavior — the same wrong-envelope guard must catch
// this too, not just an exact {count,value} count/length mismatch.
func TestAlertsEnvelope_ThirdShapeWrongKey_Errors(t *testing.T) {
	var e alertsEnvelope
	err := json.Unmarshal([]byte(`{"count":2,"alerts":[{"severity":"critical"},{"severity":"critical"}]}`), &e)
	if err == nil {
		t.Fatal("Unmarshal = nil error, want an error for a third shape (\"alerts\" key) the decoder doesn't recognize")
	}
}

// TestAlertsEnvelope_NeitherShape_Errors proves this doesn't silently
// swallow a genuinely malformed response.
func TestAlertsEnvelope_NeitherShape_Errors(t *testing.T) {
	var e alertsEnvelope
	if err := json.Unmarshal([]byte(`"just a string"`), &e); err == nil {
		t.Error("Unmarshal = nil error, want an error for a shape that's neither a bare array nor a {value:[...]} object")
	}
}

// TestAlertsEnvelope_MalformedArrayElement_ErrorNamesRealCause is the
// regression test for the LOW item found in review: when the input IS
// array-shaped but one element is malformed, the final error must not
// misattribute the failure to "neither a bare array nor an envelope" —
// that's the envelope-path's own generic "can't unmarshal array into
// struct" error, which would mask the actually useful bare-array-path
// error naming the real problem (a field type mismatch here).
func TestAlertsEnvelope_MalformedArrayElement_ErrorNamesRealCause(t *testing.T) {
	var e alertsEnvelope
	// severity is a number here, not a string — a genuine field-type
	// mismatch the bare-array decode attempt will name specifically.
	err := json.Unmarshal([]byte(`[{"severity":12345}]`), &e)
	if err == nil {
		t.Fatal("Unmarshal = nil error, want an error for a malformed array element")
	}
	if !strings.Contains(err.Error(), "severity") {
		t.Errorf("error = %q, want it to mention the real cause (the malformed severity field), not just report neither shape matched", err.Error())
	}
}

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
