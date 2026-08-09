package github

import (
	"net/http"
	"testing"
)

func responseWithScopes(scopes string) *http.Response {
	h := http.Header{}
	if scopes != "" {
		h.Set("X-OAuth-Scopes", scopes)
	}
	return &http.Response{Header: h}
}

func TestScopeTracker_ParsesReadOnlyScopes(t *testing.T) {
	s := &scopeTracker{}
	s.observe(responseWithScopes("read:org, read:audit_log"))

	got := s.Scopes()
	want := []string{"read:org", "read:audit_log"}
	if len(got) != len(want) {
		t.Fatalf("Scopes() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Scopes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if s.HasWriteScope() {
		t.Error("HasWriteScope() = true, want false for an all-read-only scope set")
	}
}

func TestScopeTracker_DetectsWriteScope(t *testing.T) {
	s := &scopeTracker{}
	s.observe(responseWithScopes("read:org, repo"))

	if !s.HasWriteScope() {
		t.Error("HasWriteScope() = false, want true (\"repo\" is write-capable despite not saying so)")
	}
}

func TestScopeTracker_UnrecognizedScopeCountsAsPossiblyWrite(t *testing.T) {
	s := &scopeTracker{}
	s.observe(responseWithScopes("some_future_scope_we_have_never_seen"))

	if !s.HasWriteScope() {
		t.Error("HasWriteScope() = false, want true (unknown scopes default to possibly-write, not silently read-only)")
	}
}

func TestScopeTracker_NoHeaderMeansFineGrainedPAT_NoFalsePositive(t *testing.T) {
	s := &scopeTracker{}
	s.observe(responseWithScopes("")) // fine-grained PATs send no X-OAuth-Scopes header

	if got := s.Scopes(); len(got) != 0 {
		t.Errorf("Scopes() = %v, want empty for a fine-grained PAT (not introspectable this way)", got)
	}
	if s.HasWriteScope() {
		t.Error("HasWriteScope() = true, want false when nothing has been observed — nothing to warn about yet")
	}
}

func TestScopeTracker_FirstObservationWins(t *testing.T) {
	s := &scopeTracker{}
	s.observe(responseWithScopes("read:org"))
	s.observe(responseWithScopes("repo")) // a later, different response must not overwrite

	got := s.Scopes()
	if len(got) != 1 || got[0] != "read:org" {
		t.Errorf("Scopes() = %v, want [read:org] (first observation should win)", got)
	}
}
