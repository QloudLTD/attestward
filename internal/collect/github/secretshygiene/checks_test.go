package secretshygiene

import (
	"testing"

	"gitlab.com/sioakeim/attestward/internal/model"
)

func strPtr(s string) *string { return &s }

// TestEvalGHASGatedFeature is a table-driven test of the pure merge logic,
// pinning a real pre-merge bug: an observed "enabled" status was being
// discarded in favor of a not-checkable licensing inference whenever GHAS
// itself read off/nil on a private repo — even though the feature's own
// field is a direct, positive observation that should never be thrown away
// (GitHub's 2025 unbundling of GHAS into standalone Secret Protection/Code
// Security products means a private repo can plausibly have one of these
// features licensed and enabled while the legacy combined advanced_security
// flag reads disabled).
func TestEvalGHASGatedFeature(t *testing.T) {
	tests := []struct {
		name       string
		status     *string
		isPrivate  bool
		ghasStatus *string
		wantStatus model.Status
	}{
		{"public enabled", strPtr("enabled"), false, nil, model.StatusVerifiedPass},
		{"public disabled", strPtr("disabled"), false, nil, model.StatusVerifiedFail},
		{"public nil status", nil, false, nil, model.StatusVerifiedFail},
		{"private no GHAS disabled feature", strPtr("disabled"), true, strPtr("disabled"), model.StatusNotCheckable},
		{"private no GHAS nil feature", nil, true, nil, model.StatusNotCheckable},
		{"private GHAS enabled feature disabled", strPtr("disabled"), true, strPtr("enabled"), model.StatusVerifiedFail},
		{"private GHAS enabled feature nil", nil, true, strPtr("enabled"), model.StatusVerifiedFail},
		{"private GHAS enabled feature enabled", strPtr("enabled"), true, strPtr("enabled"), model.StatusVerifiedPass},
		// The regression case: an observed "enabled" must win even when
		// GHAS itself reads off — a positive observation is never
		// discarded in favor of a licensing inference.
		{"private GHAS disabled feature nonetheless enabled", strPtr("enabled"), true, strPtr("disabled"), model.StatusVerifiedPass},
		{"private GHAS nil feature nonetheless enabled", strPtr("enabled"), true, nil, model.StatusVerifiedPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := evalGHASGatedFeature("secret scanning", tt.status, tt.isPrivate, tt.ghasStatus)
			if got != tt.wantStatus {
				t.Errorf("evalGHASGatedFeature(...) = %q, want %q (reason=%q)", got, tt.wantStatus, reason)
			}
			if reason == "" {
				t.Error("reason is empty")
			}
		})
	}
}
