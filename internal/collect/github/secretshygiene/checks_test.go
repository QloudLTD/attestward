package secretshygiene

import (
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
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
			got, reason := evalGHASGatedFeature("secret scanning", tt.status, tt.isPrivate, tt.ghasStatus, collect.Scope{})
			if got != tt.wantStatus {
				t.Errorf("evalGHASGatedFeature(..., collect.Scope{}) = %q, want %q (reason=%q)", got, tt.wantStatus, reason)
			}
			if reason == "" {
				t.Error("reason is empty")
			}
		})
	}
}

// TestEvalGHASGatedFeature_PublicRepoOnGHESIsNotAFail is the regression test
// for a false verified-fail that reached signed packs. On github.com secret
// scanning is free for public repositories, so "off" is a real gap. GitHub
// Enterprise Server has no such free tier — the feature is licensed
// install-wide regardless of visibility — so faulting a producer there
// invented a finding, told them to enable something they may not be licensed
// for, and contradicted this collector's own GHESNoteLicenceGated promise of
// "never a false verified-fail".
func TestEvalGHASGatedFeature_PublicRepoOnGHESIsNotAFail(t *testing.T) {
	disabled := "disabled"

	status, reason := evalGHASGatedFeature("secret scanning", &disabled, false, nil, collect.Scope{})
	if status != model.StatusVerifiedFail {
		t.Errorf("github.com public repo: status = %q, want verified-fail (the feature is free there)", status)
	}
	if !strings.Contains(reason, "freely available") {
		t.Errorf("github.com reason = %q, want the unchanged free-tier wording", reason)
	}

	status, reason = evalGHASGatedFeature("secret scanning", &disabled, false, nil, collect.Scope{IsGHES: true})
	if status == model.StatusVerifiedFail {
		t.Errorf("GHES public repo: status = %q, want not-checkable — GHES has no free public-repo tier, so this "+
			"would fault a producer for a feature their install may not be licensed for", status)
	}
	if strings.Contains(reason, "freely available") {
		t.Errorf("GHES reason claims a github.com free tier that does not exist there: %q", reason)
	}
}
