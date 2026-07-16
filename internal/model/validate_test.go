package model

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func minimalValidPack() EvidencePack {
	return EvidencePack{
		SchemaVersion: SchemaVersion,
		ToolVersion:   "0.0.0-test",
		MappingVersions: MappingVersions{
			SSDF:     "1.0.0",
			CISAForm: "1.0.0",
		},
		Scope:         ScanScope{Org: "attestor-demo", Repos: []string{"good-repo"}},
		ScanStartedAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
		ScanEndedAt:   time.Date(2026, 7, 13, 12, 0, 5, 0, time.UTC),
		Results: []CheckResult{
			{
				CheckID:    "C02.repo-protection.required-reviews",
				Title:      "Branch protection requires reviews",
				Status:     StatusVerifiedPass,
				Reason:     "main requires 1 approving review",
				Scope:      ScopeRef{Org: "attestor-demo", Repo: "good-repo"},
				Provenance: []Provenance{},
			},
		},
	}
}

func TestValidateAgainstSchema_ValidPackPasses(t *testing.T) {
	if err := minimalValidPack().ValidateAgainstSchema(); err != nil {
		t.Fatalf("ValidateAgainstSchema() = %v, want no error", err)
	}
}

func TestValidateAgainstSchema_NilResultsFails(t *testing.T) {
	pack := minimalValidPack()
	pack.Results = nil
	if err := pack.ValidateAgainstSchema(); err == nil {
		t.Fatal("ValidateAgainstSchema() with nil Results = nil error, want a schema-validation error (nil marshals as JSON null, which fails the array-typed results field)")
	}
}

// TestValidateAgainstSchema_NilProvenanceFails pins the exact bug PR #103's
// review caught: CheckResult.Provenance is `json:"provenance"` with no
// omitempty, and the schema requires it as an array — a nil (as opposed to
// empty) slice marshals to JSON null and fails validation just like nil
// Results does above. Three collectors (C01/C04/C09) built not-checkable
// results with a nil Provenance for a personal-account scan target and
// this went undetected by every collector-level unit test, because none of
// them pushed the result through schema validation — only an
// orchestration-level test (or this one, at the layer the bug actually
// bites) catches it. Any future collector that leaves Provenance nil on
// some path should fail here first.
func TestValidateAgainstSchema_NilProvenanceFails(t *testing.T) {
	pack := minimalValidPack()
	pack.Results[0].Provenance = nil
	if err := pack.ValidateAgainstSchema(); err == nil {
		t.Fatal("ValidateAgainstSchema() with a nil Provenance = nil error, want a schema-validation error (nil marshals as JSON null, which fails the array-typed provenance field)")
	}
}

func TestValidateAgainstSchema_BadStatusFails(t *testing.T) {
	pack := minimalValidPack()
	pack.Results[0].Status = Status("not-a-real-status")
	if err := pack.ValidateAgainstSchema(); err == nil {
		t.Fatal("ValidateAgainstSchema() with an invalid status = nil error, want a schema-validation error")
	}
}

func TestOversizedFacts(t *testing.T) {
	small := strings.Repeat("a", 100)
	large := strings.Repeat("a", MaxFactValueBytes+1)
	c := CheckResult{
		CheckID: "C01.example",
		Facts: map[string]any{
			"small_fact": small,
			"large_fact": large,
		},
	}
	got := c.OversizedFacts()
	if len(got) != 1 || got[0] != "large_fact" {
		t.Fatalf("OversizedFacts() = %v, want [\"large_fact\"]", got)
	}
}

func TestOversizedFacts_NoneOversized(t *testing.T) {
	c := CheckResult{
		CheckID: "C01.example",
		Facts:   map[string]any{"a": "small value", "b": 42},
	}
	if got := c.OversizedFacts(); len(got) != 0 {
		t.Fatalf("OversizedFacts() = %v, want none", got)
	}
}

func TestValidateFactsSizes_FailsOnOversizedFact(t *testing.T) {
	pack := minimalValidPack()
	pack.Results[0].Facts = map[string]any{"leaked_payload": strings.Repeat("x", MaxFactValueBytes+1)}

	err := pack.ValidateFactsSizes()
	if err == nil {
		t.Fatal("ValidateFactsSizes() = nil, want an error naming the oversized fact")
	}
	if !strings.Contains(err.Error(), "leaked_payload") {
		t.Errorf("error = %v, want it to name the offending fact key", err)
	}
}

func TestValidateFactsSizes_PassesForNormalFacts(t *testing.T) {
	pack := minimalValidPack()
	pack.Results[0].Facts = map[string]any{"required_approving_review_count": 1}
	if err := pack.ValidateFactsSizes(); err != nil {
		t.Fatalf("ValidateFactsSizes() = %v, want no error", err)
	}
}

// TestFixturePackPassesFullValidation runs the same two checks
// writeEvidencePack (cmd/attestor) will run before every real write
// against the actual committed testdata/fixture-pack.json — both must
// pass cleanly, or the fixture itself doesn't represent a shippable pack.
func TestFixturePackPassesFullValidation(t *testing.T) {
	raw, err := os.ReadFile("testdata/fixture-pack.json")
	if err != nil {
		t.Fatalf("read testdata/fixture-pack.json: %v", err)
	}
	var pack EvidencePack
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatalf("unmarshal testdata/fixture-pack.json: %v", err)
	}

	if err := pack.ValidateAgainstSchema(); err != nil {
		t.Errorf("ValidateAgainstSchema: %v", err)
	}
	if err := pack.ValidateFactsSizes(); err != nil {
		t.Errorf("ValidateFactsSizes: %v", err)
	}
}
