package mapping

import (
	"testing"

	"gitlab.com/sioakeim/attestward/internal/model"
)

func fixtureMappings() (*SSDFMapping, *CISAMapping) {
	ssdf := &SSDFMapping{
		Tasks: []SSDFTask{
			{ID: "PO.5.1", Checks: []string{"C01.org.mfa"}},
			{ID: "PO.5.2", Checks: []string{"C01.org.mfa", "C02.repo.protection"}},
			{ID: "PW.7.1", Checks: []string{"C05.sast.detected"}},
		},
	}
	cisa := &CISAMapping{
		Clusters: []CISACluster{
			{ID: "1", SSDFTasks: []string{"PO.5.1", "PO.5.2"}},
			{ID: "4", SSDFTasks: []string{"PW.7.1"}},
			{ID: "3", SSDFTasks: []string{"PS.3.1"}}, // no contributing task -> omitted
		},
	}
	return ssdf, cisa
}

func TestBuildRollup_BasicAggregation(t *testing.T) {
	ssdf, cisa := fixtureMappings()
	results := []model.CheckResult{
		{CheckID: "C01.org.mfa", Status: model.StatusVerifiedPass},
		{CheckID: "C02.repo.protection", Status: model.StatusVerifiedFail},
		{CheckID: "C05.sast.detected", Status: model.StatusSelfAttested},
	}

	rollup := BuildRollup(results, ssdf, cisa)

	taskByID := map[string]model.Status{}
	for _, tr := range rollup.Tasks {
		taskByID[tr.TaskID] = tr.Status
	}
	if got := taskByID["PO.5.1"]; got != model.StatusVerifiedPass {
		t.Errorf("PO.5.1 = %q, want verified-pass (only C01.org.mfa contributes)", got)
	}
	if got := taskByID["PO.5.2"]; got != model.StatusVerifiedFail {
		t.Errorf("PO.5.2 = %q, want verified-fail (C01 pass + C02 fail -> fail dominates)", got)
	}
	if got := taskByID["PW.7.1"]; got != model.StatusSelfAttested {
		t.Errorf("PW.7.1 = %q, want self-attested", got)
	}

	clusterByID := map[string]model.Status{}
	for _, cr := range rollup.Clusters {
		clusterByID[cr.ClusterID] = cr.Status
	}
	if got := clusterByID["1"]; got != model.StatusVerifiedFail {
		t.Errorf("cluster 1 = %q, want verified-fail (PO.5.1 pass + PO.5.2 fail -> fail dominates)", got)
	}
	if got := clusterByID["4"]; got != model.StatusSelfAttested {
		t.Errorf("cluster 4 = %q, want self-attested", got)
	}
	if _, ok := clusterByID["3"]; ok {
		t.Error("cluster 3 present in rollup, want omitted (no contributing task)")
	}
}

func TestBuildRollup_MultipleResultsForSameCheckAreReduced(t *testing.T) {
	ssdf, cisa := fixtureMappings()
	// Two results for C01.org.mfa (e.g. one per repo in a hypothetical
	// per-repo check) — one pass, one fail — must reduce via Rollup, not
	// let the last one silently win.
	results := []model.CheckResult{
		{CheckID: "C01.org.mfa", Status: model.StatusVerifiedPass},
		{CheckID: "C01.org.mfa", Status: model.StatusVerifiedFail},
	}

	rollup := BuildRollup(results, ssdf, cisa)
	for _, tr := range rollup.Tasks {
		if tr.TaskID == "PO.5.1" && tr.Status != model.StatusVerifiedFail {
			t.Errorf("PO.5.1 = %q, want verified-fail (reduced across both C01.org.mfa results)", tr.Status)
		}
	}
}

func TestBuildRollup_EmptyResultsOmitsEverything(t *testing.T) {
	ssdf, cisa := fixtureMappings()
	rollup := BuildRollup(nil, ssdf, cisa)

	if len(rollup.Tasks) != 0 {
		t.Errorf("len(Tasks) = %d, want 0", len(rollup.Tasks))
	}
	if len(rollup.Clusters) != 0 {
		t.Errorf("len(Clusters) = %d, want 0", len(rollup.Clusters))
	}
	if rollup.Tasks == nil {
		t.Error("Tasks is nil, want a non-nil empty slice (schema requires type: array)")
	}
	if rollup.Clusters == nil {
		t.Error("Clusters is nil, want a non-nil empty slice (schema requires type: array)")
	}
}

func TestBuildRollup_RealMappingFilesProduceSortedDeterministicOutput(t *testing.T) {
	ssdf, err := LoadSSDF("../../mappings/ssdf-800-218.yaml")
	if err != nil {
		t.Fatalf("LoadSSDF: %v", err)
	}
	cisa, err := LoadCISA("../../mappings/cisa-ssda-form.yaml", ssdf)
	if err != nil {
		t.Fatalf("LoadCISA: %v", err)
	}

	// No real check IDs exist in the mapping files yet (no collectors
	// landed), so this is a smoke test proving BuildRollup doesn't panic
	// or error against the real files — same honest-emptiness pattern as
	// #8's checks list smoke test.
	rollup := BuildRollup(nil, ssdf, cisa)
	if len(rollup.Tasks) != 0 || len(rollup.Clusters) != 0 {
		t.Errorf("rollup = %+v, want empty (no check IDs registered anywhere yet)", rollup)
	}
}
