package mapping

import (
	"sort"
	"strings"
	"testing"
)

func minimalSSDFFixture() *SSDFMapping {
	return &SSDFMapping{
		TaskByID: map[string]SSDFTask{
			"PO.5.1": {ID: "PO.5.1", Family: "PO", Practice: "PO.5", Text: "test"},
		},
	}
}

func TestLoadCISA_RealMappingFileLoadsAndResolves(t *testing.T) {
	ssdf, err := LoadSSDF("../../mappings/ssdf-800-218.yaml")
	if err != nil {
		t.Fatalf("LoadSSDF: %v", err)
	}
	cisa, err := LoadCISA("../../mappings/cisa-ssda-form.yaml", ssdf)
	if err != nil {
		t.Fatalf("LoadCISA(mappings/cisa-ssda-form.yaml) = %v, want no error", err)
	}
	if len(cisa.Clusters) != 4 {
		t.Fatalf("len(Clusters) = %d, want 4 (the form's four attestation clusters)", len(cisa.Clusters))
	}
	for _, id := range []string{"1", "2", "3", "4"} {
		if _, ok := cisa.ClusterByID[id]; !ok {
			t.Errorf("ClusterByID[%q] missing", id)
		}
	}
	for _, cluster := range cisa.Clusters {
		if len(cluster.SSDFTasks) == 0 {
			t.Errorf("cluster %s has no ssdf_tasks", cluster.ID)
		}
	}
}

// TestCluster1TasksAreUnionOfSubElements locks in the derivation documented
// in cluster "1"'s notes field: since CISA's Appendix table gives clause 1
// as "[See rows below]" rather than a direct task list, its top-level
// ssdf_tasks must always equal the union of its sub_elements' ssdf_tasks —
// if a future edit to either drifts out of sync, this should catch it.
func TestCluster1TasksAreUnionOfSubElements(t *testing.T) {
	ssdf, err := LoadSSDF("../../mappings/ssdf-800-218.yaml")
	if err != nil {
		t.Fatalf("LoadSSDF: %v", err)
	}
	cisa, err := LoadCISA("../../mappings/cisa-ssda-form.yaml", ssdf)
	if err != nil {
		t.Fatalf("LoadCISA: %v", err)
	}
	cluster1, ok := cisa.ClusterByID["1"]
	if !ok {
		t.Fatal("cluster \"1\" not found")
	}

	union := map[string]bool{}
	for _, sub := range cluster1.SubElements {
		for _, taskID := range sub.SSDFTasks {
			union[taskID] = true
		}
	}
	got := append([]string{}, cluster1.SSDFTasks...)
	sort.Strings(got)
	want := make([]string, 0, len(union))
	for id := range union {
		want = append(want, id)
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("cluster 1 ssdf_tasks = %v, want union of sub_elements = %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("cluster 1 ssdf_tasks = %v, want union of sub_elements = %v", got, want)
		}
	}
}

func TestLoadCISA_RejectsUnknownSSDFTaskReference(t *testing.T) {
	_, err := LoadCISA("testdata/cisa-bad-unknown-task.yaml", minimalSSDFFixture())
	if err == nil {
		t.Fatal("LoadCISA(cisa-bad-unknown-task.yaml) = nil error, want an unknown-task error")
	}
	if !strings.Contains(err.Error(), "unknown SSDF task") {
		t.Errorf("error = %v, want it to mention 'unknown SSDF task'", err)
	}
}

func TestLoadCISA_RejectsDuplicateClusterID(t *testing.T) {
	_, err := LoadCISA("testdata/cisa-bad-duplicate-cluster.yaml", minimalSSDFFixture())
	if err == nil {
		t.Fatal("LoadCISA(cisa-bad-duplicate-cluster.yaml) = nil error, want a duplicate-id error")
	}
	if !strings.Contains(err.Error(), "duplicate cluster id") {
		t.Errorf("error = %v, want it to mention 'duplicate cluster id'", err)
	}
}
