package report

import (
	"testing"

	"github.com/sioakim/attestward/internal/model"
)

func TestAssignFindings_OrdersByClusterThenCheckIDThenRepo(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, _, _ := loadRealMappings(t)

	findings := assignFindings(pack, ssdf, cisa)
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2 (rich-pack.json has one verified-fail and one partial result)", len(findings))
	}
	// Both C02.branch.protection-exists (via PS.1.1) and C08.actions.pinned
	// (via PW.4.1) are cited by the same real CISA cluster ("2"), so their
	// order must fall back to check ID.
	if findings[0].ID != "POAM-001" || findings[0].Result.CheckID != "C02.branch.protection-exists" {
		t.Errorf("findings[0] = %+v, want POAM-001/C02.branch.protection-exists", findings[0])
	}
	if findings[1].ID != "POAM-002" || findings[1].Result.CheckID != "C08.actions.pinned" {
		t.Errorf("findings[1] = %+v, want POAM-002/C08.actions.pinned", findings[1])
	}
	if findings[0].PrimaryClusterID != findings[1].PrimaryClusterID {
		t.Errorf("expected both findings to share a primary cluster (both PS.1.1 and PW.4.1 are cited by CISA cluster 2), got %q and %q", findings[0].PrimaryClusterID, findings[1].PrimaryClusterID)
	}
}

func TestAssignFindings_ExcludesNonGapStatuses(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, _, _ := loadRealMappings(t)

	findings := assignFindings(pack, ssdf, cisa)
	for _, f := range findings {
		if f.Result.Status != model.StatusVerifiedFail && f.Result.Status != model.StatusPartial {
			t.Errorf("assignFindings returned a %s result (%s) — only verified-fail/partial belong in a POA&M", f.Result.Status, f.Result.CheckID)
		}
	}
}

func TestAssignFindings_UnmappedSortsLast(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, _, _ := loadRealMappings(t)

	// C00.unmapped.check isn't cited by any real SSDF task, so it can
	// never resolve to a cluster. Deliberately named to sort FIRST
	// lexically among check IDs (C00 < C02 < C08) — if the cluster-group
	// comparison in assignFindings' sort were ever dropped, falling back
	// to check-ID-only ordering would put this finding first, not last;
	// the fixture rich-pack.json's own two findings share a cluster (so
	// a check-ID-only sort silently produces the same order for them),
	// so this is the only case in this test file that actually exercises
	// the cluster-group comparison rather than being satisfied by chance.
	pack.Results = append(pack.Results, model.CheckResult{
		CheckID: "C00.unmapped.check", Title: "Unmapped", Status: model.StatusVerifiedFail,
		Reason: "test-only unmapped finding", Scope: model.ScopeRef{Org: pack.Scope.Org},
		Provenance: []model.Provenance{},
	})

	findings := assignFindings(pack, ssdf, cisa)
	last := findings[len(findings)-1]
	if last.Result.CheckID != "C00.unmapped.check" {
		t.Errorf("last finding = %s, want the unmapped check sorted after every clustered finding", last.Result.CheckID)
	}
	if last.PrimaryClusterID != "" {
		t.Errorf("unmapped finding's PrimaryClusterID = %q, want empty", last.PrimaryClusterID)
	}
	if len(last.ClusterIDs) != 0 {
		t.Errorf("unmapped finding's ClusterIDs = %v, want empty", last.ClusterIDs)
	}
}

func TestAssignFindings_NilMappingsAllUnmappedNoPanic(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")

	findings := assignFindings(pack, nil, nil)
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}
	for _, f := range findings {
		if f.PrimaryClusterID != "" {
			t.Errorf("%s: PrimaryClusterID = %q with nil mappings, want empty", f.Result.CheckID, f.PrimaryClusterID)
		}
	}
	// With no cluster to sort by, every finding falls into the same
	// "unmapped" bucket, so order degrades to check ID/repo — still
	// deterministic, just not cluster-grouped.
	if findings[0].Result.CheckID != "C02.branch.protection-exists" || findings[1].Result.CheckID != "C08.actions.pinned" {
		t.Errorf("unexpected order with nil mappings: %s, %s", findings[0].Result.CheckID, findings[1].Result.CheckID)
	}
}

func TestAssignFindings_Deterministic(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, _, _ := loadRealMappings(t)

	first := assignFindings(pack, ssdf, cisa)
	second := assignFindings(pack, ssdf, cisa)
	if len(first) != len(second) {
		t.Fatalf("len(first) = %d, len(second) = %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID || first[i].Result.CheckID != second[i].Result.CheckID {
			t.Errorf("finding %d differs between calls: %+v vs %+v", i, first[i], second[i])
		}
	}
}
