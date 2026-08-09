package report

import (
	"fmt"
	"sort"

	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
)

// Finding is one verified-fail/partial CheckResult assigned a stable POA&M
// ID and enriched with the SSDF tasks/CISA clusters it affects. Both
// report.md's Gaps table and poam.md's finding entries are built from the
// identical assignFindings call, so a finding's ID always agrees between
// the two documents for the same pack (issue #26's "cross-links: report
// gap list <-> POA&M finding IDs" requirement) — this is the whole reason
// poam.md's renderer lives in this package rather than a separate one.
type Finding struct {
	// ID is "POAM-001", "POAM-002", ... assigned in cluster -> check ID ->
	// repo order (issue #26's own ordering requirement).
	ID     string
	Result model.CheckResult
	// TaskIDs is every SSDF task citing Result.CheckID, sorted.
	TaskIDs []string
	// ClusterIDs is every CISA cluster whose SSDFTasks includes one of
	// TaskIDs, in cisa.Clusters' own file order (not lexically sorted —
	// the form's cluster IDs are small integers today, but ordering by
	// the mapping file's own declared order is the more robust contract).
	ClusterIDs []string
	// PrimaryClusterID is ClusterIDs[0] (empty if a finding maps to no
	// cluster at all — e.g. ssdf/cisa weren't loaded, or a check's
	// mapping citation is genuinely incomplete). Used only for grouping
	// findings into sections; a finding's own detail still lists every
	// affected cluster in ClusterIDs, not just the primary one.
	PrimaryClusterID string
}

// assignFindings extracts every verified-fail/partial result from
// pack.Results and assigns each a stable POA&M finding ID. ssdf/cisa may
// be nil (degrades to every finding in the "unmapped" bucket, sorted only
// by check ID/repo) — matching this package's established nil-tolerant
// contract for mapping data.
func assignFindings(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping) []Finding {
	tasksByCheck := map[string][]string{}
	if ssdf != nil {
		for _, task := range ssdf.Tasks {
			for _, checkID := range task.Checks {
				tasksByCheck[checkID] = append(tasksByCheck[checkID], task.ID)
			}
		}
	}
	clustersByTask := map[string][]string{}
	clusterOrder := map[string]int{}
	if cisa != nil {
		for i, cluster := range cisa.Clusters {
			clusterOrder[cluster.ID] = i
			for _, taskID := range cluster.SSDFTasks {
				clustersByTask[taskID] = append(clustersByTask[taskID], cluster.ID)
			}
		}
	}

	var findings []Finding
	for _, r := range pack.Results {
		if r.Status != model.StatusVerifiedFail && r.Status != model.StatusPartial {
			continue
		}
		f := Finding{Result: r, TaskIDs: append([]string{}, tasksByCheck[r.CheckID]...)}
		sort.Strings(f.TaskIDs)

		clusterSet := map[string]bool{}
		for _, taskID := range f.TaskIDs {
			for _, clusterID := range clustersByTask[taskID] {
				clusterSet[clusterID] = true
			}
		}
		for clusterID := range clusterSet {
			f.ClusterIDs = append(f.ClusterIDs, clusterID)
		}
		sort.Slice(f.ClusterIDs, func(i, j int) bool {
			return clusterOrder[f.ClusterIDs[i]] < clusterOrder[f.ClusterIDs[j]]
		})
		if len(f.ClusterIDs) > 0 {
			f.PrimaryClusterID = f.ClusterIDs[0]
		}
		findings = append(findings, f)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		oi, oj := findingGroupOrder(findings[i], clusterOrder), findingGroupOrder(findings[j], clusterOrder)
		if oi != oj {
			return oi < oj
		}
		if findings[i].Result.CheckID != findings[j].Result.CheckID {
			return findings[i].Result.CheckID < findings[j].Result.CheckID
		}
		return findings[i].Result.Scope.Repo < findings[j].Result.Scope.Repo
	})

	for i := range findings {
		findings[i].ID = fmt.Sprintf("POAM-%03d", i+1)
	}
	return findings
}

// findingGroupOrder sorts a finding by its primary cluster's position in
// the mapping file; a finding with no cluster affiliation at all
// (PrimaryClusterID == "", which no real CISA cluster ID ever is) sorts
// after every real cluster rather than first, so the "Unmapped" section
// reads as a trailing catch-all, not an implicit top priority.
func findingGroupOrder(f Finding, clusterOrder map[string]int) int {
	if f.PrimaryClusterID == "" {
		return len(clusterOrder)
	}
	return clusterOrder[f.PrimaryClusterID]
}
