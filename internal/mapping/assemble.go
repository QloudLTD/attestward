package mapping

import (
	"sort"

	"github.com/sioakim/ssdf/internal/model"
)

// BuildRollup assembles the check -> SSDF task -> CISA form cluster rollup
// (issues #6, #7) from a scan's check results: for each SSDF task, Rollup
// reduces the statuses of every result whose CheckID appears in that task's
// `checks:` list; for each CISA cluster, Rollup reduces the just-computed
// statuses of every task its `ssdf_tasks` list references. A task or
// cluster with no contributing results at all is omitted from the output —
// absence means "nothing in this pack speaks to it," a different, honest
// claim from any of the five Status values (an empty Rollup() call would
// otherwise render it not-checkable, which overclaims that something was
// actually attempted).
//
// Tasks and Clusters are both returned sorted by ID for deterministic
// output (issue #24's writer needs byte-stable packs).
func BuildRollup(results []model.CheckResult, ssdf *SSDFMapping, cisa *CISAMapping) model.Rollup {
	statusByCheck := map[string]model.Status{}
	for _, r := range results {
		// A check ID may appear more than once across results (e.g. one
		// result per repo); reduce them together via the same precedence
		// rather than letting the last one silently win.
		if existing, ok := statusByCheck[r.CheckID]; ok {
			statusByCheck[r.CheckID] = Rollup([]model.Status{existing, r.Status})
		} else {
			statusByCheck[r.CheckID] = r.Status
		}
	}

	taskRollups := make([]model.TaskRollup, 0, len(ssdf.Tasks))
	statusByTask := map[string]model.Status{}
	for _, task := range ssdf.Tasks {
		var statuses []model.Status
		for _, checkID := range task.Checks {
			if s, ok := statusByCheck[checkID]; ok {
				statuses = append(statuses, s)
			}
		}
		if len(statuses) == 0 {
			continue
		}
		status := Rollup(statuses)
		statusByTask[task.ID] = status
		taskRollups = append(taskRollups, model.TaskRollup{TaskID: task.ID, Status: status})
	}
	sort.Slice(taskRollups, func(i, j int) bool { return taskRollups[i].TaskID < taskRollups[j].TaskID })

	clusterRollups := make([]model.ClusterRollup, 0, len(cisa.Clusters))
	for _, cluster := range cisa.Clusters {
		var statuses []model.Status
		for _, taskID := range cluster.SSDFTasks {
			if s, ok := statusByTask[taskID]; ok {
				statuses = append(statuses, s)
			}
		}
		if len(statuses) == 0 {
			continue
		}
		clusterRollups = append(clusterRollups, model.ClusterRollup{ClusterID: cluster.ID, Status: Rollup(statuses)})
	}
	sort.Slice(clusterRollups, func(i, j int) bool { return clusterRollups[i].ClusterID < clusterRollups[j].ClusterID })

	return model.Rollup{Tasks: taskRollups, Clusters: clusterRollups}
}
