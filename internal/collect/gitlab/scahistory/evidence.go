package scahistory

import (
	"context"
	"sort"
	"time"

	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
)

// reportTypeDependencyScanning is GitLab's report_type value for a
// dependency finding. A project's vulnerability listing mixes SAST, secret
// detection and dependency scanning in one response (confirmed against the
// recorded fixture, which carries all three), and C06 must judge only its own
// — counting a SAST finding here would report the same finding twice across
// two checks and make C06's verdict depend on C05's subject.
const reportTypeDependencyScanning = "dependency_scanning"

// dependencyRaw is one entry of GET /projects/:id/dependencies. Only the file
// path is read: the comparison this feeds is on paths, so the package
// manager, version and advisory list are all beside the point — see
// checkManifestCoverage.
type dependencyRaw struct {
	DependencyFilePath string `json:"dependency_file_path"`
}

// fetchScannedDependencyFiles returns the distinct dependency files GitLab
// reported dependencies from.
//
// ⚠ Ultimate-tier: this endpoint answers 403 on a Free project (measured,
// docs/gitlab-security-apis.md §1). The error is returned rather than
// swallowed precisely so the caller reports not-checkable — an empty slice
// here would be indistinguishable from an entitled project with nothing to
// report, which is the false pass this package exists to avoid.
func fetchScannedDependencyFiles(ctx context.Context, client *gitlabcollect.Client, projID string) ([]string, error) {
	raw, err := gitlabcollect.GetJSONPaged[dependencyRaw](ctx, client, "/projects/"+projID+"/dependencies", nil)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range raw {
		if d.DependencyFilePath == "" || seen[d.DependencyFilePath] {
			continue
		}
		seen[d.DependencyFilePath] = true
		out = append(out, d.DependencyFilePath)
	}
	// Sorted because the pack is meant to be comparable between scans and
	// this lands in Facts; the API's own order is not guaranteed stable.
	sort.Strings(out)
	return out, nil
}

// vulnerability is one entry of GET /projects/:id/vulnerabilities, reduced to
// what the triage check reads.
//
// ⚠ CreatedAt is when GitLab first recorded the finding, and it is the age
// this check measures. The response also carries dismissed_at / resolved_at /
// confirmed_at, none of which are read: a finding that is still open has none
// of them set, and one that has them set is not open, so State already
// answers that question — reading a timestamp to re-derive it would be a
// second, disagreeing source of truth.
//
// ⚠ Severity casing differs across three surfaces of the same product
// (docs/gitlab-security-apis.md §4): "Critical" in a raw scanner report,
// "CRITICAL" in GraphQL, "critical" here. Comparison is case-insensitive
// rather than pinned to the one casing this endpoint happens to use.
type vulnerability struct {
	Title      string    `json:"title"`
	State      string    `json:"state"`
	Severity   string    `json:"severity"`
	ReportType string    `json:"report_type"`
	CreatedAt  time.Time `json:"created_at"`
}

// fetchVulnerabilities lists the project's vulnerability records.
//
// ⚠ Ultimate-tier, same as fetchScannedDependencyFiles: 403 on Free, and the
// error is returned rather than swallowed for the same reason.
func fetchVulnerabilities(ctx context.Context, client *gitlabcollect.Client, projID string) ([]vulnerability, error) {
	return gitlabcollect.GetJSONPaged[vulnerability](ctx, client, "/projects/"+projID+"/vulnerabilities", nil)
}
