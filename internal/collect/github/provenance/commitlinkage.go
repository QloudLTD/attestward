package provenance

import (
	"context"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
)

// fetchWorkflowRunsForCommit lists every workflow run (across every
// workflow in the repo, not filtered to any scanner category) whose
// HeadSHA equals commitSHA — pushed down server-side via
// ListWorkflowRunsOptions.HeadSHA rather than fetching each workflow's run
// history and filtering client-side, so this is one call per release
// regardless of how many workflows the repo has, and doesn't need
// runhistory's category-matched-workflow machinery at all: commit-linkage
// cares whether ANY workflow run built this release, not specifically a
// provenance-tool run.
func fetchWorkflowRunsForCommit(ctx context.Context, client *ghcollect.Client, org, repo, commitSHA string) ([]*ghgithub.WorkflowRun, *ghgithub.Response, error) {
	var all []*ghgithub.WorkflowRun
	opts := &ghgithub.ListWorkflowRunsOptions{
		HeadSHA:     commitSHA,
		ListOptions: ghgithub.ListOptions{PerPage: 100},
	}
	for {
		runs, resp, err := client.REST.Actions.ListRepositoryWorkflowRuns(ctx, org, repo, opts)
		if err != nil {
			return nil, resp, err
		}
		all = append(all, runs.WorkflowRuns...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil, nil
}
