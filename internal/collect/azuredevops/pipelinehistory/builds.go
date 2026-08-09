package pipelinehistory

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gitlab.com/sioakeim/attestward/internal/collect/azuredevops"
)

// repositoryTypeTfsGit is the only Builds - List `repositoryType` value
// this project needs: Azure Repos Git. Every other repository type
// (TFVC, GitHub, Bitbucket, ...) is out of scope — issue #34's non-goals
// scope this tool to Azure Repos-hosted YAML pipelines only.
const repositoryTypeTfsGit = "TfsGit"

// buildRaw is the subset of Azure DevOps's Build shape (Builds - List)
// FetchBuilds needs.
type buildRaw struct {
	SourceVersion string    `json:"sourceVersion"`
	SourceBranch  string    `json:"sourceBranch"`
	Result        string    `json:"result"`
	QueueTime     time.Time `json:"queueTime"`
}

// FetchBuilds lists every build for repositoryID queued at or after since,
// via GET .../build/builds?repositoryId=...&repositoryType=TfsGit&minTime=...
// — the since bound is pushed down server-side (minTime) the same way
// runhistory.FetchWorkflowRuns pushes its own bound down via the `created`
// filter, to keep the rate-limit budget bounded.
//
// Unlike FetchWorkflowRuns (one workflow ID per call, since GitHub's
// equivalent endpoint is workflow-scoped), FetchBuilds accepts an optional
// definitionIDs list and fetches every matching pipeline's builds in a
// SINGLE call — Builds List's own `definitions` parameter accepts a
// comma-delimited list of definition IDs natively, a real capability
// GitHub's per-workflow-runs endpoint has no equivalent of, so exploiting
// it here avoids an otherwise-needless per-pipeline call loop. An empty/nil
// definitionIDs fetches every build in the project matching
// repositoryId+repositoryType+minTime, unfiltered by definition.
//
// There is deliberately no sourceVersion parameter here: Builds List has
// no server-side sourceVersion filter at all (verified against the full
// documented parameter list — definitions, queues, buildNumber, minTime,
// maxTime, requestedFor, reasonFilter, statusFilter, resultFilter,
// tagFilters, properties, deletedFilter, queryOrder, branchName, buildIds,
// repositoryId, repositoryType; no sourceVersion among them). Matching a
// build to a specific release's commit is therefore necessarily
// client-side — see LinkRunsToReleases, which is exactly that client-side
// match.
//
// queryOrder is set explicitly to queueTimeDescending: minTime's own doc
// comment says it filters "based on the queryOrder specified" — i.e.
// which timestamp (finish/start/queue) minTime binds against depends on
// this parameter, and the server's default ordering (unspecified) binds
// on finish time, not queue time. Without pinning queueTimeDescending
// here, minTime would silently filter out any build that hasn't finished
// yet (still queued or in progress, no finishTime set), making
// LinkRunsToReleases' still-running-build path (an empty Result) actually
// unreachable against a real service despite being a real, documented
// BuildResult/BuildStatus state.
func FetchBuilds(ctx context.Context, client *azuredevops.Client, project, repositoryID string, definitionIDs []int, since time.Time) ([]RunInfo, error) {
	path := fmt.Sprintf("/%s/%s/_apis/build/builds", client.Org(), project)
	query := url.Values{
		"repositoryId":   {repositoryID},
		"repositoryType": {repositoryTypeTfsGit},
		"minTime":        {since.UTC().Format(time.RFC3339)},
		"queryOrder":     {"queueTimeDescending"},
		"api-version":    {"7.1"},
	}
	if len(definitionIDs) > 0 {
		ids := make([]string, len(definitionIDs))
		for i, id := range definitionIDs {
			ids[i] = strconv.Itoa(id)
		}
		query.Set("definitions", strings.Join(ids, ","))
	}

	var raw []buildRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return nil, err
	}

	runs := make([]RunInfo, len(raw))
	for i, b := range raw {
		// buildRaw and RunInfo share identical field names/types/order —
		// a direct conversion, not a field-by-field copy.
		runs[i] = RunInfo(b)
	}
	return runs, nil
}
