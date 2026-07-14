package runhistory

import (
	"context"
	"time"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/mapping"
)

// MatchedWorkflow pairs one workflow file with the scanner-signature
// matches it produced, already filtered to a single category.
type MatchedWorkflow struct {
	WorkflowID int64
	Path       string
	Matches    []mapping.ScannerMatch
}

// ListWorkflows lists every workflow file entry for a repo (all pages).
// Exposed separately from MatchWorkflows so a caller needing the raw list
// itself — e.g. C05 special-casing CodeQL's "default setup" virtual
// workflow entry, which has no content to fetch — doesn't have to pay for
// a second listing call just to get at it.
func ListWorkflows(ctx context.Context, client *ghcollect.Client, org, repo string) ([]*ghgithub.Workflow, *ghgithub.Response, error) {
	var all []*ghgithub.Workflow
	opts := &ghgithub.ListOptions{PerPage: 100}
	for {
		resp, httpResp, err := client.REST.Actions.ListWorkflows(ctx, org, repo, opts)
		if err != nil {
			return nil, httpResp, err
		}
		all = append(all, resp.Workflows...)
		if httpResp.NextPage == 0 {
			break
		}
		opts.Page = httpResp.NextPage
	}
	return all, nil, nil
}

// MatchWorkflows fetches each of the given workflows' content on the
// default branch and runs it through the #16 matcher, keeping only
// matches in category. An individual workflow whose content can't be
// fetched or parsed is skipped rather than failing the whole repo — a
// listed-but-unreadable workflow file is an edge case (e.g. deleted after
// being disabled) callers shouldn't treat as a hard error. This function
// has no knowledge of any category-specific virtual workflow entries (e.g.
// CodeQL's "default setup" dynamic workflow) — callers should filter
// those out of workflows themselves (via ListWorkflows) and handle them
// separately, since that's category-specific behavior this shared package
// has no opinion about.
func MatchWorkflows(ctx context.Context, client *ghcollect.Client, registry *mapping.ScannerSignatureRegistry, org, repo, defaultBranch string, workflows []*ghgithub.Workflow, category mapping.ScannerCategory) []MatchedWorkflow {
	var matched []MatchedWorkflow
	for _, wf := range workflows {
		content, _, _, err := client.REST.Repositories.GetContents(ctx, org, repo, wf.GetPath(), &ghgithub.RepositoryContentGetOptions{Ref: defaultBranch})
		if err != nil || content == nil {
			continue
		}
		raw, err := content.GetContent()
		if err != nil {
			continue
		}
		parsed, err := mapping.ParseWorkflowFile([]byte(raw))
		if err != nil {
			continue
		}

		var categoryMatches []mapping.ScannerMatch
		for _, m := range registry.MatchWorkflow(parsed) {
			if m.Category == category {
				categoryMatches = append(categoryMatches, m)
			}
		}
		if len(categoryMatches) > 0 {
			matched = append(matched, MatchedWorkflow{WorkflowID: wf.GetID(), Path: wf.GetPath(), Matches: categoryMatches})
		}
	}
	return matched
}

// FetchReleases lists every release (all pages) — filtering to the
// lookback window happens afterward via FilterReleasesInLookback, once
// tags are resolved to commits, since ListReleases itself has no
// server-side date filter to push that work down to (v75's
// ListReleases takes a plain *ListOptions).
func FetchReleases(ctx context.Context, client *ghcollect.Client, org, repo string) ([]*ghgithub.RepositoryRelease, *ghgithub.Response, error) {
	var all []*ghgithub.RepositoryRelease
	opts := &ghgithub.ListOptions{PerPage: 100}
	for {
		page, resp, err := client.REST.Repositories.ListReleases(ctx, org, repo, opts)
		if err != nil {
			return nil, resp, err
		}
		all = append(all, page...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil, nil
}

// ResolveReleaseCommit resolves a release's tag to the commit SHA it
// actually points at. A lightweight tag's ref object is already the
// commit; an annotated tag's ref object is the *tag* object, one more
// level of indirection from the commit it targets — GitHub doesn't tell
// the caller which kind a tag is without fetching the ref first.
func ResolveReleaseCommit(ctx context.Context, client *ghcollect.Client, org, repo, tagName string) (string, error) {
	ref, _, err := client.REST.Git.GetRef(ctx, org, repo, "tags/"+tagName)
	if err != nil {
		return "", err
	}
	obj := ref.GetObject()
	if obj.GetType() != "tag" {
		return obj.GetSHA(), nil
	}
	tag, _, err := client.REST.Git.GetTag(ctx, org, repo, obj.GetSHA())
	if err != nil {
		return "", err
	}
	return tag.GetObject().GetSHA(), nil
}

// FetchWorkflowRuns lists every run of one workflow created at or after
// since — pushed down via the Created filter (a server-side range
// expression, not a client-side post-filter) specifically to keep the
// caller's rate-limit budget bounded: without it, a long-lived workflow
// could have thousands of runs to paginate through when only the lookback
// window's worth are ever used.
func FetchWorkflowRuns(ctx context.Context, client *ghcollect.Client, org, repo string, workflowID int64, since time.Time) ([]*ghgithub.WorkflowRun, error) {
	var all []*ghgithub.WorkflowRun
	opts := &ghgithub.ListWorkflowRunsOptions{
		Created:     ">=" + since.Format("2006-01-02"),
		ListOptions: ghgithub.ListOptions{PerPage: 100},
	}
	for {
		runs, resp, err := client.REST.Actions.ListWorkflowRunsByID(ctx, org, repo, workflowID, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, runs.WorkflowRuns...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return all, nil
}
