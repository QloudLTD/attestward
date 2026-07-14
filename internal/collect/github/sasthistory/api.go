package sasthistory

import (
	"context"
	"strings"
	"time"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/mapping"
)

// codeQLDefaultSetupPathPrefix is the synthetic workflow path GitHub's API
// reports for a repo's CodeQL "default setup" scanning configuration
// (Settings > Code security > Code scanning > Set up > Default), when it's
// enabled: ListWorkflows includes a virtual entry at this path even though
// no such file exists in the repo. Fetching its content 404s — it isn't a
// real file — so it must be special-cased rather than run through the
// normal content-fetch-then-match path.
const codeQLDefaultSetupPathPrefix = "dynamic/github-code-scanning/"

// codeQLSignatureID is the scanner-signatures.yaml entry this collector
// attributes default-setup's synthetic match to, so its tool name in
// checkToolConfigured's Facts matches the name a real codeql-action-based
// workflow would report.
const codeQLSignatureID = "codeql"

// matchedWorkflow pairs one workflow file with the SAST-category
// signatures it matched (non-SAST matches, e.g. an SCA tool sharing the
// same workflow, are dropped — this collector only cares about SAST).
type matchedWorkflow struct {
	WorkflowID int64
	Path       string
	Matches    []mapping.ScannerMatch
}

// fetchAndMatchWorkflows lists every workflow file, fetches each one's
// content on the default branch, and runs it through the #16 matcher.
// An individual workflow whose content can't be fetched or parsed is
// skipped rather than failing the whole repo — a listed-but-unreadable
// workflow file is an edge case (e.g. deleted after being disabled) this
// collector shouldn't treat as a hard error. Only the top-level list call
// failing is a real error, propagated to the caller.
func fetchAndMatchWorkflows(ctx context.Context, client *ghcollect.Client, registry *mapping.ScannerSignatureRegistry, org, repo, defaultBranch string) ([]matchedWorkflow, *ghgithub.Response, error) {
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

	var matched []matchedWorkflow
	for _, wf := range all {
		if strings.HasPrefix(wf.GetPath(), codeQLDefaultSetupPathPrefix) {
			// A virtual workflow, not a real file — GetContents would
			// 404. GitHub itself is the source of this entry, so it's
			// treated as a direct (high-confidence) match without going
			// through the normal content-fetch-and-parse path.
			if sig, ok := registry.SignatureByID[codeQLSignatureID]; ok {
				matched = append(matched, matchedWorkflow{
					WorkflowID: wf.GetID(),
					Path:       wf.GetPath(),
					Matches: []mapping.ScannerMatch{{
						SignatureID: sig.ID,
						Name:        sig.Name,
						Category:    mapping.CategorySAST,
						Confidence:  mapping.ConfidenceHigh,
						MatchedOn:   "codeql-default-setup",
					}},
				})
			}
			continue
		}

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

		var sastMatches []mapping.ScannerMatch
		for _, m := range registry.MatchWorkflow(parsed) {
			if m.Category == mapping.CategorySAST {
				sastMatches = append(sastMatches, m)
			}
		}
		if len(sastMatches) > 0 {
			matched = append(matched, matchedWorkflow{WorkflowID: wf.GetID(), Path: wf.GetPath(), Matches: sastMatches})
		}
	}
	return matched, nil, nil
}

// fetchReleases lists every release (all pages) — filtering to the
// lookback window happens afterward via filterReleasesInLookback, once
// tags are resolved to commits, since ListReleases itself has no
// server-side date filter to push that work down to (v75's
// ListReleases takes a plain *ListOptions).
func fetchReleases(ctx context.Context, client *ghcollect.Client, org, repo string) ([]*ghgithub.RepositoryRelease, *ghgithub.Response, error) {
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

// resolveReleaseCommit resolves a release's tag to the commit SHA it
// actually points at. A lightweight tag's ref object is already the
// commit; an annotated tag's ref object is the *tag* object, one more
// level of indirection from the commit it targets — GitHub doesn't tell
// the caller which kind a tag is without fetching the ref first.
func resolveReleaseCommit(ctx context.Context, client *ghcollect.Client, org, repo, tagName string) (string, error) {
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

// fetchWorkflowRuns lists every run of one workflow created at or after
// since — pushed down via the Created filter (a server-side range
// expression, not a client-side post-filter) specifically to keep this
// collector's rate-limit budget bounded: without it, a long-lived
// workflow could have thousands of runs to paginate through when only the
// lookback window's worth are ever used.
func fetchWorkflowRuns(ctx context.Context, client *ghcollect.Client, org, repo string, workflowID int64, since time.Time) ([]*ghgithub.WorkflowRun, error) {
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
