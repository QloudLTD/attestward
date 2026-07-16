package actionssecurity

import (
	"context"
	"net/http"
	"sort"
	"strings"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/collect/github/runhistory"
	"github.com/sioakim/ssdf/internal/mapping"
)

// skippedWorkflow is a listed or referenced workflow this collector
// could not turn into a workflowUnit for a reason other than a benign
// "doesn't exist at this ref" 404 — see fetchOneWorkflow's doc comment
// for why that distinction matters. Every check function receives this
// list so it can avoid asserting a confident verified-pass ("no
// violation found") when the evidence it searched was known-incomplete.
type skippedWorkflow struct {
	Path   string
	Reason string
}

const (
	skipReasonFetchOrParseFailed = "content fetch, decode, or YAML parse failed"
	skipReasonResolutionCapped   = "same-org reusable workflow reference exceeded the resolution cap"
	// skipReasonReusableNotFoundOrNoAccess is deliberately NOT split into
	// separate "doesn't exist" and "no access" reasons: GitHub returns an
	// identical 404 for both on a private repo (to avoid leaking whether
	// it exists), and unlike fetchWorkflows' direct-listing path — where
	// ListWorkflows already proved this token can read THIS SAME repo —
	// resolveReusableWorkflows has no prior proof of access to the
	// callee repo a reusable-workflow reference points at. A 404 here
	// therefore can't be trusted as a benign absence the way it can on
	// the direct path; see resolveReusableWorkflows' own doc comment.
	skipReasonReusableNotFoundOrNoAccess = "not found at ref, or token lacks access to the callee repository"
)

func skippedToFacts(skipped []skippedWorkflow) []map[string]any {
	out := make([]map[string]any, 0, len(skipped))
	for _, s := range skipped {
		out = append(out, map[string]any{"path": s.Path, "reason": s.Reason})
	}
	return out
}

// workflowUnit is one workflow file's content, already fetched and parsed,
// plus its raw text so check functions can attach best-effort file+line
// facts to findings. Label is what a Facts entry shows for this file: the
// bare path for a workflow fetched directly from the scanned repo, or
// "owner/repo:path" for one resolved from elsewhere via
// resolveReusableWorkflows — see that function's doc comment.
//
// Raw is exposed rather than a pre-built *lineFinder deliberately: a
// lineFinder's "consumed" state must stay scoped to a single check
// function's own pass over this unit (see lineFinder's doc comment) — all
// five checks share the same []workflowUnit slice (collectRepo builds it
// once), so a finder attached here and reused across checks would let one
// check's line lookups silently "consume" the occurrences a later,
// unrelated check searches for next, even though nothing about the two
// checks' findings has anything to do with each other. Each check
// constructs its own newLineFinder(u.Raw) where it needs one.
type workflowUnit struct {
	Label  string
	Parsed mapping.WorkflowFile
	Raw    string
}

// fetchWorkflows fetches and parses every workflow file GitHub lists for
// org/repo on its default branch. A workflow whose content 404s at this
// ref is skipped silently — a real, expected absence (e.g. a file GitHub
// still lists from historical runs but that no longer exists on the
// current default branch), not evidence loss. Any other failure (a
// genuine fetch error, a content-decode failure, or a YAML-parse
// failure) is also skipped from units, but recorded in the returned
// skippedWorkflow list — see checkPinned and its siblings for why that
// distinction matters to their pass/fail logic.
func fetchWorkflows(ctx context.Context, client *ghcollect.Client, org, repo, defaultBranch string) ([]workflowUnit, []skippedWorkflow, *ghgithub.Response, error) {
	listed, resp, err := runhistory.ListWorkflows(ctx, client, org, repo)
	if err != nil {
		return nil, nil, resp, err
	}
	var out []workflowUnit
	var skipped []skippedWorkflow
	for _, wf := range listed {
		path := wf.GetPath()
		unit, ok, notFoundAtRef := fetchOneWorkflow(ctx, client, org, repo, path, defaultBranch)
		if !ok {
			if !notFoundAtRef {
				skipped = append(skipped, skippedWorkflow{Path: path, Reason: skipReasonFetchOrParseFailed})
			}
			continue
		}
		unit.Label = path
		out = append(out, unit)
	}
	return out, skipped, nil, nil
}

// fetchOneWorkflow fetches and parses one workflow file. notFoundAtRef
// is true only when GetContents itself returned 404 — the benign "this
// file doesn't exist at this ref" case — so callers can distinguish it
// from every other failure mode (permission denied, rate limiting, a
// transient error, a content-decode failure, a YAML-parse failure),
// which represents real evidence this collector failed to read, not a
// confirmed absence.
func fetchOneWorkflow(ctx context.Context, client *ghcollect.Client, org, repo, path, ref string) (unit workflowUnit, ok bool, notFoundAtRef bool) {
	content, _, resp, err := client.REST.Repositories.GetContents(ctx, org, repo, path, &ghgithub.RepositoryContentGetOptions{Ref: ref})
	if err != nil || content == nil {
		return workflowUnit{}, false, resp != nil && resp.StatusCode == http.StatusNotFound
	}
	raw, err := content.GetContent()
	if err != nil {
		return workflowUnit{}, false, false
	}
	parsed, err := mapping.ParseWorkflowFile([]byte(raw))
	if err != nil {
		return workflowUnit{}, false, false
	}
	return workflowUnit{Parsed: parsed, Raw: raw}, true, false
}

// maxReusableWorkflowResolutions bounds how many cross-repo reusable
// workflows a single scanned repo will resolve, so one workflow file
// can't fan this collector out into an unbounded number of extra API
// calls — 10 is generously above any real-world reusable-workflow fan-out
// seen in practice, matching the spirit of provenance's per-release
// attestation-lookup cap.
const maxReusableWorkflowResolutions = 10

// unresolvedExternalWorkflow is one job-level `uses:` reference to a
// reusable workflow this collector deliberately did not fetch, because
// its owner isn't the org being scanned — see resolveReusableWorkflows'
// doc comment for why only same-org reusable workflows are resolved.
type unresolvedExternalWorkflow struct {
	FromFile string
	Line     int
	Ref      string
}

// resolveReusableWorkflows finds every job-level reusable-workflow
// reference (`jobs.<id>.uses: owner/repo/.github/workflows/file.yml@ref`)
// across units and fetches the ones whose owner is org — the same trust
// boundary this collector is already scanning, per issue #20's "referenced
// reusable workflows within scanned scope get analyzed" — up to
// maxReusableWorkflowResolutions total, regardless of whether that
// specific repo is itself one of the repos passed to this scan (a
// same-org reusable-workflow repo, e.g. "org/.github", is commonly not a
// scan target in its own right). A reusable workflow can itself call other
// reusable workflows, but this resolves only one level deep: deliberately
// not recursive, to keep the call count bounded and predictable rather
// than depending on how deeply another team's workflows happen to be
// nested. References to a different owner are recorded as unresolved, not
// fetched — resolving arbitrary external repos' content is outside this
// collector's read scope for the org being scanned.
// A reference dropped by maxReusableWorkflowResolutions, or one whose
// fetch/parse genuinely failed (not a benign 404-at-ref), is recorded
// in the returned skippedWorkflow list rather than silently vanishing —
// see fetchWorkflows' identical distinction for why.
func resolveReusableWorkflows(ctx context.Context, client *ghcollect.Client, org string, units []workflowUnit) (resolved []workflowUnit, unresolved []unresolvedExternalWorkflow, skipped []skippedWorkflow) {
	seen := map[string]bool{}
	for _, u := range units {
		seen[u.Label] = true
	}
	for _, u := range units {
		finder := newLineFinder(u.Raw)
		for _, jobName := range sortedJobNames(u.Parsed.Jobs) {
			job := u.Parsed.Jobs[jobName]
			if job.Uses == "" || !looksLikeReusableWorkflowRef(job.Uses) {
				continue
			}
			owner, repo, path, ref := splitReusableWorkflowRef(job.Uses)
			if owner != org {
				unresolved = append(unresolved, unresolvedExternalWorkflow{FromFile: u.Label, Line: finder.Find(job.Uses), Ref: job.Uses})
				continue
			}
			label := owner + "/" + repo + ":" + path
			if seen[label] {
				continue
			}
			seen[label] = true
			if len(resolved) >= maxReusableWorkflowResolutions {
				skipped = append(skipped, skippedWorkflow{Path: label, Reason: skipReasonResolutionCapped})
				continue
			}
			// Unlike fetchWorkflows, a 404 here is NOT trusted as a
			// benign absence — see skipReasonReusableNotFoundOrNoAccess's
			// doc comment for why this repo has no prior proof of access
			// the way the scanned repo itself does.
			unit, ok, _ := fetchOneWorkflow(ctx, client, owner, repo, path, ref)
			if !ok {
				skipped = append(skipped, skippedWorkflow{Path: label, Reason: skipReasonReusableNotFoundOrNoAccess})
				continue
			}
			unit.Label = label
			resolved = append(resolved, unit)
		}
	}
	return resolved, unresolved, skipped
}

// looksLikeReusableWorkflowRef reports whether uses looks like a
// reusable-workflow call rather than an action reference — GitHub
// requires the path component to be exactly ".github/workflows/<file>",
// which never appears in an action's own uses: path.
func looksLikeReusableWorkflowRef(uses string) bool {
	return strings.Contains(uses, "/.github/workflows/")
}

// splitReusableWorkflowRef splits "owner/repo/.github/workflows/file.yml@ref"
// into its parts. Malformed input (already filtered by
// looksLikeReusableWorkflowRef, but defensively handled here too) yields
// empty owner/repo/path, which resolveReusableWorkflows' "owner != org"
// check naturally treats as unresolved rather than as the scanned org's own.
func splitReusableWorkflowRef(uses string) (owner, repo, path, ref string) {
	slug, r, _ := strings.Cut(uses, "@")
	ref = r
	parts := strings.SplitN(slug, "/", 3)
	if len(parts) != 3 {
		return "", "", "", ref
	}
	return parts[0], parts[1], parts[2], ref
}

func sortedJobNames(jobs map[string]mapping.WorkflowJob) []string {
	names := make([]string, 0, len(jobs))
	for name := range jobs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
