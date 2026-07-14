package actionssecurity

import (
	"context"
	"sort"
	"strings"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
	"github.com/sioakim/ssdf/internal/collect/github/runhistory"
	"github.com/sioakim/ssdf/internal/mapping"
)

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
// org/repo on its default branch. A workflow whose content can't be
// fetched or parsed is skipped, not a hard error — matches
// runhistory.MatchWorkflows' same "an unreadable listed file is an edge
// case" reasoning.
func fetchWorkflows(ctx context.Context, client *ghcollect.Client, org, repo, defaultBranch string) ([]workflowUnit, *ghgithub.Response, error) {
	listed, resp, err := runhistory.ListWorkflows(ctx, client, org, repo)
	if err != nil {
		return nil, resp, err
	}
	var out []workflowUnit
	for _, wf := range listed {
		path := wf.GetPath()
		unit, ok := fetchOneWorkflow(ctx, client, org, repo, path, defaultBranch)
		if !ok {
			continue
		}
		unit.Label = path
		out = append(out, unit)
	}
	return out, nil, nil
}

func fetchOneWorkflow(ctx context.Context, client *ghcollect.Client, org, repo, path, ref string) (workflowUnit, bool) {
	content, _, _, err := client.REST.Repositories.GetContents(ctx, org, repo, path, &ghgithub.RepositoryContentGetOptions{Ref: ref})
	if err != nil || content == nil {
		return workflowUnit{}, false
	}
	raw, err := content.GetContent()
	if err != nil {
		return workflowUnit{}, false
	}
	parsed, err := mapping.ParseWorkflowFile([]byte(raw))
	if err != nil {
		return workflowUnit{}, false
	}
	return workflowUnit{Parsed: parsed, Raw: raw}, true
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
func resolveReusableWorkflows(ctx context.Context, client *ghcollect.Client, org string, units []workflowUnit) (resolved []workflowUnit, unresolved []unresolvedExternalWorkflow) {
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
			if seen[label] || len(resolved) >= maxReusableWorkflowResolutions {
				continue
			}
			seen[label] = true
			unit, ok := fetchOneWorkflow(ctx, client, owner, repo, path, ref)
			if !ok {
				continue
			}
			unit.Label = label
			resolved = append(resolved, unit)
		}
	}
	return resolved, unresolved
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
