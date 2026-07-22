package pipelinehistory

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/sioakim/attestward/internal/collect/azuredevops"
	"github.com/sioakim/attestward/internal/mapping"
)

// branchRefPrefix is the ref-name prefix a BuildRepository's defaultBranch
// (and a Build's own sourceBranch) carries — stripped before it's usable
// as an Items - Get versionDescriptor.version branch name, which the REST
// reference documents as a bare branch name, not a fully-qualified ref.
const branchRefPrefix = "refs/heads/"

// PipelineRef is one pipeline (build definition) listed for a project via
// GET .../_apis/pipelines.
type PipelineRef struct {
	ID   int
	Name string
}

// pipelineRaw is the subset of Azure DevOps's Pipeline shape (Pipelines -
// List) ListPipelines needs.
type pipelineRaw struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// ListPipelines lists every pipeline defined in project via GET
// .../_apis/pipelines — this is the "Pipelines" resource (vso.build
// scope), a lighter-weight list than Build Definitions - List that this
// package uses purely to enumerate IDs; FetchBuildDefinition is then
// called per ID for the fields (process, repository) actually needed.
func ListPipelines(ctx context.Context, client *azuredevops.Client, project string) ([]PipelineRef, error) {
	path := fmt.Sprintf("/%s/%s/_apis/pipelines", client.Org(), project)
	query := url.Values{"api-version": {"7.1"}}

	var raw []pipelineRaw
	if err := azuredevops.GetJSON(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return nil, err
	}

	refs := make([]PipelineRef, len(raw))
	for i, p := range raw {
		// pipelineRaw and PipelineRef share identical field names/types/order.
		refs[i] = PipelineRef(p)
	}
	return refs, nil
}

// YAMLPathStatus is the outcome of trying to determine a build
// definition's YAML pipeline file path from its `process` field — see
// YAMLPathOutcome's doc comment.
type YAMLPathStatus string

const (
	// YAMLPathResolved means process.type read 2 (YAML) and a non-empty
	// yamlFilename was present — YAMLPathOutcome.Path is usable.
	YAMLPathResolved YAMLPathStatus = "resolved"
	// YAMLPathNotYAML means process.type read something other than 2 (most
	// commonly 1, a classic/designer pipeline) — out of scope per issue
	// #34's non-goals (YAML pipelines only), not an evidence gap. A caller
	// should skip this pipeline silently, the same way it would skip a
	// repository type this tool doesn't scan at all.
	YAMLPathNotYAML YAMLPathStatus = "not-yaml"
	// YAMLPathUnknown means process.type read 2 (YAML) but no usable
	// yamlFilename was found — an evidence gap, not an absence: this is
	// exactly the [fixture-verify] case flagged in issue #152/#34.
	// Microsoft's own REST reference for BuildDefinition's `process` field
	// (BuildProcess) documents ONLY a bare {type: int} — verified directly
	// against the Definitions - Get reference page, which lists no other
	// property on BuildProcess at all. The yamlFilename field this package
	// reads is corroborated by Microsoft's own azure-devops-node-api
	// TypeScript SDK (its YamlProcess interface extends BuildProcess with
	// yamlFilename, resources, and errors fields) — a real, Microsoft-
	// maintained source, but not the REST reference itself, so it is
	// treated as fixture-to-verify rather than confirmed: if a real
	// recorded response's shape differs, this case is exactly where that
	// surfaces, as an explicit typed outcome rather than a silently wrong
	// path or a panic.
	YAMLPathUnknown YAMLPathStatus = "unknown"
)

// YAMLPathOutcome is the typed result of trying to determine a build
// definition's YAML pipeline file path — see YAMLPathStatus's doc comment
// for what each status means and why this is a typed outcome rather than
// a plain (string, error): a collector consuming this needs to tell
// "not a YAML pipeline, nothing to do here" (YAMLPathNotYAML) apart from
// "this IS a YAML pipeline but the shape wasn't what was expected"
// (YAMLPathUnknown, an honest not-checkable/partial-worthy gap) — an
// ordinary error return conflates those two very differently-meaningful
// cases into one.
type YAMLPathOutcome struct {
	// Path is the YAML file's repo-relative path (e.g.
	// "azure-pipelines.yml"), set only when Status is YAMLPathResolved.
	Path   string
	Status YAMLPathStatus
	// Reason explains a non-resolved Status in prose, suitable for a
	// collector to fold directly into a not-checkable/partial CheckResult.
	Reason string
}

// buildProcessRaw is the BuildDefinition `process` field's documented
// shape ({type: int}) plus the undocumented (see YAMLPathUnknown)
// yamlFilename field this package reads for the YAML case.
type buildProcessRaw struct {
	Type         int    `json:"type"`
	YAMLFilename string `json:"yamlFilename"`
}

// buildProcessTypeYAML is the documented-elsewhere (not on BuildProcess's
// own REST reference page — see YAMLPathUnknown) discriminator value
// meaning "this definition is a YAML pipeline" — 1 is the classic/designer
// counterpart. Both values are corroborated by the same
// azure-devops-node-api source as yamlFilename itself.
const buildProcessTypeYAML = 2

// buildRepositoryInfoRaw is the subset of BuildDefinition's `repository`
// field this package needs.
type buildRepositoryInfoRaw struct {
	ID            string `json:"id"`
	DefaultBranch string `json:"defaultBranch"`
}

// buildDefinitionRaw is the subset of Azure DevOps's BuildDefinition shape
// (Definitions - Get) FetchBuildDefinition needs.
type buildDefinitionRaw struct {
	ID         int                    `json:"id"`
	Name       string                 `json:"name"`
	Process    buildProcessRaw        `json:"process"`
	Repository buildRepositoryInfoRaw `json:"repository"`
}

// BuildDefinitionInfo is the resolved shape of one build definition this
// package's callers need: which repository it builds, that repository's
// default branch, and whether/where its YAML file could be located.
type BuildDefinitionInfo struct {
	ID            int
	Name          string
	RepositoryID  string
	DefaultBranch string
	YAMLPath      YAMLPathOutcome
}

// FetchBuildDefinition fetches one build definition via GET
// .../build/definitions/{definitionId} and determines its YAML path
// outcome — see YAMLPathStatus's doc comment for exactly how. err is
// returned only for a genuine fetch failure (transport error, non-2xx
// status); an indeterminate or absent YAML path is never an error here,
// only a YAMLPathOutcome the caller inspects.
func FetchBuildDefinition(ctx context.Context, client *azuredevops.Client, project string, definitionID int) (BuildDefinitionInfo, error) {
	path := fmt.Sprintf("/%s/%s/_apis/build/definitions/%d", client.Org(), project, definitionID)
	query := url.Values{"api-version": {"7.1"}}

	var raw buildDefinitionRaw
	if err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostCore, path, query, &raw); err != nil {
		return BuildDefinitionInfo{}, err
	}

	info := BuildDefinitionInfo{
		ID:            raw.ID,
		Name:          raw.Name,
		RepositoryID:  raw.Repository.ID,
		DefaultBranch: raw.Repository.DefaultBranch,
		YAMLPath:      resolveYAMLPath(raw.Process),
	}
	return info, nil
}

func resolveYAMLPath(process buildProcessRaw) YAMLPathOutcome {
	if process.Type != buildProcessTypeYAML {
		return YAMLPathOutcome{
			Status: YAMLPathNotYAML,
			Reason: fmt.Sprintf("process.type read %d, not %d (YAML) — classic/designer pipelines are out of scope", process.Type, buildProcessTypeYAML),
		}
	}
	if process.YAMLFilename == "" {
		return YAMLPathOutcome{
			Status: YAMLPathUnknown,
			Reason: fmt.Sprintf("process.type read %d (YAML) but no yamlFilename field was present in the response — see YAMLPathUnknown's doc comment", buildProcessTypeYAML),
		}
	}
	return YAMLPathOutcome{Status: YAMLPathResolved, Path: process.YAMLFilename}
}

// gitItemRaw is the subset of Azure DevOps's GitItem shape (Items - Get)
// FetchYAMLContent needs.
type gitItemRaw struct {
	Content string `json:"content"`
}

// FetchYAMLContent fetches the raw YAML text at path on branch (a
// fully-qualified ref, e.g. "refs/heads/main" — a BuildRepository's own
// defaultBranch, or a Build's sourceBranch; the refs/heads/ prefix is
// stripped before use, since versionDescriptor.version is documented as a
// bare branch/tag name) in repositoryID, via GET
// .../git/repositories/{repositoryId}/items?path=...&includeContent=true&
// versionDescriptor.version=...&versionDescriptor.versionType=branch.
//
// Pinning the ref matters: without it, Items - Get resolves against
// whatever the repository's OWN current default branch is at request
// time, which is not necessarily the same branch a caller's builds were
// linked against (a caller may be inspecting a specific
// BuildDefinitionInfo.DefaultBranch that predates a later default-branch
// change) — pinning here is this package's equivalent of the GitHub twin
// (runhistory.MatchWorkflows) passing an explicit Ref to GetContents
// rather than relying on an implicit "current default" resolution.
//
// $format=json is required, not optional: Items - Get is content-
// negotiated, and fetchOnce sets no Accept header at all, so its
// documented default for a file blob is the raw byte stream, not a JSON
// envelope — without this parameter, json.Unmarshal deserializing into
// gitItemRaw would fail on every real (non-fixture) response, since
// adofixture always replies with JSON regardless of what's requested and
// so cannot catch this by itself. This precondition is part of what the
// S9 recorded-fixture verification pass (issue #34/#155) must confirm.
func FetchYAMLContent(ctx context.Context, client *azuredevops.Client, project, repositoryID, path, branch string) (string, error) {
	reqPath := fmt.Sprintf("/%s/%s/_apis/git/repositories/%s/items", client.Org(), project, repositoryID)
	query := url.Values{
		"path":                          {path},
		"includeContent":                {"true"},
		"$format":                       {"json"},
		"versionDescriptor.version":     {strings.TrimPrefix(branch, branchRefPrefix)},
		"versionDescriptor.versionType": {"branch"},
		"api-version":                   {"7.1"},
	}

	var item gitItemRaw
	if err := azuredevops.GetJSONObject(ctx, client, azuredevops.HostCore, reqPath, query, &item); err != nil {
		return "", err
	}
	return item.Content, nil
}

// MatchedPipeline pairs one pipeline (build definition) with the
// scanner-signature matches its YAML produced, already filtered to a
// single category — mirrors runhistory.MatchedWorkflow. Name (from
// PipelineRef, the same source used for SkippedPipeline) makes Facts/report
// output readable — a bare DefinitionID is opaque there, unlike
// skipped_workflows' own precedent of identifying content by a
// human-readable path. RepositoryID (from the same FetchBuildDefinition
// call that already resolved everything else here — no extra API call)
// is what lets a per-repo caller (C05/C06, issue #152) filter this
// project-wide list down to the pipelines that actually target the one
// repo it's currently scoring: pipeline discovery itself is project-scoped
// (ListPipelines has no per-repo filter), so without this field a caller
// would have no way to tell a match for repo A apart from one for repo B
// in the same project.
type MatchedPipeline struct {
	DefinitionID int
	Name         string
	Path         string
	RepositoryID string
	Matches      []mapping.ScannerMatch
}

// SkippedPipeline is one pipeline (or one template reference inside a
// pipeline) MatchPipelines could not turn into full evidence — mirrors
// actionssecurity's skippedWorkflow: every check consuming this list can
// avoid asserting a confident verified-pass when the evidence it searched
// was known-incomplete, rather than silently treating a gap as an absence.
// A YAMLPathNotYAML pipeline (classic/designer, genuinely out of scope) is
// NOT recorded here — see MatchPipelines' doc comment. Name carries the
// same readability benefit as MatchedPipeline.Name.
//
// RepositoryID carries the same per-repo attribution MatchedPipeline.RepositoryID
// does, wherever it's actually known: every skip reason except the very
// first (the build-definition fetch itself failing) happens strictly
// after FetchBuildDefinition already succeeded, so RepositoryID is
// populated for those; the one case where FetchBuildDefinition itself is
// what failed leaves RepositoryID empty — genuinely unknown, not a bug —
// since there is no repository field to read from a response that was
// never received. A caller attributing skips to a specific repo's Facts
// should treat an empty RepositoryID as "could not be attributed to any
// one repo," not "belongs to every repo."
type SkippedPipeline struct {
	DefinitionID int
	Name         string
	RepositoryID string
	Reason       string
}

// MatchPipelines resolves each of pipelines' build definitions, fetches
// and parses the YAML for every one that resolves to a YAML pipeline, and
// matches it via registry.MatchPipeline, keeping only matches in category
// — the ADO analogue of runhistory.ListWorkflows + MatchWorkflows
// together.
//
// A classic/designer pipeline (YAMLPathNotYAML) is skipped silently, not
// recorded in the returned skipped list — issue #34's non-goals scope this
// tool to YAML pipelines only, so a classic pipeline is out of scope by
// design, the same way a repository type other than TfsGit would be, not
// an evidence gap. Every other failure — the build-definition fetch
// itself failing, an indeterminate YAML path (YAMLPathUnknown), the YAML
// content fetch failing, or a `template:` reference MatchPipeline
// couldn't resolve (mapping.UnresolvedTemplateRef) — becomes a
// SkippedPipeline entry: this mirrors how skipped_workflows surfaces
// content this tool couldn't fully inspect (issue #34's non-goals:
// "cross-repo YAML templates... recorded as skipped, mirroring
// skipped_workflows"), and how a YAML/decode failure (not a benign
// absence) is recorded in actionssecurity's own skippedWorkflow list
// rather than silently vanishing.
func MatchPipelines(ctx context.Context, client *azuredevops.Client, registry *mapping.ScannerSignatureRegistry, project string, pipelines []PipelineRef, category mapping.ScannerCategory) (matched []MatchedPipeline, skipped []SkippedPipeline) {
	for _, p := range pipelines {
		info, err := FetchBuildDefinition(ctx, client, project, p.ID)
		if err != nil {
			skipped = append(skipped, SkippedPipeline{DefinitionID: p.ID, Name: p.Name, Reason: fmt.Sprintf("fetch build definition failed: %v", err)})
			continue
		}

		switch info.YAMLPath.Status {
		case YAMLPathNotYAML:
			continue // out of scope, not a gap — see doc comment
		case YAMLPathUnknown:
			skipped = append(skipped, SkippedPipeline{DefinitionID: p.ID, Name: p.Name, RepositoryID: info.RepositoryID, Reason: info.YAMLPath.Reason})
			continue
		}

		content, err := FetchYAMLContent(ctx, client, project, info.RepositoryID, info.YAMLPath.Path, info.DefaultBranch)
		if err != nil {
			skipped = append(skipped, SkippedPipeline{DefinitionID: p.ID, Name: p.Name, RepositoryID: info.RepositoryID, Reason: fmt.Sprintf("fetch YAML content failed: %v", err)})
			continue
		}

		parsed, err := mapping.ParsePipelineFile([]byte(content))
		if err != nil {
			skipped = append(skipped, SkippedPipeline{DefinitionID: p.ID, Name: p.Name, RepositoryID: info.RepositoryID, Reason: fmt.Sprintf("parse YAML failed: %v", err)})
			continue
		}

		matches, unresolved := registry.MatchPipeline(parsed)
		for _, ref := range unresolved {
			skipped = append(skipped, SkippedPipeline{DefinitionID: p.ID, Name: p.Name, RepositoryID: info.RepositoryID, Reason: fmt.Sprintf("template reference not resolved: %s", ref.Ref)})
		}

		var categoryMatches []mapping.ScannerMatch
		for _, m := range matches {
			if m.Category == category {
				categoryMatches = append(categoryMatches, m)
			}
		}
		if len(categoryMatches) > 0 {
			matched = append(matched, MatchedPipeline{DefinitionID: p.ID, Name: p.Name, Path: info.YAMLPath.Path, RepositoryID: info.RepositoryID, Matches: categoryMatches})
		}
	}
	return matched, skipped
}
