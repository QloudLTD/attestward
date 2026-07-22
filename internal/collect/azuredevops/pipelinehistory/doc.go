// Package pipelinehistory is Azure DevOps's counterpart to
// internal/collect/github/runhistory: the release-resolution,
// pipeline-discovery, run-lookback, and cadence machinery shared by any
// ADO collector that needs to answer "did a matched tool actually run for
// each recent release" — C05 sast-history and C06 sca-history (issue
// #152) are its first consumers, mirroring how C05/C06 share runhistory on
// the GitHub side (issue #18).
//
// This package deliberately does not import runhistory, and vice versa:
// ADR-0005's platform seam keeps github and azuredevops as independent
// siblings so a future platform (GitLab, issue #35) never has to reach
// into either one — the two packages' pure lookback/linkage/cadence
// functions are structurally identical (same shapes, same contracts,
// proven by mirrored test suites) but independently implemented, the same
// trade CONTRIBUTING.md's collector packages already make rather than
// share code across platform boundaries.
//
// Azure DevOps has no equivalent of a GitHub Release: a "release" here is
// a git tag matching a caller-supplied pattern, resolved via the Git Refs
// API (release.go) — a multi-step process (list tags, then resolve each
// one's date via either the annotated-tag object or the pointed-to commit,
// depending on tag kind) that GitHub's Releases API collapses into a
// single call. "Runs" are Azure Pipelines builds (builds.go), matched to
// releases by source-version/branch the same way runhistory links workflow
// runs (linkage.go) — Azure DevOps's Builds List has no server-side
// sourceVersion filter (verified against the full documented parameter
// list), so that matching happens client-side here, same as the GitHub
// side's own head-SHA/head-branch comparison.
//
// Pipeline discovery (pipeline.go) resolves which of a project's pipelines
// are YAML-based (as opposed to classic/designer, out of scope per #34's
// non-goals) and fetches their YAML for matching via #149's
// mapping.MatchPipeline — the ADO analogue of runhistory's
// ListWorkflows/MatchWorkflows split.
package pipelinehistory
