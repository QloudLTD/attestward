package scahistory

import (
	"context"
	"sort"

	ghgithub "github.com/google/go-github/v75/github"

	ghcollect "github.com/sioakim/ssdf/internal/collect/github"
)

// manifestEcosystems maps each detectable Dependabot package-ecosystem
// value to the root-level filename(s) that, if present, indicate that
// ecosystem is in active use in this repo. A practical, common-case subset
// — not exhaustive of every ecosystem Dependabot supports — chosen for
// confident detection from a single root-directory listing. A manifest
// nested in a subdirectory (a documented, legitimate Dependabot use case
// via its own `directory:` field) won't be detected here: this is a v0.1
// heuristic bounded to one API call, not a full repository tree walk.
var manifestEcosystems = map[string][]string{
	"gomod":    {"go.mod"},
	"npm":      {"package.json"},
	"pip":      {"requirements.txt", "Pipfile", "pyproject.toml", "setup.py"},
	"bundler":  {"Gemfile"},
	"maven":    {"pom.xml"},
	"gradle":   {"build.gradle", "build.gradle.kts"},
	"composer": {"composer.json"},
	"cargo":    {"Cargo.toml"},
	"docker":   {"Dockerfile"},
	"mix":      {"mix.exs"},
	"pub":      {"pubspec.yaml"},
	"swift":    {"Package.swift"},
}

// githubActionsEcosystem is Dependabot's ecosystem for keeping pinned
// GitHub Actions versions up to date — its "manifest" is any workflow
// file under .github/workflows/, already known from the workflow listing
// this collector fetches for C06.sca.tool-configured, so detecting it
// costs no extra API call.
const githubActionsEcosystem = "github-actions"

// detectEcosystems reports which Dependabot ecosystems appear to be in
// use, given a repo's root-directory filenames and whether it has any
// GitHub Actions workflows at all. Returns a sorted, deduplicated list.
func detectEcosystems(rootFilenames []string, hasWorkflows bool) []string {
	present := map[string]bool{}
	for _, name := range rootFilenames {
		present[name] = true
	}

	var detected []string
	for ecosystem, filenames := range manifestEcosystems {
		for _, f := range filenames {
			if present[f] {
				detected = append(detected, ecosystem)
				break
			}
		}
	}
	if hasWorkflows {
		detected = append(detected, githubActionsEcosystem)
	}
	sort.Strings(detected)
	return detected
}

// fetchRootFilenames lists the repo's root directory and returns the
// filenames of its top-level regular files (subdirectories excluded —
// this collector only looks at root-level manifests, see
// manifestEcosystems' doc comment).
func fetchRootFilenames(ctx context.Context, client *ghcollect.Client, org, repo, defaultBranch string) ([]string, *ghgithub.Response, error) {
	_, dirContent, resp, err := client.REST.Repositories.GetContents(ctx, org, repo, "", &ghgithub.RepositoryContentGetOptions{Ref: defaultBranch})
	if err != nil {
		return nil, resp, err
	}
	names := make([]string, 0, len(dirContent))
	for _, entry := range dirContent {
		if entry.GetType() == "file" {
			names = append(names, entry.GetName())
		}
	}
	return names, resp, nil
}
