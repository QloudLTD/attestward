package scahistory

import (
	"context"
	"fmt"
	"net/http"

	ghgithub "github.com/google/go-github/v75/github"
	"gopkg.in/yaml.v3"

	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
)

// dependabotConfigPaths are the two file extensions GitHub accepts for
// this config — checked in order, first hit wins. Both are real,
// supported paths (GitHub's own docs use .yml in examples but accept
// either).
var dependabotConfigPaths = []string{".github/dependabot.yml", ".github/dependabot.yaml"}

// dependabotConfig is the minimal slice of .github/dependabot.yml this
// package needs: which ecosystems are configured. Deliberately NOT
// strict-decoded, matching mapping.WorkflowFile's precedent (see its doc
// comment) — this is external, uncontrolled content from a scanned repo
// with many fields (schedule, reviewers, labels, ...) this package has no
// opinion about.
type dependabotConfig struct {
	Updates []struct {
		PackageEcosystem string `yaml:"package-ecosystem"`
	} `yaml:"updates"`
}

func parseDependabotConfig(raw []byte) (dependabotConfig, error) {
	var cfg dependabotConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return dependabotConfig{}, fmt.Errorf("parse dependabot config: %w", err)
	}
	return cfg, nil
}

// ecosystems returns the set of package-ecosystem values this config
// configures, empty entries dropped.
func (c dependabotConfig) ecosystems() map[string]bool {
	out := map[string]bool{}
	for _, u := range c.Updates {
		if u.PackageEcosystem != "" {
			out[u.PackageEcosystem] = true
		}
	}
	return out
}

// fetchDependabotConfig tries both accepted file extensions in turn. A 404
// on both is a legitimate "no config present" outcome, not an error — the
// caller (checkDependabotConfig) decides whether that's a real gap or
// not-checkable depending on whether there's anything to cover at all. Any
// other error (permission denied, a real parse failure) is returned as-is.
func fetchDependabotConfig(ctx context.Context, client *ghcollect.Client, org, repo, defaultBranch string) (cfg *dependabotConfig, exists bool, resp *ghgithub.Response, err error) {
	var lastResp *ghgithub.Response
	for _, path := range dependabotConfigPaths {
		content, _, pathResp, pathErr := client.REST.Repositories.GetContents(ctx, org, repo, path, &ghgithub.RepositoryContentGetOptions{Ref: defaultBranch})
		lastResp = pathResp
		if pathErr != nil {
			if pathResp != nil && pathResp.StatusCode == http.StatusNotFound {
				continue // try the other extension
			}
			return nil, false, pathResp, pathErr
		}
		if content == nil {
			continue
		}
		raw, contentErr := content.GetContent()
		if contentErr != nil {
			return nil, false, pathResp, contentErr
		}
		parsed, parseErr := parseDependabotConfig([]byte(raw))
		if parseErr != nil {
			return nil, false, pathResp, parseErr
		}
		return &parsed, true, pathResp, nil
	}
	return nil, false, lastResp, nil
}
