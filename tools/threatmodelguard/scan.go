// Package main implements threatmodelguard: a CI guard for issue #260,
// closing the same "hand-maintained list of code facts, no guard" gap
// checks-docs-check (#30), examples-check (#228), and rubricguard (#209)
// already close elsewhere — for docs/threat-model.md's self-hosted-macOS
// job enumeration (CHANGELOG's #260 entry has the full story). Coarse
// like those siblings: a job counts as documented if it's backtick-quoted
// anywhere in the runner-state bullet, not disambiguated by workflow file
// (CHANGELOG has the one real ambiguity this causes).
//
// A green run doesn't mean every self-hosted-macOS job is truly discovered
// — jobLabelSets' matrix-indirection resolution (round 2 review of #260)
// only understands `runs-on: ${{ matrix.<field> }}` paired with
// `strategy.matrix.include`. Three related shapes would go undetected if
// they ever appeared, none of which exist in this repo today (confirmed
// directly, not assumed):
//
//   - Plain `strategy.matrix.<key>: [...]` without an `include:` block —
//     the *more common* form in real-world Actions workflows, and this
//     package doesn't resolve it at all; a self-hosted-macOS leg reached
//     only this way is invisible.
//   - A typo'd matrix key in `${{ matrix.<field> }}` (or in an `include`
//     entry) — silently resolves to zero legs rather than erroring, since
//     `entry[field]`'s `ok` check just skips a missing key the same way it
//     skips a legitimately-absent one. `actionlint` catches this class,
//     but isn't run in this repo's CI — checked directly, not assumed; it
//     appears only inside a comment in `ci.yaml` — so there's no in-repo
//     mitigation for it today.
//   - A non-bare matrix expression, e.g. `${{ matrix.os || 'ubuntu-latest'
//     }}` — matrixExprRe only matches a bare `${{ matrix.<word> }}`
//     (arbitrary surrounding whitespace is fine; anything else in the
//     expression isn't), so an operator or default-value form falls
//     through to the bare-runner-label case instead, silently treating the
//     whole literal expression string as one (never self-hosted-macOS)
//     label.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// workflowFile is the minimal shape this guard needs from a GitHub
// Actions workflow — everything else in a real workflow file (on:,
// permissions:, concurrency:, steps:, ...) is irrelevant to "which jobs
// run on a self-hosted macOS runner" and left unparsed.
type workflowFile struct {
	Jobs map[string]job `yaml:"jobs"`
}

type job struct {
	RunsOn   yaml.Node `yaml:"runs-on"`
	Strategy struct {
		Matrix struct {
			Include []map[string]yaml.Node `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
}

var matrixExprRe = regexp.MustCompile(`^\$\{\{\s*matrix\.(\w+)\s*\}\}$`)

// jobLabelSets returns every distinct runs-on label set j can resolve
// to — one set for a plain job, or one per strategy.matrix.include entry
// when runs-on indirects through `${{ matrix.<field> }}`. An include
// entry with no such field is skipped, not an error — a matrix can vary
// other fields without touching the runner.
//
// The default branch (round 2 review of #260) returns no sets rather than
// erroring — it used to hard-error the whole run for any unrecognized
// shape, and a job-level `uses:` (a reusable-workflow call) has no
// `runs-on` at all, decoding to RunsOn's zero Kind. Probe confirmed: one
// reusable call anywhere plus one correctly-documented macOS job elsewhere
// aborted the guard entirely (`unrecognized runs-on shape`) and reported
// nothing — worse than missing that one job, since it silences every real
// finding too. `runs-on: {group:, labels:}` (a MappingNode, GitHub's
// runner-group syntax) hits the same branch and is skipped the same way —
// disclosed, accepted coarseness matching this guard's own siblings, not
// fixed further: no job in this repo uses either shape today, confirmed
// directly, so nothing is silently missed in practice yet.
func jobLabelSets(j job) ([][]string, error) {
	switch j.RunsOn.Kind {
	case yaml.SequenceNode:
		labels, err := decodeStringList(&j.RunsOn)
		if err != nil {
			return nil, err
		}
		return [][]string{labels}, nil
	case yaml.ScalarNode:
		m := matrixExprRe.FindStringSubmatch(j.RunsOn.Value)
		if m == nil {
			// A bare runner label (e.g. "ubuntu-latest") — never
			// self-hosted macOS on its own, one leg with that label.
			return [][]string{{j.RunsOn.Value}}, nil
		}
		field := m[1]
		var sets [][]string
		for _, entry := range j.Strategy.Matrix.Include {
			node, ok := entry[field]
			if !ok {
				continue
			}
			labels, err := decodeStringList(&node)
			if err != nil {
				return nil, err
			}
			sets = append(sets, labels)
		}
		return sets, nil
	default:
		return nil, nil
	}
}

// decodeStringList reads n as either a single scalar (one-element list)
// or a sequence of scalars.
func decodeStringList(n *yaml.Node) ([]string, error) {
	if n.Kind == yaml.ScalarNode {
		return []string{n.Value}, nil
	}
	var out []string
	if err := n.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// isMacOSSelfHosted reports whether labels names a self-hosted macOS
// runner — both "self-hosted" and "macOS" present, case-insensitively.
func isMacOSSelfHosted(labels []string) bool {
	hasSelfHosted, hasMacOS := false, false
	for _, l := range labels {
		switch strings.ToLower(l) {
		case "self-hosted":
			hasSelfHosted = true
		case "macos":
			hasMacOS = true
		}
	}
	return hasSelfHosted && hasMacOS
}

// selfHostedMacOSJobs returns the sorted, deduplicated set of job names
// (bare job keys, matching how threat-model.md names them) across every
// dir/*.yaml or dir/*.yml file resolving to a self-hosted macOS runner.
// GitHub Actions accepts either extension for a workflow file, and this
// repo already uses .yml elsewhere (dependabot.yml, every
// ISSUE_TEMPLATE/*.yml) — round 2 review of #260 confirmed a self-hosted
// macOS job in a .yml-suffixed workflow was invisible to a .yaml-only
// glob, a live convention gap, not a hypothetical one.
func selfHostedMacOSJobs(dir string) ([]string, error) {
	var files []string
	for _, pattern := range []string{"*.yaml", "*.yml"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
	}
	names := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var wf workflowFile
		if err := yaml.Unmarshal(data, &wf); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f, err)
		}
		for name, j := range wf.Jobs {
			sets, err := jobLabelSets(j)
			if err != nil {
				return nil, fmt.Errorf("%s job %q: %w", f, name, err)
			}
			for _, labels := range sets {
				if isMacOSSelfHosted(labels) {
					names[name] = true
					break
				}
			}
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// bulletStartRe anchors on the bullet's own list-item syntax (2-space
// indent, "- **", line start), not just the bare phrase — round 2 review
// of #260: strings.Index on the bare phrase found the FIRST occurrence
// anywhere in the document, so a forward cross-reference elsewhere (e.g.
// "(see the Shared, persistent runner state residual risk below)" — a
// style this document and ci.yaml's own comments already use) became "the
// section", making every real job look undocumented against a completely
// correct document — exactly the false-positive class ci.yaml:58-63 says
// is worse than no guard at all. Anchoring on the actual bullet-list
// prefix means a prose mention can never match: it would need to start a
// new line at this exact indent with this exact "- **" opening, which a
// parenthetical cross-reference never does.
var bulletStartRe = regexp.MustCompile(`(?m)^  - \*\*Shared, persistent runner state`)

// runnerStateSection extracts the runner-state bullet's own text — from
// its start to whichever of these comes first: the next nested "  - **"
// bullet at this same two-space indent (a sibling residual-risk sub-
// bullet), a 0-indent "- **" bullet (a sibling top-level residual risk —
// the level this document's own residual-risks list actually uses), a
// "## " heading, or a "### " heading — so a job name mentioned in any of
// those doesn't count as documented here.
func runnerStateSection(doc []byte) (string, error) {
	text := string(doc)
	loc := bulletStartRe.FindStringIndex(text)
	if loc == nil {
		return "", fmt.Errorf("no %q bullet found", "Shared, persistent runner state")
	}
	// loc[0] is the start of this bullet's own "  - **" — rest can't
	// spuriously self-match any end marker below, since each one only
	// begins after a "\n" and rest itself doesn't start with one.
	rest := text[loc[0]:]
	end := len(rest)
	for _, marker := range []string{"\n  - **", "\n- **", "\n## ", "\n### "} {
		if i := strings.Index(rest, marker); i >= 0 && i < end {
			end = i
		}
	}
	return rest[:end], nil
}

// missingFromDoc returns which of jobNames don't appear backtick-quoted
// (this document's own convention for naming a job, e.g. "`lint`")
// anywhere in section.
func missingFromDoc(jobNames []string, section string) []string {
	var missing []string
	for _, name := range jobNames {
		if !strings.Contains(section, "`"+name+"`") {
			missing = append(missing, name)
		}
	}
	return missing
}
