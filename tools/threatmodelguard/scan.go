// Package main implements threatmodelguard: a CI guard for issue #260,
// closing the same "hand-maintained list of code facts, no guard" gap
// checks-docs-check (#30), examples-check (#228), and rubricguard (#209)
// already close elsewhere — for docs/threat-model.md's self-hosted-macOS
// job enumeration (CHANGELOG's #260 entry has the full story). A job
// counts as documented only if it's backtick-quoted inside the runner-
// state bullet's own list — the parenthetical opened by "(every
// macOS-labeled job in this repo:" — not merely mentioned anywhere in the
// bullet: issue #286 found a mention in a clause claiming something else
// entirely (moving `sign-verify` into the spyros-ionos-ssdf clause) used
// to still pass. Still coarse on one axis, unchanged from before #286: a
// documented name isn't disambiguated by workflow file, so two different
// jobs sharing one bare key (ci.yaml's `build` and multi-arch-build-
// sample.yaml's own `build`) are treated as the same name (CHANGELOG has
// the one real ambiguity this causes).
//
// The reverse direction is checked too (issue #302): a name left in the
// list after its job is deleted, renamed, or moves off macOS produced no
// signal, since the forward check only ever walks discovered jobs looking
// for a mention. extraInDoc walks the list instead, for backtick-quoted,
// job-id-shaped tokens with no matching real job — nonJobBacktickTokens
// is a short, explicit exclusion list (today: `workflow_dispatch`) for the
// one case that shape check alone can't rule out.
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

// sectionTerminatorRe matches the start of any Markdown construct that ends
// the runner-state bullet's own scope: a heading two or more "#"s deep, a
// sibling bullet at this bullet's own two-space indent or the residual-
// risks list's own zero-space indent, or a zero-indent numbered list item —
// the alternation has no paired two-space form, so a two-space-indented
// numbered item ("  1. ...") isn't matched. Left that way deliberately: the
// gap only makes this function's own scope run further than it strictly
// needs to, and runnerStateListSection's independent paren-tracking (#308)
// already bounds the text this guard actually acts on well short of where
// either indent's numbered form would change a real verdict — the same
// "gap real here, absorbed downstream" shape this fix's own PR measured
// for the terminator regex as a whole.
//
// Issue #309 found two shapes the old literal-prefix list ("\n  - **",
// "\n- **", "\n## ", "\n### ") let through: a "#### "
// heading, since the old "### " marker's trailing space isn't the fourth
// "#"; and an unbolded sibling bullet ("- A sibling risk") or a numbered
// item ("1. ..."), since the old bullet markers required the bold "**"
// opener. Matching the bare "- "/"  - " prefix, rather than "- **"/"  - **"
// (the shape #309 itself suggested), covers a sibling bullet whether or
// not it's bolded with one alternative instead of a bold-specific and a
// plain-specific entry per indent: "- " is a strict prefix of "- **", so
// matching it alone already covers both. Matching any heading depth
// ("#{2,}", not capped at four) means a heading deeper than this document
// uses today needs no future entry either — the exact kind of gap #309
// was filed to close.
var sectionTerminatorRe = regexp.MustCompile(`\n(#{2,} |  - |- |\d+\. )`)

// runnerStateSection extracts the runner-state bullet's own text — from
// its start to wherever sectionTerminatorRe first matches — so a job name
// mentioned in a heading, a sibling bullet, or a numbered item after this
// bullet's own end doesn't count as documented here.
func runnerStateSection(doc []byte) (string, error) {
	text := string(doc)
	loc := bulletStartRe.FindStringIndex(text)
	if loc == nil {
		return "", fmt.Errorf("no %q bullet found", "Shared, persistent runner state")
	}
	// loc[0] is the start of this bullet's own "  - **" — rest can't
	// spuriously self-match sectionTerminatorRe, since every alternative
	// requires a preceding "\n" and rest itself doesn't start with one.
	rest := text[loc[0]:]
	end := len(rest)
	if m := sectionTerminatorRe.FindStringIndex(rest); m != nil {
		end = m[0]
	}
	return rest[:end], nil
}

// missingFromDoc returns which of jobNames don't appear backtick-quoted
// (this document's own convention for naming a job, e.g. "`lint`")
// anywhere in section — callers pass the list text from
// runnerStateListSection, not the whole bullet from runnerStateSection, so
// a mention outside the list that claims exhaustiveness doesn't satisfy
// the check (issue #286).
func missingFromDoc(jobNames []string, section string) []string {
	var missing []string
	for _, name := range jobNames {
		if !strings.Contains(section, "`"+name+"`") {
			missing = append(missing, name)
		}
	}
	return missing
}

// macOSListMarkerRe anchors on the literal "(every macOS-labeled job in
// this repo:" phrase that opens the runner-state bullet's own exhaustive
// list — the same "anchor on a real syntactic construct, not a bare
// phrase" idea as collectors.go's adoCollectorListRe (issue #274), adapted
// to prose: there's no bare `{...}` here, so the list's own boundary is
// this parenthetical's balanced close instead of a single delimiter
// character.
var macOSListMarkerRe = regexp.MustCompile(`\(every\s+macOS-labeled job in this repo:`)

// runnerStateListSection narrows section (the whole runner-state bullet,
// from runnerStateSection) down to just the parenthetical that actually
// claims exhaustiveness. Depth is tracked rather than stopping at the
// first ")" because nearly every item in the list has its own explanatory
// aside in parens (e.g. "`gomod-tidy-drift` (added with issue #249's drift
// guard ...)"), and the list itself continues past the first job or two
// that "lands here too" via a different workflow file before the
// parenthetical actually closes. Errors if the marker or its own balanced
// close can't be found — a restructured bullet needs a human to re-anchor
// this, not a silent pass, the same contract adoCollectorListFromDoc uses.
func runnerStateListSection(section string) (string, error) {
	loc := macOSListMarkerRe.FindStringIndex(section)
	if loc == nil {
		return "", fmt.Errorf("no %q parenthetical found", "(every macOS-labeled job in this repo:")
	}
	depth := 0
	for i := loc[0]; i < len(section); i++ {
		switch section[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return section[loc[0] : i+1], nil
			}
		}
	}
	return "", fmt.Errorf("%q parenthetical never closes", "(every macOS-labeled job in this repo:")
}

// backtickTokenRe extracts every backtick-quoted token from a piece of
// text. Used only against the already-scoped list, not the whole bullet,
// so every match is a genuine candidate for "a name this list claims" —
// never a mention from a clause making some other claim.
var backtickTokenRe = regexp.MustCompile("`([^`]*)`")

// jobIDShapeRe is a loose "looks like a GitHub Actions job id" gate —
// letters, digits, hyphens, and underscores only, per GitHub's own job-id
// syntax — just enough to drop the workflow-filename asides the list's own
// prose also backtick-quotes (ci.yaml, release.yaml, ...) and multi-word
// phrases (the go mod tidy step), without a per-token exclusion list for
// every one of those.
var jobIDShapeRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// nonJobBacktickTokens are job-id-shaped tokens the list's own prose
// backtick-quotes for a reason other than naming a job — today just the
// one workflow-trigger keyword the "manually run" aside mentions
// (confirmed directly against the real list text, not assumed). Extend
// this rather than jobIDShapeRe if a future edit adds another such token.
var nonJobBacktickTokens = map[string]bool{
	"workflow_dispatch": true,
}

// extraInDoc is missingFromDoc's mirror image (issue #302): it returns
// job-id-shaped names backtick-quoted inside list that don't correspond to
// any real jobName — a name left in the list after its job is deleted,
// renamed, or moves off macOS, which missingFromDoc's walk-the-jobs
// direction can never surface on its own.
func extraInDoc(jobNames []string, list string) []string {
	realJobs := map[string]bool{}
	for _, n := range jobNames {
		realJobs[n] = true
	}
	seen := map[string]bool{}
	var extra []string
	for _, m := range backtickTokenRe.FindAllStringSubmatch(list, -1) {
		token := m[1]
		if !jobIDShapeRe.MatchString(token) || nonJobBacktickTokens[token] || realJobs[token] || seen[token] {
			continue
		}
		seen[token] = true
		extra = append(extra, token)
	}
	sort.Strings(extra)
	return extra
}

// runRunnerStateExtras is run's mirror image (issue #302): it flags a
// backtick-quoted, job-id-shaped name in the runner-state list that
// doesn't correspond to any real self-hosted-macOS job today. Duplicates
// run's file-reading and section/list resolution rather than sharing a
// helper — a deliberate choice to avoid restructuring run's own shape
// mid-fix; a shared helper is a reasonable follow-up once both directions
// have landed.
func runRunnerStateExtras(workflowsDir, threatModelPath string) ([]string, error) {
	jobNames, err := selfHostedMacOSJobs(workflowsDir)
	if err != nil {
		return nil, fmt.Errorf("scan workflows: %w", err)
	}
	doc, err := os.ReadFile(threatModelPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", threatModelPath, err)
	}
	section, err := runnerStateSection(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", threatModelPath, err)
	}
	list, err := runnerStateListSection(section)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", threatModelPath, err)
	}
	return extraInDoc(jobNames, list), nil
}
