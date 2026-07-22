// Package packdiff compares two evidence packs semantically (issue #143,
// spun out of #36): same check keyed by (check_id, org, repo), status
// transitions classified, volatile fields (scan window, provenance
// timestamps and digests) ignored. It is pure data-in/data-out — no I/O,
// no rendering opinions beyond the text/markdown helpers in render.go —
// so both the CLI and the future continuous-mode action consume the same
// Delta.
package packdiff

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sioakim/attestward/internal/model"
)

// Ref identifies one check result within a pack.
type Ref struct {
	CheckID string `json:"check_id"`
	Org     string `json:"org"`
	Repo    string `json:"repo,omitempty"`
}

func (r Ref) String() string {
	if r.Repo == "" {
		return fmt.Sprintf("%s (%s)", r.CheckID, r.Org)
	}
	return fmt.Sprintf("%s (%s/%s)", r.CheckID, r.Org, r.Repo)
}

// Change is one check whose status differs between baseline and current.
type Change struct {
	Ref
	From model.Status `json:"from"`
	To   model.Status `json:"to"`
	// Reason is the current pack's reason — the explanation of the state
	// the check is in now, which is what a drift reader acts on.
	Reason string `json:"reason"`
}

// Entry is a check present in only one of the two packs.
type Entry struct {
	Ref
	Status model.Status `json:"status"`
	Reason string       `json:"reason"`
}

// Context flags pack-level differences that can explain status changes
// without any real posture drift — a newer tool or mapping revision may
// check different things. Surfaced so a reader never mistakes a checker
// change for a posture change.
type Context struct {
	BaselineToolVersion    string `json:"baseline_tool_version,omitempty"`
	CurrentToolVersion     string `json:"current_tool_version,omitempty"`
	ToolVersionChanged     bool   `json:"tool_version_changed"`
	MappingVersionsChanged bool   `json:"mapping_versions_changed"`
	ReposChanged           bool   `json:"repos_changed"`
}

// Delta is the full semantic difference between a baseline and a current
// pack. Every slice is sorted by (CheckID, Repo) so output is
// deterministic; all slices are initialized empty, never nil, so the JSON
// form is stable for automation.
type Delta struct {
	Regressions  []Change `json:"regressions"`
	Improvements []Change `json:"improvements"`
	CoverageLoss []Change `json:"coverage_loss"`
	CoverageGain []Change `json:"coverage_gain"`
	Other        []Change `json:"other_changes"`
	Added        []Entry  `json:"added"`
	Removed      []Entry  `json:"removed"`
	Context      Context  `json:"context"`
}

// HasRegressions reports whether the delta contains any regression — the
// one class that fails `attestward diff`'s exit code (and, downstream,
// the continuous-mode workflow).
func (d Delta) HasRegressions() bool { return len(d.Regressions) > 0 }

// Empty reports whether the two packs are semantically identical.
func (d Delta) Empty() bool {
	return len(d.Regressions) == 0 && len(d.Improvements) == 0 &&
		len(d.CoverageLoss) == 0 && len(d.CoverageGain) == 0 &&
		len(d.Other) == 0 && len(d.Added) == 0 && len(d.Removed) == 0
}

// Compare diffs current against baseline. It errors on packs that aren't
// meaningfully comparable: different orgs, or duplicate (check_id, org,
// repo) keys within one pack (which would make "the same check" ambiguous).
func Compare(baseline, current model.EvidencePack) (Delta, error) {
	if baseline.Scope.Org != current.Scope.Org {
		return Delta{}, fmt.Errorf("packs cover different orgs (%q vs %q) — comparing them is not meaningful", baseline.Scope.Org, current.Scope.Org)
	}

	base, err := index(baseline, "baseline")
	if err != nil {
		return Delta{}, err
	}
	cur, err := index(current, "current")
	if err != nil {
		return Delta{}, err
	}

	d := Delta{
		Regressions:  []Change{},
		Improvements: []Change{},
		CoverageLoss: []Change{},
		CoverageGain: []Change{},
		Other:        []Change{},
		Added:        []Entry{},
		Removed:      []Entry{},
		Context: Context{
			BaselineToolVersion:    baseline.ToolVersion,
			CurrentToolVersion:     current.ToolVersion,
			ToolVersionChanged:     baseline.ToolVersion != current.ToolVersion,
			MappingVersionsChanged: baseline.MappingVersions != current.MappingVersions,
			ReposChanged:           !reposEqual(baseline.Scope.Repos, current.Scope.Repos),
		},
	}

	for ref, b := range base {
		c, ok := cur[ref]
		if !ok {
			d.Removed = append(d.Removed, Entry{Ref: ref, Status: b.Status, Reason: b.Reason})
			continue
		}
		if b.Status == c.Status {
			continue
		}
		ch := Change{Ref: ref, From: b.Status, To: c.Status, Reason: c.Reason}
		switch classify(b.Status, c.Status) {
		case classRegression:
			d.Regressions = append(d.Regressions, ch)
		case classImprovement:
			d.Improvements = append(d.Improvements, ch)
		case classCoverageLoss:
			d.CoverageLoss = append(d.CoverageLoss, ch)
		case classCoverageGain:
			d.CoverageGain = append(d.CoverageGain, ch)
		default:
			d.Other = append(d.Other, ch)
		}
	}
	for ref, c := range cur {
		if _, ok := base[ref]; !ok {
			d.Added = append(d.Added, Entry{Ref: ref, Status: c.Status, Reason: c.Reason})
		}
	}

	sortChanges := func(s []Change) {
		slices.SortFunc(s, func(a, b Change) int { return compareRefs(a.Ref, b.Ref) })
	}
	sortChanges(d.Regressions)
	sortChanges(d.Improvements)
	sortChanges(d.CoverageLoss)
	sortChanges(d.CoverageGain)
	sortChanges(d.Other)
	slices.SortFunc(d.Added, func(a, b Entry) int { return compareRefs(a.Ref, b.Ref) })
	slices.SortFunc(d.Removed, func(a, b Entry) int { return compareRefs(a.Ref, b.Ref) })

	return d, nil
}

// compareRefs orders by the full key — Org included, even though both
// packs' orgs match at the pack level, because per-result orgs in a
// malformed pack could still differ and slices.SortFunc is unstable:
// equal sort keys would make output order nondeterministic.
func compareRefs(a, b Ref) int {
	if c := strings.Compare(a.CheckID, b.CheckID); c != 0 {
		return c
	}
	if c := strings.Compare(a.Org, b.Org); c != 0 {
		return c
	}
	return strings.Compare(a.Repo, b.Repo)
}

func index(pack model.EvidencePack, label string) (map[Ref]model.CheckResult, error) {
	m := make(map[Ref]model.CheckResult, len(pack.Results))
	for _, r := range pack.Results {
		ref := Ref{CheckID: r.CheckID, Org: r.Scope.Org, Repo: r.Scope.Repo}
		if _, dup := m[ref]; dup {
			return nil, fmt.Errorf("%s pack has duplicate results for %s — cannot diff ambiguous packs", label, ref)
		}
		m[ref] = r
	}
	return m, nil
}

func reposEqual(a, b []string) bool {
	as, bs := slices.Clone(a), slices.Clone(b)
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}

type class int

const (
	classOther class = iota
	classRegression
	classImprovement
	classCoverageLoss
	classCoverageGain
)

// classify buckets a status transition. Regression/improvement move
// within the verified spectrum (pass/partial/fail); transitions in or out
// of not-checkable from that spectrum are coverage changes — a token or
// plan capability difference, deliberately never conflated with posture
// drift (see #29's under-scoped-token measurement for why: a weaker token
// flips dozens of checks to not-checkable with zero posture change).
// Everything else — self-attested moves in any direction — is "other":
// self-attestation answers are producer statements, not observed posture.
func classify(from, to model.Status) class {
	verified := func(s model.Status) bool {
		return s == model.StatusVerifiedPass || s == model.StatusVerifiedFail || s == model.StatusPartial
	}
	switch {
	case from == model.StatusVerifiedPass && (to == model.StatusVerifiedFail || to == model.StatusPartial),
		from == model.StatusPartial && to == model.StatusVerifiedFail:
		return classRegression
	case from == model.StatusVerifiedFail && (to == model.StatusVerifiedPass || to == model.StatusPartial),
		from == model.StatusPartial && to == model.StatusVerifiedPass:
		return classImprovement
	case verified(from) && to == model.StatusNotCheckable:
		return classCoverageLoss
	case from == model.StatusNotCheckable && verified(to):
		return classCoverageGain
	default:
		return classOther
	}
}
