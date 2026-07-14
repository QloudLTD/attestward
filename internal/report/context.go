package report

import (
	"sort"

	"github.com/sioakim/ssdf/internal/mapping"
	"github.com/sioakim/ssdf/internal/model"
)

// renderContext is everything the templates need, precomputed once by
// buildContext so the templates themselves stay declarative (no lookups
// or branching logic embedded in template text). Building this is a pure
// function of its inputs — no I/O, no clock reads — matching this
// package's own "pure functions over model.EvidencePack" contract.
type renderContext struct {
	Pack model.EvidencePack

	// MappingVersionMismatch is set when the loaded ssdf/cisa/questions
	// mapping's own Version doesn't match what pack.MappingVersions
	// records — e.g. rendering an old saved pack with a newer binary.
	// Rendering still proceeds (IDs without a matching title/text just
	// render bare), but the report surfaces this rather than silently
	// mixing eras of mapping text.
	MappingVersionMismatch bool

	StatusCounts map[model.Status]int
	Clusters     []clusterView
	Gaps         []model.CheckResult
	SelfAttested []selfAttestedView
	NotCheckable []model.CheckResult
}

type clusterView struct {
	ID       string
	Title    string
	FormText string
	Status   model.Status
	// HasStatus is false when pack.Rollup has no entry at all for this
	// cluster — mapping.BuildRollup's own documented semantics: absence
	// means "nothing in this pack speaks to this cluster", a different,
	// honest claim from any of the five Status values, not the same as
	// the cluster's Status having some zero-ish value.
	HasStatus bool
	Tasks     []taskView
}

type taskView struct {
	ID        string
	Text      string
	Status    model.Status
	HasStatus bool
	Checks    []model.CheckResult
}

// selfAttestedView pairs one self-attested CheckResult with the
// API-verified checks its question named as complementary (Pairing) —
// "C09/C10 pairings shown side-by-side", per issue #25. Paired checks
// that don't actually appear in this scan's Results are simply omitted,
// not rendered as a broken reference.
type selfAttestedView struct {
	Result model.CheckResult
	Paired []model.CheckResult
}

// buildContext assembles a renderContext from pack plus the mapping data
// needed to turn bare IDs into human-readable titles/text. ssdf/cisa/
// saQuestions may each be nil (a caller that couldn't load one, or
// doesn't need self-attestation pairing) — every lookup degrades to the
// bare ID rather than panicking or erroring.
func buildContext(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions) renderContext {
	ctx := renderContext{Pack: pack, StatusCounts: map[model.Status]int{}}

	if ssdf != nil && pack.MappingVersions.SSDF != "" && ssdf.Version != pack.MappingVersions.SSDF {
		ctx.MappingVersionMismatch = true
	}
	if cisa != nil && pack.MappingVersions.CISAForm != "" && cisa.Version != pack.MappingVersions.CISAForm {
		ctx.MappingVersionMismatch = true
	}

	resultsByCheck := map[string][]model.CheckResult{}
	for _, r := range pack.Results {
		ctx.StatusCounts[r.Status]++
		resultsByCheck[r.CheckID] = append(resultsByCheck[r.CheckID], r)

		switch r.Status {
		case model.StatusVerifiedFail, model.StatusPartial:
			ctx.Gaps = append(ctx.Gaps, r)
		case model.StatusNotCheckable:
			ctx.NotCheckable = append(ctx.NotCheckable, r)
		}
	}
	sortResults(ctx.Gaps)
	sortResults(ctx.NotCheckable)

	statusByTask := map[string]model.Status{}
	hasTaskStatus := map[string]bool{}
	if pack.Rollup != nil {
		for _, tr := range pack.Rollup.Tasks {
			statusByTask[tr.TaskID] = tr.Status
			hasTaskStatus[tr.TaskID] = true
		}
	}

	if cisa != nil {
		for _, cluster := range cisa.Clusters {
			cv := clusterView{ID: cluster.ID, Title: cluster.Title, FormText: cluster.FormText}
			if pack.Rollup != nil {
				for _, cr := range pack.Rollup.Clusters {
					if cr.ClusterID == cluster.ID {
						cv.Status = cr.Status
						cv.HasStatus = true
					}
				}
			}
			for _, taskID := range cluster.SSDFTasks {
				tv := taskView{ID: taskID, Status: statusByTask[taskID], HasStatus: hasTaskStatus[taskID]}
				if ssdf != nil {
					if task, ok := ssdf.TaskByID[taskID]; ok {
						tv.Text = task.Text
						for _, checkID := range task.Checks {
							tv.Checks = append(tv.Checks, resultsByCheck[checkID]...)
						}
					}
				}
				sortResults(tv.Checks)
				cv.Tasks = append(cv.Tasks, tv)
			}
			ctx.Clusters = append(ctx.Clusters, cv)
		}
	}

	pairingByCheck := map[string][]string{}
	if saQuestions != nil {
		for _, q := range saQuestions.Questions {
			pairingByCheck[q.ID] = q.Pairing
		}
	}
	for _, r := range pack.Results {
		if r.Status != model.StatusSelfAttested {
			continue
		}
		sav := selfAttestedView{Result: r}
		for _, pairedID := range pairingByCheck[r.CheckID] {
			sav.Paired = append(sav.Paired, resultsByCheck[pairedID]...)
		}
		sortResults(sav.Paired)
		ctx.SelfAttested = append(ctx.SelfAttested, sav)
	}
	sort.Slice(ctx.SelfAttested, func(i, j int) bool {
		return ctx.SelfAttested[i].Result.CheckID < ctx.SelfAttested[j].Result.CheckID
	})

	return ctx
}

func sortResults(results []model.CheckResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].CheckID != results[j].CheckID {
			return results[i].CheckID < results[j].CheckID
		}
		return results[i].Scope.Repo < results[j].Scope.Repo
	})
}
