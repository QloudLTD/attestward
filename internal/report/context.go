package report

import (
	"sort"

	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
)

// renderContext is everything the templates need, precomputed once by
// buildContext so the templates themselves stay declarative (no lookups
// or branching logic embedded in template text). Building this is a pure
// function of its inputs — no I/O, no clock reads — matching this
// package's own "pure functions over model.EvidencePack" contract.
type renderContext struct {
	Pack model.EvidencePack

	// MappingVersionMismatch is set when any loaded mapping's own Version
	// doesn't match what pack.MappingVersions recorded for it — e.g.
	// rendering an old saved pack with a newer binary. All four mapping
	// files are compared (ssdf, cisa_form, self_attestation,
	// scanner_signatures — see mappingVersionMismatch). Rendering still
	// proceeds (IDs without a matching title/text just render bare), but
	// the report surfaces this rather than silently mixing eras of
	// mapping text.
	MappingVersionMismatch bool

	StatusCounts map[model.Status]int
	Clusters     []clusterView
	Gaps         []gapView
	SelfAttested []selfAttestedView
	NotCheckable []notCheckableView
}

// gapView pairs a verified-fail/partial CheckResult with the POA&M finding
// ID assignFindings gave it, so report.md's Gaps table can cross-link into
// poam.md — see Finding's doc comment for why the same assignFindings call
// backs both documents. POAMID is empty only if a caller renders report.md
// with a pack whose Results, when re-run through assignFindings, somehow
// produced no matching entry — not expected in practice (every Gaps entry
// comes from the same pack.Results assignFindings consumes) but rendered
// as an em dash rather than a broken reference if it ever happened.
//
// ScopeLabel is precomputed by scopeLabel (issue #176) rather than left
// for the template to infer from (Scope.Repo, Scope.Project) presence —
// see that function's doc comment for why that inference was wrong.
type gapView struct {
	Result     model.CheckResult
	POAMID     string
	ScopeLabel string
}

// notCheckableView pairs a not-checkable CheckResult with its precomputed
// ScopeLabel — see gapView's doc comment.
type notCheckableView struct {
	Result     model.CheckResult
	ScopeLabel string
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

// mappingVersionMismatch reports whether any loaded mapping's own Version
// differs from what pack itself recorded for it. A nil loaded mapping (a
// caller that couldn't load one, or doesn't need it), or an empty
// recorded pack version (an older pack that predates that field being
// populated — see issue #255 for scanner_signatures' own history of
// exactly that), skips that one comparison rather than asserting a
// mismatch it has no actual evidence for — confirmed directly, not
// assumed, by TestMappingVersionMismatch_OlderPackMissingScannerSignaturesVersion_NoFalsePositive:
// this is what makes it safe to ship this comparison when not every pack
// carries scanner_signatures. #255's fix (PR #263) started populating it,
// so packs scanned from that point on have it — but packs captured before
// it, including examples/demo-org-pack's own, still lack the field
// entirely and must not spuriously trigger this banner.
//
// One shared implementation rather than duplicated inline comparisons in
// buildContext and buildPOAMContext (issue #264, found while working on
// #263): the two copies had drifted to compare only ssdf/cisa_form, never
// self_attestation or scanner_signatures — identically in both files,
// exactly the failure mode one shared function removes. The
// de-duplication alone doesn't prevent a FIFTH mapping file from being
// silently missed the same way, though (#265's review: adding one more
// string field to model.MappingVersions leaves this function's own
// comparisons — and a hand-listed table test of them — green forever,
// with no compile error or test failure to catch it). What closes that
// gap is TestMappingVersionMismatch_EveryFieldDriftsIndependently in
// context_test.go: it reflects over model.MappingVersions itself (one
// struct, one uniform predicate — the same shape #263's own guard uses),
// not over the four differently-typed *ssdf/*cisa/... parameters here,
// so a future field is discovered and drifted automatically rather than
// needing a new hand-written case. A fifth mapping file still needs a
// comparison line added here, but only once (not once per caller), and
// the test above will say so by name if that line is ever missed.
func mappingVersionMismatch(pack model.MappingVersions, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions, scannerSignatures *mapping.ScannerSignatureRegistry) bool {
	if ssdf != nil && pack.SSDF != "" && ssdf.Version != pack.SSDF {
		return true
	}
	if cisa != nil && pack.CISAForm != "" && cisa.Version != pack.CISAForm {
		return true
	}
	if saQuestions != nil && pack.SelfAttestation != "" && saQuestions.Version != pack.SelfAttestation {
		return true
	}
	if scannerSignatures != nil && pack.ScannerSignatures != "" && scannerSignatures.Version != pack.ScannerSignatures {
		return true
	}
	return false
}

// buildContext assembles a renderContext from pack plus the mapping data
// needed to turn bare IDs into human-readable titles/text. ssdf/cisa/
// saQuestions/scannerSignatures may each be nil (a caller that couldn't
// load one, or doesn't need self-attestation pairing) — every lookup
// degrades to the bare ID rather than panicking or erroring.
// scopeLevelByCheckID is built by the caller from collect.Registered()
// (cmd/attestward's buildScopeLevelByCheckID, ADR-0005's seam); nil or
// incomplete degrades every unresolvable check to the org-level label,
// same as before #176.
func buildContext(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions, scannerSignatures *mapping.ScannerSignatureRegistry, scopeLevelByCheckID map[string]string) renderContext {
	ctx := renderContext{Pack: pack, StatusCounts: map[model.Status]int{}}

	ctx.MappingVersionMismatch = mappingVersionMismatch(pack.MappingVersions, ssdf, cisa, saQuestions, scannerSignatures)

	poamIDByCheckRepo := map[string]string{}
	for _, f := range assignFindings(pack, ssdf, cisa) {
		poamIDByCheckRepo[f.Result.CheckID+"\x00"+f.Result.Scope.Repo] = f.ID
	}

	resultsByCheck := map[string][]model.CheckResult{}
	for _, r := range pack.Results {
		ctx.StatusCounts[r.Status]++
		resultsByCheck[r.CheckID] = append(resultsByCheck[r.CheckID], r)

		switch r.Status {
		case model.StatusVerifiedFail, model.StatusPartial:
			ctx.Gaps = append(ctx.Gaps, gapView{
				Result: r, POAMID: poamIDByCheckRepo[r.CheckID+"\x00"+r.Scope.Repo],
				ScopeLabel: scopeLabel(r.Scope, r.CheckID, scopeLevelByCheckID),
			})
		case model.StatusNotCheckable:
			ctx.NotCheckable = append(ctx.NotCheckable, notCheckableView{
				Result: r, ScopeLabel: scopeLabel(r.Scope, r.CheckID, scopeLevelByCheckID),
			})
		}
	}
	sort.Slice(ctx.Gaps, func(i, j int) bool {
		if ctx.Gaps[i].Result.CheckID != ctx.Gaps[j].Result.CheckID {
			return ctx.Gaps[i].Result.CheckID < ctx.Gaps[j].Result.CheckID
		}
		return ctx.Gaps[i].Result.Scope.Repo < ctx.Gaps[j].Result.Scope.Repo
	})
	sort.Slice(ctx.NotCheckable, func(i, j int) bool {
		if ctx.NotCheckable[i].Result.CheckID != ctx.NotCheckable[j].Result.CheckID {
			return ctx.NotCheckable[i].Result.CheckID < ctx.NotCheckable[j].Result.CheckID
		}
		return ctx.NotCheckable[i].Result.Scope.Repo < ctx.NotCheckable[j].Result.Scope.Repo
	})

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
