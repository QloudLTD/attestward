package report

import (
	"bytes"
	"fmt"
	texttemplate "text/template"

	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/mdescape"
	"github.com/sioakim/attestward/internal/model"
)

// poamContext is everything poam.md's template needs, precomputed once by
// buildPOAMContext — same "no lookups/branching in template text"
// discipline as renderContext.
type poamContext struct {
	Pack model.EvidencePack

	// DriftedMappingFiles — see renderContext's identical field in
	// context.go for the full doc comment; shared logic (mappingVersionMismatch),
	// duplicated field because poamContext and renderContext are otherwise
	// unrelated template-input types.
	DriftedMappingFiles []string

	TotalFindings int
	FailCount     int
	PartialCount  int

	ClusterSummaries []poamClusterSummary
	Groups           []poamGroup
	OutsideTool      []model.CheckResult
}

// poamClusterSummary is one row of the summary table — ClusterID is empty
// for the "Unmapped" catch-all bucket.
type poamClusterSummary struct {
	ClusterID    string
	Title        string
	FailCount    int
	PartialCount int
	Total        int
}

// poamGroup is one cluster's section in the Findings detail — HasCluster
// is false only for the "Unmapped" bucket (findings whose check maps to no
// SSDF task, or no task maps to any CISA cluster), which renders under a
// plain "Unmapped" heading instead of real cluster title/form text.
type poamGroup struct {
	ClusterID  string
	Title      string
	FormText   string
	HasCluster bool
	Findings   []poamFindingView
}

// poamFindingView pairs a Finding with the remediation text looked up for
// its check — Remediation comes from the caller (see RenderPOAM's doc
// comment for why it's a plain parameter, not fetched internally).
// ScopeLabel is precomputed by scopeLabelVerbose (issue #176) — see
// gapView's identical field in context.go.
type poamFindingView struct {
	Finding
	Remediation string
	ScopeLabel  string
}

// buildPOAMContext assembles a poamContext from pack plus the mapping data
// needed to group findings by cluster and cite their affected SSDF tasks.
// ssdf/cisa may each be nil — every finding just falls into the "Unmapped"
// bucket rather than panicking or erroring, matching this package's
// established nil-tolerant contract. scopeLevelByCheckID may be nil — see
// scopeLabelVerbose's doc comment.
func buildPOAMContext(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions, scannerSignatures *mapping.ScannerSignatureRegistry, remediationByCheckID, scopeLevelByCheckID map[string]string) poamContext {
	ctx := poamContext{Pack: pack}

	ctx.DriftedMappingFiles = mappingVersionMismatch(pack.MappingVersions, ssdf, cisa, saQuestions, scannerSignatures)

	findings := assignFindings(pack, ssdf, cisa)
	ctx.TotalFindings = len(findings)

	findingsByCluster := map[string][]poamFindingView{}
	failByCluster := map[string]int{}
	partialByCluster := map[string]int{}

	for _, f := range findings {
		fv := poamFindingView{
			Finding: f, Remediation: remediationByCheckID[f.Result.CheckID],
			ScopeLabel: scopeLabelVerbose(f.Result.Scope, f.Result.CheckID, scopeLevelByCheckID),
		}
		key := f.PrimaryClusterID
		findingsByCluster[key] = append(findingsByCluster[key], fv)
		switch f.Result.Status {
		case model.StatusVerifiedFail:
			failByCluster[key]++
			ctx.FailCount++
		case model.StatusPartial:
			partialByCluster[key]++
			ctx.PartialCount++
		}
	}

	if cisa != nil {
		for _, cluster := range cisa.Clusters {
			failCount, partialCount := failByCluster[cluster.ID], partialByCluster[cluster.ID]
			ctx.ClusterSummaries = append(ctx.ClusterSummaries, poamClusterSummary{
				ClusterID: cluster.ID, Title: cluster.Title,
				FailCount: failCount, PartialCount: partialCount, Total: failCount + partialCount,
			})
			if fs := findingsByCluster[cluster.ID]; len(fs) > 0 {
				ctx.Groups = append(ctx.Groups, poamGroup{
					ClusterID: cluster.ID, Title: cluster.Title, FormText: cluster.FormText,
					HasCluster: true, Findings: fs,
				})
			}
		}
	}
	if fs := findingsByCluster[""]; len(fs) > 0 {
		failCount, partialCount := failByCluster[""], partialByCluster[""]
		ctx.ClusterSummaries = append(ctx.ClusterSummaries, poamClusterSummary{
			FailCount: failCount, PartialCount: partialCount, Total: failCount + partialCount,
		})
		ctx.Groups = append(ctx.Groups, poamGroup{Findings: fs})
	}

	for _, r := range pack.Results {
		if r.Status == model.StatusSelfAttested || r.Status == model.StatusNotCheckable {
			ctx.OutsideTool = append(ctx.OutsideTool, r)
		}
	}
	sortResults(ctx.OutsideTool)

	return ctx
}

// RenderPOAM renders pack as poam.md — a draft Plan of Action & Milestones
// listing every verified-fail/partial finding, grouped by CISA form
// cluster then check ID (matching assignFindings' own ordering, so a
// finding's POAM-NNN ID always agrees with the same ID shown next to it in
// report.md's Gaps table — see Finding's doc comment).
//
// remediationByCheckID supplies each finding's suggested-remediation text,
// keyed by check ID. It's a plain parameter rather than looked up via
// collect.Lookup internally: this package must never import
// internal/collect (ADR-0005's seam), and a package-level lookup would
// also only ever be populated in a binary that already imported every
// collector package (as cmd/attestward does) — a caller builds this map from
// collect.Registered() and passes it in, keeping this renderer a pure
// function of its own inputs, testable without a live collector registry.
// A missing entry renders as "(none on file for this check)" rather than
// an empty line.
//
// scopeLevelByCheckID is the same kind of caller-built map, for the same
// ADR-0005 reason: each finding's registered scope level (see
// scopeLabelVerbose). May be nil — degrades to the org-level label.
//
// saQuestions/scannerSignatures (issue #264) are consulted only for
// DriftedMappingFiles — poam.md itself has no self-attestation
// pairing or scanner-signature content of its own to render, unlike
// report.md/report.html — so both may be nil with no other effect.
func RenderPOAM(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions, scannerSignatures *mapping.ScannerSignatureRegistry, remediationByCheckID, scopeLevelByCheckID map[string]string) ([]byte, error) {
	ctx := buildPOAMContext(pack, ssdf, cisa, saQuestions, scannerSignatures, remediationByCheckID, scopeLevelByCheckID)

	tmpl, err := texttemplate.New("poam.md.tmpl").Funcs(texttemplate.FuncMap{
		"esc":         mdescape.Escape,
		"statusLabel": statusLabel,
		"statusBadge": statusBadge,
		"fmtTime":     fmtTime,
	}).ParseFS(templatesFS, "templates/poam.md.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse poam.md template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("render poam.md: %w", err)
	}
	return buf.Bytes(), nil
}
