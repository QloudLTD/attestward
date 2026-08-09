package report

import (
	"bytes"
	"embed"
	"fmt"
	htmltemplate "html/template"
	texttemplate "text/template"
	"time"

	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/mdescape"
	"gitlab.com/sioakeim/attestward/internal/model"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

// report.html.tmpl's stylesheet annotations live here rather than as CSS
// comments inside its <style> block, because html/template runs a CSS-context
// lexer over literal <style> content as part of contextual autoescaping and
// that lexer discards /* ... */ bodies (issue #227). A comment written there
// reaches neither the rendered report.html nor anyone reading it — it is
// replaced by blank whitespace — so the annotation silently evaporates while
// still looking present in the template source.
//
// Section markers, in stylesheet order:
//
//	Tables
//	Status badges
//	Per-check evidence cards
//	Gaps and appendix
//	Methodology/status legend
//
// The three that carry reasoning rather than navigation:
//
//   - .badge — text and border pattern remain meaningful without color, so
//     the status is readable to a color-blind reader and in a monochrome
//     print of the pack.
//
//   - @page { size: Letter } — report.html is a US federal compliance
//     artifact filed alongside the CISA SSDA form, so the sheet is pinned
//     rather than inheriting the reader's locale default (A4 elsewhere).
//
//   - .note — not one of the design's tokens. cmd/attestward/report.go's
//     tamper-warning banner (withTamperBanner) and the template's own
//     mapping-version-mismatch note both hardcode class="note" for an
//     out-of-band advisory; it is styled so neither ever renders as an
//     invisible, unstyled div.
//
// Keep this list in step with the stylesheet. Nothing enforces that, which is
// the cost of the move — the alternative was annotations that are silently
// discarded, which is worse.

// statusOrder is the display order for the status-counts summary — most
// urgent first, matching mapping.Rollup's own precedence for the same
// "worst first" reasoning.
var statusOrder = []model.Status{
	model.StatusVerifiedFail,
	model.StatusPartial,
	model.StatusNotCheckable,
	model.StatusSelfAttested,
	model.StatusVerifiedPass,
}

// statusLabel is a human-readable label for a Status — used by both
// renderers so the vocabulary stays identical across formats (issue #25:
// "Status vocabulary/styling defined once").
//
// The default branch (issue #240) is reachable only by a Status this
// package's own callers never produce — model.Status's doc comment says
// "exactly these five values exist" — but a pack loaded from disk isn't
// bound by that at the Go type level, since Status is just a string
// underneath. This function does not itself guard against that: it trusts
// the caller to have already rejected an out-of-enum Status, the same way
// it already trusts the caller on schema_version (neither renderer
// re-validates the pack it's handed). cmd/attestward/report.go's runReport
// is where that trust is actually earned, via pack.ValidateAgainstSchema()
// — a caller that skips it (a future CLI subcommand, a hosted-tier
// consumer calling this package directly) reopens exactly the hole #240
// closed, since text/template's callers below interpolate this return
// value without esc, having always trusted it to be one of a handful of
// known-safe strings.
func statusLabel(s model.Status) string {
	switch s {
	case model.StatusVerifiedPass:
		return "Verified Pass"
	case model.StatusVerifiedFail:
		return "Verified Fail"
	case model.StatusPartial:
		return "Partial"
	case model.StatusSelfAttested:
		return "Self-Attested"
	case model.StatusNotCheckable:
		return "Not Checkable"
	default:
		return string(s)
	}
}

// statusBadge is a short, text-only marker for a Status — deliberately
// not an emoji (this project avoids them outside explicit request) and
// deliberately not color-only (issue #25: "status conveyed by text+icon,
// never color alone" — a colorblind reader or a black-and-white printout
// of report.html must still be able to tell statuses apart from the text
// alone). Same caller-trust contract as statusLabel's own doc comment for
// its default branch — not repeated here.
func statusBadge(s model.Status) string {
	switch s {
	case model.StatusVerifiedPass:
		return "[PASS]"
	case model.StatusVerifiedFail:
		return "[FAIL]"
	case model.StatusPartial:
		return "[PARTIAL]"
	case model.StatusSelfAttested:
		return "[SELF-ATTESTED]"
	case model.StatusNotCheckable:
		return "[NOT CHECKABLE]"
	default:
		return "[" + string(s) + "]"
	}
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

// scopeLevelProject mirrors collect.ScopeLevelProject's string value —
// duplicated rather than imported, since internal/report must never
// import internal/collect (ADR-0005).
const scopeLevelProject = "project"

// scopeLabel renders scope the way report.md's/report.html's Gaps and
// Not-Checkable tables display it: the repo name if repo-scoped, or —
// when Repo is empty — the check's own registered scope level (looked up
// in scopeLevelByCheckID, built by the caller from collect.Registered();
// this package never imports internal/collect directly), not an
// inference from (Repo, Project) presence. That inference is what
// produced issue #176: an ADO project-scoped check (e.g. C03
// env-separation) has Repo empty the same way a genuinely org-scoped
// check does, and — for this Repo-empty case specifically — Scope.Project
// can't be used to disambiguate them either: since issue #221, the
// orchestrator derives a Repo-empty result's Scope.Project FROM this
// exact scope-level registration (only ScopeLevelProject checks get one;
// a Repo-non-empty result also keeps Project, but from Repo's presence,
// not from this — see model.ScopeRef.Project's own doc comment for the
// full rule, which doesn't matter here since this function already
// returned scope.Repo for that case), so reading Project's presence here
// would just be reading back what scopeLevelByCheckID already determined.
// A missing map entry defaults to the org-level label. Returns a plain,
// unescaped string, same as Scope.Repo itself (report.html auto-escapes;
// report.md/poam.md wrap it in esc()).
func scopeLabel(scope model.ScopeRef, checkID string, scopeLevelByCheckID map[string]string) string {
	if scope.Repo != "" {
		return scope.Repo
	}
	if scopeLevelByCheckID[checkID] == scopeLevelProject {
		if scope.Project != "" {
			return "(project: " + scope.Project + ")"
		}
		return "(project)"
	}
	return "(org)"
}

// scopeLabelVerbose is scopeLabel's poam.md counterpart: same
// classification, verbose wording to match poam.md's prose "**Scope:**"
// line — a separate function, not a shared one with a bool, since the two
// renderers' wording ("(org)" vs "(org-level)") already differs.
func scopeLabelVerbose(scope model.ScopeRef, checkID string, scopeLevelByCheckID map[string]string) string {
	if scope.Repo != "" {
		return scope.Repo
	}
	if scopeLevelByCheckID[checkID] == scopeLevelProject {
		if scope.Project != "" {
			return "(project-level: " + scope.Project + ")"
		}
		return "(project-level)"
	}
	return "(org-level)"
}

func statusCountRows(counts map[model.Status]int) []statusCount {
	rows := make([]statusCount, 0, len(statusOrder))
	for _, s := range statusOrder {
		rows = append(rows, statusCount{Status: s, Count: counts[s]})
	}
	return rows
}

type statusCount struct {
	Status model.Status
	Count  int
}

// RenderMarkdown renders pack as report.md. ssdf/cisa/saQuestions/
// scannerSignatures may be nil — see buildContext's doc comment for how
// missing mapping data degrades (bare IDs, no version-mismatch detection)
// rather than failing. scopeLevelByCheckID may be nil (every Repo-empty
// result degrades to the org-level label) — see buildContext's and
// scopeLabel's own doc comments.
func RenderMarkdown(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions, scannerSignatures *mapping.ScannerSignatureRegistry, scopeLevelByCheckID map[string]string) ([]byte, error) {
	ctx := buildContext(pack, ssdf, cisa, saQuestions, scannerSignatures, scopeLevelByCheckID)

	tmpl, err := texttemplate.New("report.md.tmpl").Funcs(texttemplate.FuncMap{
		"esc":          mdescape.Escape,
		"statusLabel":  statusLabel,
		"statusBadge":  statusBadge,
		"fmtTime":      fmtTime,
		"fmtVal":       fmtFactValue,
		"facts":        buildFactsView,
		"statusCounts": statusCountRows,
	}).ParseFS(templatesFS, "templates/report.md.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse report.md template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("render report.md: %w", err)
	}
	return buf.Bytes(), nil
}

// RenderHTML renders pack as a single self-contained report.html — no
// external stylesheets, scripts, fonts, or CDN references (issue #25:
// must open correctly with no network, file:// in a browser). Every
// dynamic value goes through html/template's default contextual
// auto-escaping (never template.HTML on API-derived content), which is
// this renderer's actual injection defense — see render_test.go's hostile
// -strings fixture for the proof.
// scopeLevelByCheckID may be nil — see RenderMarkdown's identical doc
// comment.
func RenderHTML(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions, scannerSignatures *mapping.ScannerSignatureRegistry, scopeLevelByCheckID map[string]string) ([]byte, error) {
	ctx := buildContext(pack, ssdf, cisa, saQuestions, scannerSignatures, scopeLevelByCheckID)

	tmpl, err := htmltemplate.New("report.html.tmpl").Funcs(htmltemplate.FuncMap{
		"statusLabel":  statusLabel,
		"statusBadge":  statusBadge,
		"fmtTime":      fmtTime,
		"fmtVal":       fmtFactValue,
		"facts":        buildFactsView,
		"statusCounts": statusCountRows,
	}).ParseFS(templatesFS, "templates/report.html.tmpl")
	if err != nil {
		return nil, fmt.Errorf("parse report.html template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return nil, fmt.Errorf("render report.html: %w", err)
	}
	return buf.Bytes(), nil
}
