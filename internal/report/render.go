package report

import (
	"bytes"
	"embed"
	"fmt"
	htmltemplate "html/template"
	texttemplate "text/template"
	"time"

	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/mdescape"
	"github.com/sioakim/attestward/internal/model"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

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
// alone).
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
// check does, and Scope.Project can't disambiguate them either — the
// orchestrator stamps it onto every result from an ADO scan regardless of
// the check's own scope level. A missing map entry defaults to the
// org-level label. Returns a plain, unescaped string, same as Scope.Repo
// itself (report.html auto-escapes; report.md/poam.md wrap it in esc()).
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
// classification, verbose wording to match poam.md's prose "**Repo:**"
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

// RenderMarkdown renders pack as report.md. ssdf/cisa/saQuestions may be
// nil — see buildContext's doc comment for how missing mapping data
// degrades (bare IDs, no version-mismatch detection) rather than failing.
// scopeLevelByCheckID may be nil (every Repo-empty result degrades to the
// org-level label) — see buildContext's and scopeLabel's own doc comments.
func RenderMarkdown(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions, scopeLevelByCheckID map[string]string) ([]byte, error) {
	ctx := buildContext(pack, ssdf, cisa, saQuestions, scopeLevelByCheckID)

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
func RenderHTML(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions, scopeLevelByCheckID map[string]string) ([]byte, error) {
	ctx := buildContext(pack, ssdf, cisa, saQuestions, scopeLevelByCheckID)

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
