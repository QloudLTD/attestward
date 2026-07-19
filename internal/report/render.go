package report

import (
	"bytes"
	"embed"
	"fmt"
	htmltemplate "html/template"
	texttemplate "text/template"
	"time"

	"github.com/sioakim/attestward/internal/mapping"
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
func RenderMarkdown(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions) ([]byte, error) {
	ctx := buildContext(pack, ssdf, cisa, saQuestions)

	tmpl, err := texttemplate.New("report.md.tmpl").Funcs(texttemplate.FuncMap{
		"esc":          escapeMD,
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
func RenderHTML(pack model.EvidencePack, ssdf *mapping.SSDFMapping, cisa *mapping.CISAMapping, saQuestions *mapping.SelfAttestationQuestions) ([]byte, error) {
	ctx := buildContext(pack, ssdf, cisa, saQuestions)

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
