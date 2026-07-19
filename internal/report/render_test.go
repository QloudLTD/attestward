package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
	"github.com/sioakim/attestward/mappings"
)

var updateGolden = flag.Bool("update", false, "write golden files instead of comparing against them")

func loadTestPack(t *testing.T, name string) model.EvidencePack {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var pack model.EvidencePack
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatalf("unmarshal %s: %v", name, err)
	}
	return pack
}

// loadRealMappings loads the actual embedded mappings — used so tests
// exercise the exact same task/cluster titles a real report would show,
// not a synthetic stand-in that could drift from the real files.
func loadRealMappings(t *testing.T) (*mapping.SSDFMapping, *mapping.CISAMapping, *mapping.SelfAttestationQuestions) {
	t.Helper()
	ssdf, err := mapping.LoadSSDFFS(mappings.FS, "ssdf-800-218.yaml")
	if err != nil {
		t.Fatalf("LoadSSDFFS: %v", err)
	}
	cisa, err := mapping.LoadCISAFS(mappings.FS, "cisa-ssda-form.yaml", ssdf)
	if err != nil {
		t.Fatalf("LoadCISAFS: %v", err)
	}
	saQuestions, err := mapping.LoadSelfAttestationQuestionsFS(mappings.FS, "self-attestation-questions.yaml", ssdf)
	if err != nil {
		t.Fatalf("LoadSelfAttestationQuestionsFS: %v", err)
	}
	return ssdf, cisa, saQuestions
}

func compareOrUpdateGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to create it)", path, err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s mismatch (run with -update to refresh, then review the diff):\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

func TestRenderMarkdown_RichPackGolden(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	compareOrUpdateGolden(t, "report.md.golden", got)
}

func TestRenderHTML_RichPackGolden(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions := loadRealMappings(t)

	got, err := RenderHTML(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	compareOrUpdateGolden(t, "report.html.golden", got)
}

// TestRenderMarkdown_Deterministic and TestRenderHTML_Deterministic prove
// the renderers are genuinely pure functions of their inputs: rendering
// the identical pack twice must produce byte-identical output, matching
// this project's established determinism discipline (issue #24).
func TestRenderMarkdown_Deterministic(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions := loadRealMappings(t)

	first, err := RenderMarkdown(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderMarkdown (1): %v", err)
	}
	second, err := RenderMarkdown(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderMarkdown (2): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two RenderMarkdown calls over the identical pack produced different output")
	}
}

func TestRenderHTML_Deterministic(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions := loadRealMappings(t)

	first, err := RenderHTML(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderHTML (1): %v", err)
	}
	second, err := RenderHTML(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderHTML (2): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two RenderHTML calls over the identical pack produced different output")
	}
}

// hostileMarkers is every distinctive substring the hostile-pack.json
// fixture plants across Title/Reason/Scope/Provenance/Facts (scalar,
// list, and table-shaped) — issue #25's own acceptance criterion:
// "fixture pack with hostile strings (<script>, markdown link bombs)
// renders inert". None of these must ever appear un-neutralized in
// either renderer's output.
var hostileMarkers = []string{
	"<script>alert('repo')</script>",
	"<script>alert('title')</script>",
	"<script>alert('reason2')</script>",
	"<script>alert('scope-repo')</script>",
	"<script>alert('endpoint')</script>",
	"<script>alert('scalar')</script>",
	"<script>alert('list1')</script>",
	"<script>alert('table')</script>",
	"<script>alert('sa-reason')</script>",
	"<script>alert('sa-answer')</script>",
}

func TestRenderMarkdown_HostileStringsRenderInert(t *testing.T) {
	pack := loadTestPack(t, "hostile-pack.json")
	ssdf, cisa, saQuestions := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	assertNoHostileMarkers(t, "report.md", got)
	// The markdown-specific threat: a literal, unescaped markdown link
	// whose target is a javascript: URL would render as a clickable,
	// functional link if this markdown is later converted to HTML (e.g.
	// pasted into a GitHub issue). escapeMD must break the [...]( syntax.
	if bytes.Contains(got, []byte("[click here](javascript:")) || bytes.Contains(got, []byte("[bomb](javascript:")) || bytes.Contains(got, []byte("[click](javascript:")) {
		t.Error("report.md contains a live, unescaped markdown link to a javascript: URL")
	}
}

func TestRenderHTML_HostileStringsRenderInert(t *testing.T) {
	pack := loadTestPack(t, "hostile-pack.json")
	ssdf, cisa, saQuestions := loadRealMappings(t)

	got, err := RenderHTML(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	assertNoHostileMarkers(t, "report.html", got)
	// html/template's contextual auto-escaping is this renderer's actual
	// defense — confirm no literal "<script>" tag survived anywhere,
	// which would only be possible if some value were wrapped in
	// template.HTML (bypassing escaping) rather than interpolated plainly.
	if bytes.Contains(got, []byte("<script>")) {
		t.Error("report.html contains a literal, live <script> tag")
	}
	if bytes.Contains(got, []byte(`href="javascript:`)) {
		t.Error("report.html contains a live javascript: href")
	}
}

func assertNoHostileMarkers(t *testing.T, format string, got []byte) {
	t.Helper()
	for _, marker := range hostileMarkers {
		if bytes.Contains(got, []byte(marker)) {
			t.Errorf("%s contains un-neutralized hostile marker %q", format, marker)
		}
	}
}

// TestBuildContext_MissingMappingDataDegradesGracefully proves buildContext
// never panics or errors when ssdf/cisa/saQuestions are nil — a caller
// that couldn't load one (e.g. a version mismatch with no fallback) still
// gets a renderable, if less detailed, report.
func TestBuildContext_MissingMappingDataDegradesGracefully(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")

	md, err := RenderMarkdown(pack, nil, nil, nil)
	if err != nil {
		t.Fatalf("RenderMarkdown with nil mappings: %v", err)
	}
	if len(md) == 0 {
		t.Error("RenderMarkdown with nil mappings produced empty output")
	}
	if !strings.Contains(string(md), "attestor-demo") {
		t.Error("RenderMarkdown with nil mappings lost the org name, which doesn't depend on mapping data")
	}

	html, err := RenderHTML(pack, nil, nil, nil)
	if err != nil {
		t.Fatalf("RenderHTML with nil mappings: %v", err)
	}
	if len(html) == 0 {
		t.Error("RenderHTML with nil mappings produced empty output")
	}
}

// TestRenderHTML_NoExternalReferences locks in "must render air-gapped":
// no external stylesheet, script, font, or CDN reference anywhere. This
// checks for *active* references specifically (a <script>/<link> tag, or
// a src=/href= pointing off-page) — a URL appearing as inert human-
// readable text (e.g. an evidence_ref fact value) is legitimate data, not
// a network dependency, and must not be flagged.
func TestRenderHTML_NoExternalReferences(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions := loadRealMappings(t)

	got, err := RenderHTML(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	for _, forbidden := range []string{"<script", "<link", `src="http`, `href="http`, "@import", "url(http"} {
		if bytes.Contains(got, []byte(forbidden)) {
			t.Errorf("report.html contains %q — must be fully self-contained (no active network dependency)", forbidden)
		}
	}
}

// TestRenderMarkdown_NewlineDoesNotInjectMarkdownStructure locks in that a
// newline inside attacker-influenceable content (e.g. a Facts value pulled
// from a workflow file's `name:` field, or a Reason string) can never turn
// into real markdown block structure — headings, in particular, would let
// scanned-repo content forge a fake "Verified Pass" section or corrupt the
// Gaps table. escapeMD must neutralize \n/\r, not just markdown-inline
// syntax, since CommonMark is line-oriented and ATX headings interrupt a
// paragraph regardless of what surrounds them on adjacent lines.
func TestRenderMarkdown_NewlineDoesNotInjectMarkdownStructure(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	pack.Results[0].Reason = "line one\n\n# INJECTED HEADING MARKER\n\nline two"
	ssdf, cisa, saQuestions := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	for _, line := range strings.Split(string(got), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, "INJECTED HEADING MARKER") {
			t.Errorf("attacker-controlled newline turned into a real markdown heading line: %q", line)
		}
	}
}

// TestRenderMarkdown_CodeSpanValuesNotBackslashEscaped locks in that values
// already wrapped in backticks (Repo, CheckID, Method, Endpoint,
// ResponseSHA256) are NOT also passed through esc — CommonMark doesn't
// process backslash escapes inside code spans, so escaping there is both
// unnecessary (the backticks already make the content literal) and
// actively wrong: it leaves a visible, spurious backslash in front of any
// escapable character. Repo/org names commonly contain underscores.
func TestRenderMarkdown_CodeSpanValuesNotBackslashEscaped(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	pack.Results[0].Scope.Repo = "my_repo"
	ssdf, cisa, saQuestions := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if strings.Contains(string(got), "`my\\_repo`") {
		t.Error("repo name inside a markdown code span was corrupted by backslash-escaping")
	}
	if !strings.Contains(string(got), "`my_repo`") {
		t.Error("expected an unescaped `my_repo` code span in report.md")
	}
}

func TestRenderMarkdown_SelfAttestedPairingShowsSideBySide(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	text := string(got)
	saIdx := strings.Index(text, "SA.audit-log-export-fallback")
	if saIdx < 0 {
		t.Fatal("SA.audit-log-export-fallback not found in report.md")
	}
	pairedIdx := strings.Index(text[saIdx:], "C09.audit.org-log-available")
	if pairedIdx < 0 {
		t.Error("SA.audit-log-export-fallback's paired check C09.audit.org-log-available not shown alongside it")
	}
}
