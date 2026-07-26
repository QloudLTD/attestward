package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"html"
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
func loadRealMappings(t *testing.T) (*mapping.SSDFMapping, *mapping.CISAMapping, *mapping.SelfAttestationQuestions, *mapping.ScannerSignatureRegistry) {
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
	scannerSignatures, err := mapping.LoadScannerSignaturesFS(mappings.FS, "scanner-signatures.yaml")
	if err != nil {
		t.Fatalf("LoadScannerSignaturesFS: %v", err)
	}
	return ssdf, cisa, saQuestions, scannerSignatures
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
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	compareOrUpdateGolden(t, "report.md.golden", got)
}

func TestRenderHTML_RichPackGolden(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderHTML(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
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
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	first, err := RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
	if err != nil {
		t.Fatalf("RenderMarkdown (1): %v", err)
	}
	second, err := RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
	if err != nil {
		t.Fatalf("RenderMarkdown (2): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two RenderMarkdown calls over the identical pack produced different output")
	}
}

func TestRenderHTML_Deterministic(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	first, err := RenderHTML(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
	if err != nil {
		t.Fatalf("RenderHTML (1): %v", err)
	}
	second, err := RenderHTML(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
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
//
// Found in review of #222: this claim was FALSE for years without any test
// catching it. hostile-pack.json's main result originally used a made-up
// check_id ("C99.hostile.check") cited by no real SSDF task, and
// context.go's Cluster Detail block (report.md/html's Scope.Repo/
// Provenance/Facts rendering — the only place most of these markers could
// ever appear) is driven off task.Checks: an unmapped result never reaches
// it, only the Gaps table. 3 of these 12 markers (scalar/list1/table) were
// therefore never emitted in ANY format, and the whole Facts-escaping path
// passed vacuously — undetected until report.md.tmpl's own Scope.Repo/
// Provenance lines turned out to be genuinely unescaped (see
// TestRenderMarkdown_ProvenanceAndRepoEscapedNotCodeSpan). Fixed for those
// three by giving the main hostile result a real, SSDF-cited check_id
// (C02.branch.protection-exists) so every field it plants actually reaches
// the Cluster Detail block this test relies on.
//
// A 4th marker, sa-answer, is NOT fixed by that and never will be by a
// check_id change alone (found in round 2 of the same review): it lives
// on a separate result (SA.hostile-question, self-attested, its own
// check_id still made up) whose Facts.answer field plants it. Both
// report.md.tmpl's and report.html.tmpl's Self-Attested block render only
// CheckID/Status/Title/Reason/Paired for a self-attested entry — never
// Facts, at all, for any check_id — so sa-answer is structurally
// unreachable through either renderer as they exist today, not merely
// unexercised by this fixture. A real fix would need a template change,
// not a fixture one; out of scope here.
//
// Issue #231 added the seven pack-level (header-block) markers below —
// tool-version/ssdfversion/cisaversion/scannerversion/selfattestversion/org/
// releasetag. Unlike every marker above (which lives on a per-result field,
// reached only through the Cluster Detail/Gaps/Self-Attested machinery
// #222 fixed), these reach report.md/poam.md's Summary section directly
// from Pack itself — a separate render path this list previously had zero
// coverage of, which is exactly how report.md.tmpl:7/poam.md.tmpl:13's Org
// interpolation and report.md.tmpl:110's release-tag-pattern code span
// went unescaped for as long as they did.
var hostileMarkers = []string{
	"<script>alert('repo')</script>",
	"<script>alert('title')</script>",
	"<img src=x onerror=alert('reason2')>",
	"<script>alert('scope-repo')</script>",
	"<script>alert('endpoint')</script>",
	"<script>alert('scalar')</script>",
	"<script>alert('list1')</script>",
	"<script>alert('table')</script>",
	"<script>alert('sa-reason')</script>",
	"<script>alert('sa-answer')</script>",
	"<script>alert('toolversion')</script>",
	"<script>alert('ssdfversion')</script>",
	"<script>alert('cisaversion')</script>",
	"<script>alert('scannerversion')</script>",
	"<script>alert('selfattestversion')</script>",
	"<script>alert('org')</script>",
	"<script>alert('releasetag')</script>",
	hostilePackProjectValue,
	hostileScopeProjectValue,
}

// hostilePackProjectValue/hostileScopeProjectValue are hostile-pack.json's
// two Project values, decoded — issue #216: before this, hostile-pack.json
// had no "project" key at all, so neither the three Pack.Scope.Project
// header rows (report.md/report.html/poam.md each show one) nor the
// "(project: " + Project + ")" concatenation in scopeLabel/scopeLabelVerbose
// were exercised by the hostile-strings regression tests. Each value packs
// five different threats into one string, since md/html/poam.md escape
// them differently and each needs to hold independently: a quote plus an
// HTML-attribute-breakout attempt (" onmouseover="alert(...) — harmless
// here because Pack.Scope.Project/ScopeLabel are always interpolated in a
// text node, never inside a tag attribute, but only html/template's
// auto-escaping guarantees that, not this codebase's own code); a
// Markdown table-breaking pipe; a backtick (breaks a code span, and — with
// the pipe — could otherwise splice a fake table cell); and a real
// newline (schema places no restriction on it — could otherwise forge a
// new table/list row if mdescape didn't flatten it). hostilePackProjectValue
// is hostile-pack.json's top-level scope.project (the three header rows);
// hostileScopeProjectValue is C99.hostile.project-scope's per-result
// scope.project (the scopeLabel/scopeLabelVerbose concatenation) — distinct
// strings so a test failure names which of the two broke.
const (
	hostilePackProjectValue  = "pack-project\" onmouseover=\"alert('pack-project')|`code-span-break`\nsecond-line-pack-project"
	hostileScopeProjectValue = "scope-project\" onmouseover=\"alert('scope-project')|`code-span-break`\nsecond-line-scope-project"
)

// hostileScopeLevelByCheckID classifies C99.hostile.project-scope (the
// result carrying hostileScopeProjectValue) as project-scoped — passing
// nil here, as the rest of this file's hostile-string tests otherwise
// would, leaves every Repo-empty result classified org-scoped by default
// (scopeLabel's own zero-value behavior), which never reaches the
// "(project: " + Project + ")" concatenation at all. See CheckMeta.ScopeLevel
// (#176) for why a real pack needs the registry for this and a synthetic
// fixture like this one can just hand-build the map.
var hostileScopeLevelByCheckID = map[string]string{
	"C99.hostile.project-scope": scopeLevelProject,
}

func TestRenderMarkdown_HostileStringsRenderInert(t *testing.T) {
	pack := loadTestPack(t, "hostile-pack.json")
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, hostileScopeLevelByCheckID)
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
	assertHostileProjectValuesEscapedForMarkdown(t, "report.md", "(project: ", got)
}

func TestRenderHTML_HostileStringsRenderInert(t *testing.T) {
	pack := loadTestPack(t, "hostile-pack.json")
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderHTML(pack, ssdf, cisa, saQuestions, scannerSignatures, hostileScopeLevelByCheckID)
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
	assertHostileProjectValuesEscapedForHTML(t, "report.html", got)
}

// hostilePackProjectValueEscaped/hostileScopeProjectValueEscaped are
// hostilePackProjectValue/hostileScopeProjectValue's expected mdescape.Escape
// output, HAND-WRITTEN rather than computed by calling Escape on the raw
// value — issue #222's review finding: computing "expected" via the same
// function under test is self-referential and structurally can't fail the
// way its own doc comment claimed. Proven by mutation: deleting the pipe
// rule from escaper left ./internal/report/... green with the
// self-referential version; deleting the backtick rule left the ENTIRE
// repo test suite green (nothing else in this codebase pins mdescape's
// per-rule behavior — see internal/mdescape/mdescape_test.go, added in the
// same review round, which independently confirms these two literals).
// Kept as package-level consts, not recomputed per test, so both
// assertHostileProjectValuesEscapedForMarkdown call sites (report.md and
// poam.md) check against the identical hand-written string.
const (
	hostilePackProjectValueEscaped  = "pack-project\" onmouseover=\"alert('pack-project')\\|\\`code-span-break\\` second-line-pack-project"
	hostileScopeProjectValueEscaped = "scope-project\" onmouseover=\"alert('scope-project')\\|\\`code-span-break\\` second-line-scope-project"
)

// assertHostileProjectValuesEscapedForMarkdown proves the "esc" template
// func report.md/poam.md both use (mdescape.Escape) actually neutralizes
// EVERY threat class hostilePackProjectValue/hostileScopeProjectValue pack
// in — not just that hostileMarkers' whole-string check finds the combined
// value altered somewhere, which a bug in only one of the five escapes
// (e.g. pipe) could still pass if another one (e.g. backtick) still
// changed. scopeLabelPrefix is "(project: " (report.md's scopeLabel) or
// "(project-level: " (poam.md's scopeLabelVerbose) — the two renderers'
// wording already differs (see scopeLabelVerbose's own doc comment), so
// the caller says which shape applies.
func assertHostileProjectValuesEscapedForMarkdown(t *testing.T, format, scopeLabelPrefix string, got []byte) {
	t.Helper()
	// "- **Project:** " + escaped value, not wrapped in parens — that shape
	// is scopeLabel's, not the header row's — so the raw escaped substring
	// is what to look for here.
	if !bytes.Contains(got, []byte(hostilePackProjectValueEscaped)) {
		t.Errorf("%s: expected the Project header row to contain the escaped pack project value; want %q", format, hostilePackProjectValueEscaped)
	}
	wantScope := scopeLabelPrefix + hostileScopeProjectValueEscaped + ")"
	if !bytes.Contains(got, []byte(wantScope)) {
		t.Errorf("%s: expected a scope-label cell reading %q — table integrity around the raw pipe/backtick/newline may have broken", format, wantScope)
	}
}

// assertHostileProjectValuesEscapedForHTML is the HTML twin: html/template
// auto-escapes {{.Pack.Scope.Project}}/{{.ScopeLabel}} because both are
// always interpolated in a text node in report.html.tmpl, never inside a
// tag attribute — confirm the attribute-breakout attempt specifically
// never produces a live attribute (the raw `" onmouseover="` sequence must
// not survive), independent of the whole-string hostileMarkers check.
//
// The backtick/pipe/newline in hostilePackProjectValue/hostileScopeProjectValue
// are deliberately NOT checked here: unlike Markdown, HTML attributes no
// special meaning to any of the three in a text node, so html/template
// leaves them raw (confirmed empirically) — correct, not a gap. Only `<`,
// `>`, `&`, `'`, `"` matter for HTML, which is why this fixture's HTML
// coverage rests on the quote-based attribute-breakout attempt specifically.
//
// wantScopeSubstring proves the scope-label concatenation was actually
// exercised (not skipped, e.g. because scopeLevelByCheckID was nil/wrong,
// which would render "(org)" and never touch hostileScopeProjectValue at
// all — a gap the whole-string hostileMarkers check alone can't catch,
// since "value absent because the check was misclassified org-scoped"
// and "value absent because it was escaped away" both look like
// "marker not found").
func assertHostileProjectValuesEscapedForHTML(t *testing.T, format string, got []byte) {
	t.Helper()
	if bytes.Contains(got, []byte(`" onmouseover="alert(`)) {
		t.Errorf("%s contains a live, unescaped onmouseover attribute breakout from a hostile Project value", format)
	}
	wantScopeSubstring := "(project: " + html.EscapeString("scope-project\" onmouseover=\"alert('scope-project')") + "|`code-span-break`"
	if !bytes.Contains(got, []byte(wantScopeSubstring)) {
		t.Errorf("%s: expected a scope-label cell containing %q — the project-scope concatenation may not have been exercised at all", format, wantScopeSubstring)
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

	md, err := RenderMarkdown(pack, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("RenderMarkdown with nil mappings: %v", err)
	}
	if len(md) == 0 {
		t.Error("RenderMarkdown with nil mappings produced empty output")
	}
	if !strings.Contains(string(md), "attestward-demo") {
		t.Error("RenderMarkdown with nil mappings lost the org name, which doesn't depend on mapping data")
	}

	html, err := RenderHTML(pack, nil, nil, nil, nil, nil)
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
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderHTML(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	for _, forbidden := range []string{"<script", "<link", `src="http`, `href="http`, "@import", "url(http"} {
		if bytes.Contains(got, []byte(forbidden)) {
			t.Errorf("report.html contains %q — must be fully self-contained (no active network dependency)", forbidden)
		}
	}
}

// TestRenderHTML_PrintsToUSLetter locks in that report.html paginates to US
// Letter, not the reader's locale default. This is a US federal compliance
// artifact filed alongside the CISA SSDA form; an @page that fell back to
// `size: auto` would silently print A4 for anyone whose printer/PDF default
// is A4, so the intent is pinned here explicitly rather than left to the
// golden file (which would catch the change but not explain why it matters).
func TestRenderHTML_PrintsToUSLetter(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderHTML(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	html := string(got)
	if !strings.Contains(html, "@media print") {
		t.Fatal("report.html has no @media print block — the printed artifact is unstyled")
	}
	if !strings.Contains(html, "size: Letter") {
		t.Error("report.html @page does not pin `size: Letter` — it will inherit the reader's locale paper size (A4 outside the US)")
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
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
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

// TestRenderMarkdown_ProvenanceAndRepoEscapedNotCodeSpan is issue #222's
// own review finding: the Cluster Detail block's inline "Repo: ..." mention
// and its Evidence line (Method/Endpoint/ResponseSHA256) reached output
// completely unescaped and NOT inside a code span either — a real
// injection hole (poam.md already escaped the identical fields; report.md
// didn't, an oversight, not a design choice). The fix mirrors poam.md's own
// established pattern exactly (see TestRenderPOAM_RepoNameNotBackslashEscaped):
// escaped plain text, no surrounding backticks — CommonMark doesn't process
// backslash escapes inside a code span, so escaping AND keeping backticks
// would produce a visible, spurious backslash instead of neutralizing
// anything. CheckID, on the same block's heading line, is deliberately
// left as-is (still a raw, unescaped code span): unlike Repo/Method/
// Endpoint/ResponseSHA256, it's never attacker-influenced — every real
// value is a Go source string literal a collector registers (see
// collect.CheckMeta.ID), never derived from scanned repo/org data, so
// there's no hole there to fix, and no natural test for it either — real
// check IDs never contain a character esc would touch (dot/hyphen-
// separated only, by this project's own naming convention).
//
// The framing that matters, because the earlier version of this test got it
// wrong and pinned the wrong behaviour as intentional: the choice was never
// "escape or don't". It was "code span or escaped plain text". A code span is
// a security boundary only if the value cannot contain a backtick — and a
// repo or Azure DevOps project name can, so it never was one. Escaping
// inside the span was rejected for a real reason (CommonMark does not process
// backslash escapes there, so it shows a spurious backslash), but the
// conclusion drawn from that — drop the escaping, keep the span — traded an
// injection hole for cosmetics. Plain escaped text satisfies both.
func TestRenderMarkdown_ProvenanceAndRepoEscapedNotCodeSpan(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	pack.Results[0].Scope.Repo = "my_repo"
	pack.Results[0].Provenance = []model.Provenance{
		{Endpoint: "/repos/attestward-demo/my_repo/rulesets", Method: "GET", HTTPStatus: 200, ResponseSHA256: strings.Repeat("a", 64)},
	}
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	text := string(got)

	if strings.Contains(text, "`my_repo`") {
		t.Error("Repo is still rendered inside a raw, unescaped code span — the injection hole issue #222's review found is still open")
	}
	if strings.Contains(text, "Repo: my_repo.") {
		t.Error("Repo reached output completely unescaped (not even backslash-escaped) — an underscore alone wouldn't prove this, but a hostile marker would; this asserts the literal raw form never appears")
	}
	if !strings.Contains(text, "Repo: my\\_repo.") {
		t.Errorf("expected the repo name escaped as plain text (my\\_repo, no surrounding backticks); got:\n%s", text)
	}
	if strings.Contains(text, "`GET /repos/attestward-demo/my_repo/rulesets`") {
		t.Error("Evidence line's Method/Endpoint are still rendered inside a raw, unescaped code span")
	}
	if !strings.Contains(text, "GET /repos/attestward-demo/my\\_repo/rulesets at") {
		t.Errorf("expected the Evidence line's Method/Endpoint escaped as plain text, no surrounding backticks; got:\n%s", text)
	}
}

// projectScopedTestResults returns two Azure DevOps project-scoped
// CheckResults (Scope.Repo empty, Scope.Project set) — one verified-fail
// (Gaps table), one not-checkable (Not Checkable table) — plus the
// scopeLevelByCheckID map a caller would build from collect.Registered()
// for them. Both check IDs are real, mapped C03 env-separation checks
// (issue #176's own motivating example), not invented ones.
func projectScopedTestResults() ([]model.CheckResult, map[string]string) {
	results := []model.CheckResult{
		{
			CheckID: "C03.env.exists", Title: "At least one environment exists",
			Status: model.StatusVerifiedFail, Reason: "no environments found in this project",
			Scope: model.ScopeRef{Org: "attestward-demo", Project: "my-project", Platform: "azuredevops"},
		},
		{
			CheckID: "C03.env.protection-rules", Title: "Environments have protection rules",
			Status: model.StatusNotCheckable, Reason: "could not list environments (403)",
			Scope: model.ScopeRef{Org: "attestward-demo", Project: "my-project", Platform: "azuredevops"},
		},
	}
	scopeLevelByCheckID := map[string]string{
		"C03.env.exists":           "project",
		"C03.env.protection-rules": "project",
	}
	return results, scopeLevelByCheckID
}

// assertScopeLabelPrecise fails the test unless text contains want but not
// wrong — used by both the markdown and html project-scope-labeling tests
// below to check the exact checkID-cell-then-scope-cell shape, not every
// line mentioning the check ID (report.md's Cluster Detail section, and
// report.html's <code> headings, also name these IDs — deliberately
// untouched by #176 — and would otherwise produce a false failure here).
func assertScopeLabelPrecise(t *testing.T, text, label, want, wrong string) {
	t.Helper()
	if !strings.Contains(text, want) {
		t.Errorf("%s row for the project-scoped result = missing %q; got:\n%s", label, want, text)
	}
	if strings.Contains(text, wrong) {
		t.Errorf("%s row for the project-scoped result mislabels it org-level", label)
	}
}

// TestRenderMarkdown_ProjectScopedResultsNotLabeledOrgLevel is issue #176's
// regression case: an ADO project-scoped result (Scope.Repo empty,
// Scope.Project set — e.g. C03 env-separation) must not render as "(org)"
// in report.md's Gaps or Not Checkable tables — correct only for a
// genuinely org-level result (e.g. C01/C09, also Scope.Repo empty). Also
// covers #176's pack-header-shows-Project requirement in the same test,
// since both exercise the identical ADO-project-scoped-pack scenario.
func TestRenderMarkdown_ProjectScopedResultsNotLabeledOrgLevel(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	extra, scopeLevelByCheckID := projectScopedTestResults()
	pack.Results = append(pack.Results, extra...)
	pack.Scope.Project = "my-project" // also covers issue #176's pack-header requirement below
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, scopeLevelByCheckID)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	text := string(got)

	if !strings.Contains(text, "**Project:** my-project") {
		t.Errorf("report.md's Executive Summary doesn't surface Pack.Scope.Project; got:\n%s", text)
	}
	assertScopeLabelPrecise(t, text, "Gaps", "`C03.env.exists` | (project: my-project) |", "`C03.env.exists` | (org) |")
	assertScopeLabelPrecise(t, text, "Not Checkable", "`C03.env.protection-rules` | (project: my-project) |", "`C03.env.protection-rules` | (org) |")
}

// TestRenderHTML_ProjectScopedResultsNotLabeledOrgLevel is report.html's
// twin of TestRenderMarkdown_ProjectScopedResultsNotLabeledOrgLevel — the
// issue calls out "the html template needs the same treatment as the
// markdown one" explicitly, and report.html carries the identical "(org)"
// literal. Also covers the pack-header Project row, same rationale.
func TestRenderHTML_ProjectScopedResultsNotLabeledOrgLevel(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	extra, scopeLevelByCheckID := projectScopedTestResults()
	pack.Results = append(pack.Results, extra...)
	pack.Scope.Project = "my-project" // also covers issue #176's pack-header requirement below
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderHTML(pack, ssdf, cisa, saQuestions, scannerSignatures, scopeLevelByCheckID)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	text := string(got)

	if !strings.Contains(text, `<th scope="row">Project</th><td>my-project</td>`) {
		t.Errorf("report.html's scope table doesn't surface Pack.Scope.Project; got:\n%s", text)
	}
	assertScopeLabelPrecise(t, text, "Gaps", "<code>C03.env.exists</code></td><td>(project: my-project)</td>", "<code>C03.env.exists</code></td><td>(org)</td>")
	assertScopeLabelPrecise(t, text, "Not Checkable", "<code>C03.env.protection-rules</code></td><td>(project: my-project)</td>", "<code>C03.env.protection-rules</code></td><td>(org)</td>")
}

// TestRenderMarkdown_MappingVersionMismatchBanner_SelfAttestationOnly proves
// buildContext's self_attestation/scanner_signatures wiring is genuinely
// exercised through RenderMarkdown end-to-end, not just by
// mappingVersionMismatch in isolation (#265's review: mutating both call
// sites to mappingVersionMismatch(pack.MappingVersions, ssdf, cisa, nil, nil)
// — a full revert of #264's user-visible behavior — left go test green,
// because every existing fixture already mismatches on ssdf, so the banner
// already fired for an unrelated reason and masked whether the new
// parameters do anything). rich-pack.json's own ssdf/cisa_form/
// scanner_signatures are overridden here to match what's actually loaded;
// only self_attestation is drifted, isolating the one field the old,
// two-field-only comparison could never catch.
func TestRenderMarkdown_MappingVersionMismatchBanner_SelfAttestationOnly(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)
	pack.MappingVersions = model.MappingVersions{
		SSDF:              ssdf.Version,
		CISAForm:          cisa.Version,
		ScannerSignatures: scannerSignatures.Version,
		SelfAttestation:   saQuestions.Version + "-drifted",
	}

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	if !strings.Contains(string(got), "this pack's mapping versions do not match") {
		t.Error("report.md doesn't show the mapping-version-mismatch banner for a pack whose self_attestation alone has drifted from what's loaded")
	}
}

func TestRenderMarkdown_SelfAttestedPairingShowsSideBySide(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	got, err := RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
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
