package report

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/model"
)

// richPackRemediations is the remediation text for the two checks
// rich-pack.json's Gaps actually exercise — a small, realistic stand-in
// for what a caller would build from collect.Registered() (this package
// must never import internal/collect — see RenderPOAM's doc comment).
var richPackRemediations = map[string]string{
	"C02.branch.protection-exists": "Repo Settings -> Rules -> Rulesets -> add a rule targeting the default branch.",
	"C08.actions.pinned":           "Pin every third-party action reference to a full 40-char commit SHA.",
}

func TestRenderPOAM_RichPackGolden(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, _, _ := loadRealMappings(t)

	got, err := RenderPOAM(pack, ssdf, cisa, nil, nil, richPackRemediations, nil)
	if err != nil {
		t.Fatalf("RenderPOAM: %v", err)
	}
	compareOrUpdateGolden(t, "poam.md.golden", got)
}

func TestRenderPOAM_Deterministic(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, _, _ := loadRealMappings(t)

	first, err := RenderPOAM(pack, ssdf, cisa, nil, nil, richPackRemediations, nil)
	if err != nil {
		t.Fatalf("RenderPOAM (1): %v", err)
	}
	second, err := RenderPOAM(pack, ssdf, cisa, nil, nil, richPackRemediations, nil)
	if err != nil {
		t.Fatalf("RenderPOAM (2): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two RenderPOAM calls over the identical pack produced different output")
	}
}

func TestRenderPOAM_HostileStringsRenderInert(t *testing.T) {
	pack := loadTestPack(t, "hostile-pack.json")
	ssdf, cisa, _, _ := loadRealMappings(t)

	got, err := RenderPOAM(pack, ssdf, cisa, nil, nil, nil, hostileScopeLevelByCheckID)
	if err != nil {
		t.Fatalf("RenderPOAM: %v", err)
	}
	assertNoHostileMarkers(t, "poam.md", got)
	if bytes.Contains(got, []byte("[click here](javascript:")) || bytes.Contains(got, []byte("[bomb](javascript:")) || bytes.Contains(got, []byte("[click](javascript:")) {
		t.Error("poam.md contains a live, unescaped markdown link to a javascript: URL")
	}
	// poam.md's Findings section uses scopeLabelVerbose, not scopeLabel —
	// "(project-level: " wording, not report.md's "(project: " — see
	// scopeLabelVerbose's own doc comment.
	assertHostileProjectValuesEscapedForMarkdown(t, "poam.md", "(project-level: ", got)
}

// TestRenderPOAM_CleanPackRendersNoFindingsDocument locks in issue #26's
// explicit requirement: "empty-gap case renders a 'no findings' document
// (not an empty file)". clean-pack.json has one verified-pass and one
// not-checkable result — zero verified-fail/partial.
func TestRenderPOAM_CleanPackRendersNoFindingsDocument(t *testing.T) {
	pack := loadTestPack(t, "clean-pack.json")
	ssdf, cisa, _, _ := loadRealMappings(t)

	got, err := RenderPOAM(pack, ssdf, cisa, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("RenderPOAM: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("RenderPOAM on a gap-free pack produced an empty file, want a real \"no findings\" document")
	}
	text := string(got)
	if !strings.Contains(text, "No open findings") {
		t.Errorf("expected a \"No open findings\" message, got:\n%s", text)
	}
	if strings.Contains(text, "POAM-001") {
		t.Error("clean pack shouldn't assign any POAM finding IDs")
	}
	// The not-checkable result still belongs in the outside-tool footer —
	// "no hidden unknowns" even on an otherwise clean scan.
	if !strings.Contains(text, "C09.audit.org-log-available") {
		t.Error("expected the not-checkable result in the \"Requires Attention Outside This Tool\" footer")
	}
}

// TestRenderPOAM_MappingVersionMismatchBanner_SelfAttestationOnly is
// TestRenderMarkdown_MappingVersionMismatchBanner_SelfAttestationOnly's
// poam.md twin — the other call site #265's review found untested: every
// RenderPOAM call in this file passes nil, nil for saQuestions/
// scannerSignatures, so poam.go's two new parameters were exercised by no
// test at all before this one, and read as removable dead params to a
// future cleanup. Passing the real loaded values here, with only
// self_attestation drifted, proves buildPOAMContext's wiring — not just
// mappingVersionMismatch in isolation — actually reacts to it.
func TestRenderPOAM_MappingVersionMismatchBanner_SelfAttestationOnly(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)
	pack.MappingVersions = model.MappingVersions{
		SSDF:              ssdf.Version,
		CISAForm:          cisa.Version,
		ScannerSignatures: scannerSignatures.Version,
		SelfAttestation:   saQuestions.Version + "-drifted",
	}

	got, err := RenderPOAM(pack, ssdf, cisa, saQuestions, scannerSignatures, richPackRemediations, nil)
	if err != nil {
		t.Fatalf("RenderPOAM: %v", err)
	}
	if !strings.Contains(string(got), "this pack's mapping versions do not match") {
		t.Error("poam.md doesn't show the mapping-version-mismatch banner for a pack whose self_attestation alone has drifted from what's loaded")
	}
}

func TestRenderPOAM_MissingMappingDataDegradesGracefully(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")

	got, err := RenderPOAM(pack, nil, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("RenderPOAM with nil mappings: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("RenderPOAM with nil mappings produced empty output")
	}
	text := string(got)
	if !strings.Contains(text, "attestward-demo") {
		t.Error("RenderPOAM with nil mappings lost the org name, which doesn't depend on mapping data")
	}
	if !strings.Contains(text, "Unmapped") {
		t.Error("with no CISA mapping loaded, every finding should fall into the Unmapped bucket")
	}
	if !strings.Contains(text, "POAM-001") || !strings.Contains(text, "POAM-002") {
		t.Error("findings should still get POAM IDs even without mapping data")
	}
}

// TestRenderPOAM_MissingRemediationRendersPlaceholder locks in that a
// check with no entry in remediationByCheckID renders an honest
// placeholder rather than a blank line — the caller's map may be
// incomplete (e.g. a newly added check without remediation text yet).
// TestRenderPOAM_RepoNameNotBackslashEscaped locks in the same class of
// bug PR #71 fixed for report.md: Repo must render as escaped plain text,
// not inside a backtick code span — CommonMark doesn't process backslash
// escapes inside code spans, so an underscore-containing repo name placed
// there would show a spurious literal backslash (my_repo -> `my\_repo`).
func TestRenderPOAM_RepoNameNotBackslashEscaped(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	pack.Results[1].Scope.Repo = "my_repo" // Results[1] is the verified-fail gap
	ssdf, cisa, _, _ := loadRealMappings(t)

	got, err := RenderPOAM(pack, ssdf, cisa, nil, nil, richPackRemediations, nil)
	if err != nil {
		t.Fatalf("RenderPOAM: %v", err)
	}
	if bytes.Contains(got, []byte("`my\\_repo`")) {
		t.Error("repo name was placed inside a backtick code span and backslash-escaped, which CommonMark renders with a visible literal backslash")
	}
	if !bytes.Contains(got, []byte("my\\_repo")) {
		t.Error("expected the repo name to be escaped as plain text (my\\_repo, no surrounding backticks) so CommonMark renders it as my_repo")
	}
}

func TestRenderPOAM_MissingRemediationRendersPlaceholder(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	ssdf, cisa, _, _ := loadRealMappings(t)

	got, err := RenderPOAM(pack, ssdf, cisa, nil, nil, map[string]string{}, nil)
	if err != nil {
		t.Fatalf("RenderPOAM: %v", err)
	}
	if !strings.Contains(string(got), "(none on file for this check)") {
		t.Error("expected a placeholder for a check missing from remediationByCheckID")
	}
}

// TestRenderPOAM_ProjectScopedFindingNotLabeledOrgLevel is issue #176's
// regression case for poam.md: an ADO project-scoped finding (Scope.Repo
// empty, Scope.Project set — e.g. C03 env-separation) must not render as
// "(org-level)" in a Finding's "**Scope:**" line — correct only for a
// genuinely org-level result (e.g. C01/C09). Also covers #176's
// pack-header/Summary-shows-Project requirement in the same test, since
// both exercise the identical ADO-project-scoped-pack scenario.
func TestRenderPOAM_ProjectScopedFindingNotLabeledOrgLevel(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	extra, scopeLevelByCheckID := projectScopedTestResults()
	// Only the verified-fail result becomes a Finding (assignFindings'
	// verified-fail/partial-only contract); the not-checkable one is
	// exercised by the render_test.go twins instead.
	pack.Results = append(pack.Results, extra[0])
	pack.Scope.Project = "my-project" // also covers issue #176's Summary-section requirement below
	ssdf, cisa, _, _ := loadRealMappings(t)

	got, err := RenderPOAM(pack, ssdf, cisa, nil, nil, richPackRemediations, scopeLevelByCheckID)
	if err != nil {
		t.Fatalf("RenderPOAM: %v", err)
	}
	text := string(got)

	if !strings.Contains(text, "**Project:** my-project") {
		t.Errorf("poam.md's Summary doesn't surface Pack.Scope.Project; got:\n%s", text)
	}
	if !strings.Contains(text, "- **Scope:** (project-level: my-project)") {
		t.Errorf("Finding for the project-scoped result doesn't show the project-level label; got:\n%s", text)
	}
	// rich-pack.json's own two findings are both repo-scoped, so
	// "(org-level)" appearing anywhere here can only be a mislabel.
	if strings.Contains(text, "(org-level)") {
		t.Error("the project-scoped finding's Scope line mislabels it org-level")
	}
}

// TestRenderPOAM_FindingIDsCrossLinkWithReportGaps proves issue #26's
// "cross-links: report gap list <-> POA&M finding IDs" requirement holds
// at row level: every POA&M ID shown in report.md's Gaps table names the
// SAME check and repo in poam.md's matching finding block — not just that
// the ID string appears somewhere. A second verified-fail result is added
// for the same check ID as an existing gap but a different repo: without
// this, a cross-link bug that keyed solely on check ID (ignoring repo)
// would go undetected, since every other check in rich-pack.json is
// unique — two rows would silently collapse onto one POAM ID and this
// test would still pass if it only checked "does the ID exist somewhere".
func TestRenderPOAM_FindingIDsCrossLinkWithReportGaps(t *testing.T) {
	pack := loadTestPack(t, "rich-pack.json")
	dup := pack.Results[1] // C02.branch.protection-exists on bad-repo
	if dup.CheckID != "C02.branch.protection-exists" {
		t.Fatalf("rich-pack.json's Results[1] changed to %s — update this test's duplicate-check fixture", dup.CheckID)
	}
	dup.Scope.Repo = "bad-repo-2"
	pack.Results = append(pack.Results, dup)

	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)

	reportMD, err := RenderMarkdown(pack, ssdf, cisa, saQuestions, scannerSignatures, nil)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	poamMD, err := RenderPOAM(pack, ssdf, cisa, nil, nil, richPackRemediations, nil)
	if err != nil {
		t.Fatalf("RenderPOAM: %v", err)
	}

	gapRow := regexp.MustCompile("\\| (POAM-\\d{3}) \\| `([^`]+)` \\| ([^|]+) \\|")
	gaps := gapRow.FindAllStringSubmatch(string(reportMD), -1)
	if len(gaps) == 0 {
		t.Fatal("report.md's Gaps table has no POAM rows — is rich-pack.json still gap-free?")
	}

	findingBlock := regexp.MustCompile("(?s)#### (POAM-\\d{3}): .*?\\(`([^`]+)`\\).*?- \\*\\*Scope:\\*\\* (\\S+)")
	poamByID := map[string][2]string{}
	for _, b := range findingBlock.FindAllStringSubmatch(string(poamMD), -1) {
		poamByID[b[1]] = [2]string{b[2], b[3]}
	}

	sawDuplicatedCheck := false
	seenIDs := map[string]bool{}
	for _, g := range gaps {
		id, checkID, repo := g[1], g[2], strings.TrimSpace(g[3])
		if seenIDs[id] {
			t.Errorf("POAM ID %s appears more than once in report.md's Gaps table — IDs must be unique per row", id)
		}
		seenIDs[id] = true

		got, ok := poamByID[id]
		if !ok {
			t.Errorf("report.md cites %s for %s/%s, but poam.md has no matching \"#### %s:\" finding block", id, checkID, repo, id)
			continue
		}
		if got[0] != checkID {
			t.Errorf("%s: report.md's Gaps row says check %q, poam.md's finding block says %q", id, checkID, got[0])
		}
		wantRepo := repo
		if repo == "(org)" {
			wantRepo = "(org-level)"
		}
		if got[1] != wantRepo {
			t.Errorf("%s: report.md's Gaps row says repo %q, poam.md's finding block says %q", id, repo, got[1])
		}
		if checkID == "C02.branch.protection-exists" {
			sawDuplicatedCheck = true
		}
	}
	if !sawDuplicatedCheck {
		t.Fatal("test fixture no longer includes the duplicated-check/different-repo case this test needs")
	}
}
