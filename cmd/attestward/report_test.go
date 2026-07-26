package main

import (
	"bytes"
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/integrity"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
	"github.com/sioakim/attestward/internal/report"
	"github.com/sioakim/attestward/mappings"
)

// reportFixturePack has one verified-fail (so poam.md has content to
// render) and one verified-pass, giving both renderers something
// non-trivial to exercise without pulling in a full demo-org-scale pack.
// CheckID values must be real, registered check IDs (not made up) — poam.md
// looks up remediation text by CheckID, and TestRunReport_PoamIncludesRealRemediationText
// depends on this fixture's fail actually resolving to a real, non-empty
// remediation string, not a lookup miss that happens to render as blank.
func reportFixturePack() model.EvidencePack {
	return model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "attestward-demo", Repos: []string{"good-repo"}},
		Results: []model.CheckResult{
			{
				CheckID: "C01.org.2fa-required",
				Title:   "Org requires two-factor authentication",
				Status:  model.StatusVerifiedFail,
				Reason:  "org does not enforce 2FA for members",
				Scope:   model.ScopeRef{Org: "attestward-demo"},
				Provenance: []model.Provenance{
					{Endpoint: "/orgs/attestward-demo", Method: "GET", HTTPStatus: 200, ResponseSHA256: strings.Repeat("a", 64)},
				},
			},
			{
				CheckID: "C02.branch.required-reviews",
				Title:   "Branch protection requires reviews",
				Status:  model.StatusVerifiedPass,
				Reason:  "main requires 1 approving review",
				Scope:   model.ScopeRef{Org: "attestward-demo", Repo: "good-repo"},
				Provenance: []model.Provenance{
					{Endpoint: "/repos/attestward-demo/good-repo/rulesets", Method: "GET", HTTPStatus: 200, ResponseSHA256: strings.Repeat("b", 64)},
				},
			},
		},
	}
}

// writeReportFixture writes a fixture pack (and, if withSidecar, its
// .sha256) into dir and returns the evidence.json path and its hash.
func writeReportFixture(t *testing.T, dir string, withSidecar bool) (path, hash string) {
	t.Helper()
	pack := reportFixturePack()
	hash, err := writeEvidencePack(pack, dir)
	if err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}
	path = filepath.Join(dir, "evidence.json")
	if withSidecar {
		if err := integrity.WriteSidecar(path, hash); err != nil {
			t.Fatalf("WriteSidecar: %v", err)
		}
	}
	return path, hash
}

func loadReportMappings(t *testing.T) (*mapping.SSDFMapping, *mapping.CISAMapping, *mapping.SelfAttestationQuestions) {
	t.Helper()
	ssdf, err := mapping.LoadSSDFFS(mappings.FS, "ssdf-800-218.yaml")
	if err != nil {
		t.Fatalf("load ssdf mapping: %v", err)
	}
	cisa, err := mapping.LoadCISAFS(mappings.FS, "cisa-ssda-form.yaml", ssdf)
	if err != nil {
		t.Fatalf("load cisa mapping: %v", err)
	}
	saQuestions, err := mapping.LoadSelfAttestationQuestionsFS(mappings.FS, "self-attestation-questions.yaml", ssdf)
	if err != nil {
		t.Fatalf("load self-attestation questions: %v", err)
	}
	return ssdf, cisa, saQuestions
}

// TestRunReport_ByteIdenticalToDirectRenderersCall is issue #28's own named
// proof: attestward report's file-reading/mapping-loading/writing pipeline
// must not introduce any drift versus calling internal/report's renderers
// directly on the same in-memory pack — the whole point of #25/#26 having
// kept those renderers pure functions of evidence.json.
func TestRunReport_ByteIdenticalToDirectRenderersCall(t *testing.T) {
	dir := t.TempDir()
	path, hash := writeReportFixture(t, dir, false)
	pack := reportFixturePack()
	// runReport always sets Pack.Integrity.SHA256 to the hash of the exact
	// bytes it read (see report.go) before rendering — replicate that here
	// so this comparison exercises the real behavior instead of failing on
	// a field runReport populates that a bare in-memory pack never would.
	pack.Integrity = &model.Integrity{SHA256: hash}

	ssdf, cisa, saQuestions := loadReportMappings(t)
	remediationByCheckID := map[string]string{}
	for _, meta := range collect.Registered() {
		remediationByCheckID[meta.ID] = meta.Remediation
	}
	// Built through the SAME per-platform resolution production uses, not by
	// flat-ranging Registered(). A flat range is last-wins per ID, and 10 of
	// the 11 project-scoped ADO checks also exist on GitHub with the zero
	// value — so it would silently agree with production today (Registered()
	// sorts platform-then-ID, and this fixture pack is GitHub) while losing
	// the ability to detect a buildScopeLevelByCheckID that ignores platform.
	// That is precisely the divergence this test is named for.
	scopeLevelByCheckID := buildScopeLevelByCheckID(pack.Results, collect.LookupPlatform)

	wantMD, err := report.RenderMarkdown(pack, ssdf, cisa, saQuestions, scopeLevelByCheckID)
	if err != nil {
		t.Fatalf("RenderMarkdown: %v", err)
	}
	wantHTML, err := report.RenderHTML(pack, ssdf, cisa, saQuestions, scopeLevelByCheckID)
	if err != nil {
		t.Fatalf("RenderHTML: %v", err)
	}
	wantPOAM, err := report.RenderPOAM(pack, ssdf, cisa, remediationByCheckID, scopeLevelByCheckID)
	if err != nil {
		t.Fatalf("RenderPOAM: %v", err)
	}

	outDir := t.TempDir()
	if err := runReport(context.Background(), &bytes.Buffer{}, path, outDir, []string{"md", "html", "poam"}, false); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	for name, want := range map[string][]byte{"report.md": wantMD, "report.html": wantHTML, "poam.md": wantPOAM} {
		got, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: attestward report output differs from a direct renderer call\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
		}
	}
}

// TestRunReport_PoamIncludesRealRemediationText proves runReport's
// remediationByCheckID map is actually built from a live, populated
// collect.Registered() — not just present but empty. Without this, the
// round-trip test above can't tell "the registry is wired correctly" from
// "the registry is broken and both sides of the comparison degraded to
// empty remediations identically" — a fixture using a made-up CheckID
// would pass that test either way.
func TestRunReport_PoamIncludesRealRemediationText(t *testing.T) {
	const wantCheckID = "C01.org.2fa-required"
	meta, ok := collect.Lookup(wantCheckID)
	if !ok || meta.Remediation == "" {
		t.Fatalf("collect.Lookup(%q) has no remediation text — fixture or registry drifted, update this test", wantCheckID)
	}

	dir := t.TempDir()
	path, _ := writeReportFixture(t, dir, false)
	outDir := t.TempDir()
	if err := runReport(context.Background(), &bytes.Buffer{}, path, outDir, []string{"poam"}, false); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(outDir, "poam.md"))
	if err != nil {
		t.Fatalf("read poam.md: %v", err)
	}
	if !bytes.Contains(got, []byte(meta.Remediation)) {
		t.Errorf("poam.md does not contain %s's real remediation text (%q) — remediationByCheckID may not be wired to a live collect.Registered()", wantCheckID, meta.Remediation)
	}
}

// TestBuildRemediationByCheckID_ResolvesPerResultsOwnPlatform proves the
// fix for the last-write-wins bug review of #164 found: two platforms
// registering the same check ID with different remediation text must each
// resolve correctly via the RESULT's own Scope.Platform, not collapse to
// whichever platform a naive collect.Registered()-wholesale map happened to
// visit last. Uses a synthetic lookup function rather than collect.Register
// — registering a fake check into the real global registry would corrupt
// other tests in this package that assert an exact collect.Registered()
// count (e.g. TestAllC01ThroughC10ChecksHaveRemediation).
func TestBuildRemediationByCheckID_ResolvesPerResultsOwnPlatform(t *testing.T) {
	lookup := func(platform, id string) (collect.CheckMeta, bool) {
		if platform == "" {
			platform = "github"
		}
		switch {
		case platform == "github" && id == "TEST.dual":
			return collect.CheckMeta{Remediation: "Fix it the GitHub way."}, true
		case platform == "azuredevops" && id == "TEST.dual":
			return collect.CheckMeta{Remediation: "Fix it the Azure DevOps way."}, true
		default:
			return collect.CheckMeta{}, false
		}
	}

	githubResults := []model.CheckResult{{CheckID: "TEST.dual", Scope: model.ScopeRef{Platform: "github"}}}
	if got := buildRemediationByCheckID(githubResults, lookup)["TEST.dual"]; got != "Fix it the GitHub way." {
		t.Errorf("github remediation = %q, want the github text", got)
	}

	adoResults := []model.CheckResult{{CheckID: "TEST.dual", Scope: model.ScopeRef{Platform: "azuredevops"}}}
	if got := buildRemediationByCheckID(adoResults, lookup)["TEST.dual"]; got != "Fix it the Azure DevOps way." {
		t.Errorf("azuredevops remediation = %q, want the Azure DevOps text", got)
	}

	// A pre-#164 pack has no Platform field at all — must fall back to
	// github, same convention as LookupPlatform itself.
	absentPlatformResults := []model.CheckResult{{CheckID: "TEST.dual", Scope: model.ScopeRef{}}}
	if got := buildRemediationByCheckID(absentPlatformResults, lookup)["TEST.dual"]; got != "Fix it the GitHub way." {
		t.Errorf("absent-platform remediation = %q, want the github text (absent falls back to github)", got)
	}

	// A check with no registered metadata for its result's platform gets no
	// entry at all (not a zero-value empty string) — RenderPOAM's own
	// missing-entry contract renders a placeholder for that.
	unknownResults := []model.CheckResult{{CheckID: "TEST.unknown", Scope: model.ScopeRef{Platform: "azuredevops"}}}
	if _, ok := buildRemediationByCheckID(unknownResults, lookup)["TEST.unknown"]; ok {
		t.Error("expected no entry for a check with no registered metadata under its platform")
	}
}

// TestRunReport_ADOWebhooksRendersAsProjectScope is issue #214's end-to-end
// proof: C09.repo.webhooks (Azure DevOps) now registers ScopeLevelProject
// (see internal/collect/azuredevops/auditlogging), so a result for it must
// render "(project: X)"/"(project-level: X)" — never "(org)"/"(org-level)" —
// in all three renderers. Goes through the real collect.Registered()/
// LookupPlatform (via buildScopeLevelByCheckID) and the real
// attestward-report pipeline (runReport), not a hand-built scope map or a
// direct RenderX call: a synthetic map would prove the renderers work
// without proving this specific check is actually wired into the registry
// correctly.
func TestRunReport_ADOWebhooksRendersAsProjectScope(t *testing.T) {
	const checkID = "C09.repo.webhooks"
	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "test",
		Scope:         model.ScanScope{Org: "contoso", Repos: []string{}, Platform: "azuredevops", Project: "billing"},
		Results: []model.CheckResult{
			{
				CheckID: checkID,
				Title:   "A service hook subscription exports push/build events",
				Status:  model.StatusVerifiedFail,
				Reason:  "no enabled service-hook subscription with eventType git.push or build.complete is scoped to this project (or to all projects)",
				Scope:   model.ScopeRef{Org: "contoso", Project: "billing", Platform: "azuredevops"},
				Provenance: []model.Provenance{
					{Endpoint: "GET dev.azure.com/{org}/_apis/hooks/subscriptions", Method: "GET", HTTPStatus: 200, ResponseSHA256: strings.Repeat("c", 64)},
				},
			},
		},
	}

	dir := t.TempDir()
	if _, err := writeEvidencePack(pack, dir); err != nil {
		t.Fatalf("writeEvidencePack: %v", err)
	}
	path := filepath.Join(dir, "evidence.json")

	outDir := t.TempDir()
	if err := runReport(context.Background(), &bytes.Buffer{}, path, outDir, []string{"md", "html", "poam"}, false); err != nil {
		t.Fatalf("runReport: %v", err)
	}

	md, err := os.ReadFile(filepath.Join(outDir, "report.md"))
	if err != nil {
		t.Fatalf("read report.md: %v", err)
	}
	if !bytes.Contains(md, []byte("`"+checkID+"` | (project: billing) |")) {
		t.Errorf("report.md doesn't label %s (project: billing); got:\n%s", checkID, md)
	}
	if bytes.Contains(md, []byte("`"+checkID+"` | (org) |")) {
		t.Errorf("report.md still labels %s org-level (issue #214)", checkID)
	}

	html, err := os.ReadFile(filepath.Join(outDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	if !bytes.Contains(html, []byte("<code>"+checkID+"</code></td><td>(project: billing)</td>")) {
		t.Errorf("report.html doesn't label %s (project: billing); got:\n%s", checkID, html)
	}
	if bytes.Contains(html, []byte("<code>"+checkID+"</code></td><td>(org)</td>")) {
		t.Errorf("report.html still labels %s org-level (issue #214)", checkID)
	}

	poam, err := os.ReadFile(filepath.Join(outDir, "poam.md"))
	if err != nil {
		t.Fatalf("read poam.md: %v", err)
	}
	if !bytes.Contains(poam, []byte("- **Scope:** (project-level: billing)")) {
		t.Errorf("poam.md doesn't label %s (project-level: billing); got:\n%s", checkID, poam)
	}
	if bytes.Contains(poam, []byte("- **Scope:** (org-level)")) {
		t.Errorf("poam.md still labels %s org-level (issue #214)", checkID)
	}
}

func TestRunReport_DefaultOutDirIsAlongsideInput(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeReportFixture(t, dir, false)

	if err := runReport(context.Background(), &bytes.Buffer{}, path, "", []string{"md"}, false); err != nil {
		t.Fatalf("runReport: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "report.md")); err != nil {
		t.Errorf("report.md not written alongside input when --out is empty: %v", err)
	}
}

func TestRunReport_UnknownFormatIsError(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeReportFixture(t, dir, false)

	err := runReport(context.Background(), &bytes.Buffer{}, path, t.TempDir(), []string{"pdf"}, false)
	if err == nil {
		t.Fatal("runReport with --format=pdf returned no error, want one")
	}
}

func TestRunReport_UnsupportedSchemaVersionIsFriendlyError(t *testing.T) {
	dir := t.TempDir()
	pack := reportFixturePack()
	// A pack whose schema_version is newer than this build recognizes
	// can't come from writeEvidencePack — its own pre-write schema
	// validation correctly rejects an out-of-range schema_version (the
	// schema declares it `const: 1`). Written directly instead, to
	// simulate a pack handed over from some future attestward version this
	// build doesn't understand yet.
	pack.SchemaVersion = model.SchemaVersion + 1
	data, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		t.Fatalf("marshal pack: %v", err)
	}
	path := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write evidence.json: %v", err)
	}

	err = runReport(context.Background(), &bytes.Buffer{}, path, t.TempDir(), []string{"md"}, false)
	if err == nil {
		t.Fatal("runReport against a newer-schema pack returned no error, want one")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error %q doesn't mention schema_version", err)
	}
}

// TestRunReport_MalformedSidecarIsHardErrorEvenWithForce locks in the
// distinction --force's own help text now makes explicit: --force only
// overrides a hash *mismatch* (verification ran and found tampering). A
// malformed sidecar means verification couldn't run at all, which is a
// different, unconditional error — there's no "render anyway" for a
// question attestward couldn't actually answer.
func TestRunReport_MalformedSidecarIsHardErrorEvenWithForce(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeReportFixture(t, dir, false)
	if err := os.WriteFile(integrity.SidecarPath(path), []byte("not a sha256sum line\n"), 0o644); err != nil {
		t.Fatalf("write malformed sidecar: %v", err)
	}

	if err := runReport(context.Background(), &bytes.Buffer{}, path, t.TempDir(), []string{"md"}, true); err == nil {
		t.Error("runReport with --force against a malformed sidecar returned no error, want one")
	}
}

// tamperEvidenceFile rewrites path's tool_version field in place, changing
// the file's content (and thus its hash) while keeping it valid JSON —
// runReport unmarshals the file to render it, unlike attestward verify's
// hash-only check, so a tamper that breaks JSON syntax entirely would mask
// what these tests are actually proving (that a hash mismatch specifically
// is caught) behind an unrelated parse error instead.
func tamperEvidenceFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	const from = `"tool_version": "test"`
	const to = `"tool_version": "xest"`
	if !bytes.Contains(data, []byte(from)) {
		t.Fatalf("fixture doesn't contain %q — tamper helper needs updating", from)
	}
	tampered := bytes.Replace(data, []byte(from), []byte(to), 1)
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatalf("tamper %s: %v", path, err)
	}
}

func TestRunReport_NoSidecarRendersNormally(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeReportFixture(t, dir, false) // no sidecar at all

	outDir := t.TempDir()
	if err := runReport(context.Background(), &bytes.Buffer{}, path, outDir, []string{"md"}, false); err != nil {
		t.Fatalf("runReport on a pack with no sidecar returned an error, want success: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "report.md"))
	if err != nil {
		t.Fatalf("read report.md: %v", err)
	}
	if bytes.Contains(got, []byte("WARNING")) {
		t.Error("report.md contains a tamper-warning banner despite no sidecar ever existing to fail against")
	}
}

// TestRunReport_TamperedWithoutForceFails proves a hash mismatch against
// the .sha256 sidecar is refused by default — rendering tampered evidence
// must be a conscious act (issue #28's own acceptance criterion).
func TestRunReport_TamperedWithoutForceFails(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeReportFixture(t, dir, true)
	tamperEvidenceFile(t, path)

	if err := runReport(context.Background(), &bytes.Buffer{}, path, t.TempDir(), []string{"md"}, false); err == nil {
		t.Error("runReport on a tampered pack without --force returned no error, want one")
	}
}

// TestRunReport_TamperedWithForceRendersWithBanner proves --force renders
// anyway, and that every rendered file visibly says so.
func TestRunReport_TamperedWithForceRendersWithBanner(t *testing.T) {
	dir := t.TempDir()
	path, _ := writeReportFixture(t, dir, true)
	tamperEvidenceFile(t, path)

	outDir := t.TempDir()
	if err := runReport(context.Background(), &bytes.Buffer{}, path, outDir, []string{"md", "html", "poam"}, true); err != nil {
		t.Fatalf("runReport with --force on a tampered pack returned an error, want success: %v", err)
	}
	for _, name := range []string{"report.md", "report.html", "poam.md"} {
		got, err := os.ReadFile(filepath.Join(outDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Contains(got, []byte("hash verification failed")) {
			t.Errorf("%s does not carry the hash-verification-failed banner", name)
		}
	}
	// report.html must still be well-formed enough to open (banner
	// injected, not corrupting the surrounding markup).
	html, err := os.ReadFile(filepath.Join(outDir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	if !bytes.Contains(html, []byte("<body>")) || !bytes.Contains(html, []byte("</html>")) {
		t.Error("report.html's banner injection corrupted the surrounding document structure")
	}
}

// TestReportGo_NoNetworkImports locks in issue #28's explicit threat-model
// requirement ("zero network access in this command path") as a static
// guarantee: report.go must never import net/http or the GitHub client
// package, not just happen to avoid calling them today.
func TestReportGo_NoNetworkImports(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "report.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse report.go: %v", err)
	}
	forbidden := map[string]bool{
		"net":      true,
		"net/http": true,
		"github.com/sioakim/attestward/internal/collect/github": true,
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if forbidden[path] {
			t.Errorf("report.go imports %q — attestward report must never touch the network", path)
		}
	}
}

// TestRegistry_ProjectScopedADOChecksArePinned pins the CLASSIFICATION, which
// nothing else does.
//
// Issue #176 was that project-scoped Azure DevOps results rendered as
// org-level. The fix works by tagging checks with CheckMeta.ScopeLevel — but
// the three renderer tests hand-build their scope map, so they prove the
// renderer and say nothing about the registry. Measured: deleting
// `ScopeLevel: collect.ScopeLevelProject` from envseparation's registration,
// silently un-classifying all four C03 ADO checks, leaves `go test ./...`
// fully green.
//
// That is exactly where the next regression lands. ScopeLevelOrg is the zero
// value, so a new project-scoped ADO collector whose author omits the field
// compiles, passes, and ships a wrong "(org)" label into a signed evidence
// pack — #176 verbatim, in a document a compliance reader acts on.
//
// This asserts the EXACT set, both directions: a check that stops being
// project-scoped fails here too, so the list cannot silently grow or shrink.
// Adding a genuinely project-scoped check means adding its ID here, on
// purpose, in the same change.
func TestRegistry_ProjectScopedADOChecksArePinned(t *testing.T) {
	// Every Azure DevOps check whose results carry a Project but no Repo.
	// Derived from each collector's actual model.ScopeRef construction, not
	// from the registry itself — a test that read the registry to build its
	// own expectation would pass no matter what the registry said.
	want := map[string]bool{
		"C03.env.branch-policy":           true,
		"C03.env.exists":                  true,
		"C03.env.protection-rules":        true,
		"C03.env.required-reviewers":      true,
		"C04.vars.secret-hygiene":         true,
		"C08.actions.oidc-vs-secrets":     true,
		"C08.actions.pinned":              true,
		"C08.actions.pull-request-target": true,
		"C08.actions.self-hosted":         true,
		"C08.actions.token-permissions":   true,
		"C08.pipelines.fork-protection":   true,
		"C09.repo.webhooks":               true,
	}

	got := map[string]bool{}
	for _, meta := range collect.Registered() {
		if meta.Platform != "azuredevops" {
			continue
		}
		// "" and ScopeLevelOrg are both org — the field's zero value is the
		// empty string, not "org", and almost no check sets it explicitly.
		switch meta.ScopeLevel {
		case collect.ScopeLevelProject:
			got[meta.ID] = true
		case collect.ScopeLevelOrg, "":
			if want[meta.ID] {
				t.Errorf("%s is registered org-scoped but its results carry a Project — it will render as \"(org)\" in a signed pack (issue #176)", meta.ID)
			}
		default:
			t.Errorf("%s has unknown ScopeLevel %q", meta.ID, meta.ScopeLevel)
		}
	}

	for id := range want {
		if !got[id] {
			t.Errorf("%s is no longer registered as project-scoped — either the registration was dropped, or the check genuinely changed scope and this list needs updating deliberately", id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("%s is newly registered as project-scoped and is not in this list — add it here if that is correct, so the set stays reviewed", id)
		}
	}
}
