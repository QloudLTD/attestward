package packdiff

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sioakim/attestward/internal/model"
)

func pack(org string, results ...model.CheckResult) model.EvidencePack {
	return model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   "0.1.0",
		Scope:         model.ScanScope{Org: org, Repos: []string{"r1"}},
		Results:       results,
	}
}

func res(checkID, org, repo string, status model.Status, reason string) model.CheckResult {
	return model.CheckResult{
		CheckID: checkID,
		Title:   checkID,
		Status:  status,
		Reason:  reason,
		Scope:   model.ScopeRef{Org: org, Repo: repo},
	}
}

func TestCompareClassifiesTransitions(t *testing.T) {
	cases := []struct {
		name   string
		from   model.Status
		to     model.Status
		bucket func(Delta) int
	}{
		{"pass to fail is regression", model.StatusVerifiedPass, model.StatusVerifiedFail, func(d Delta) int { return len(d.Regressions) }},
		{"pass to partial is regression", model.StatusVerifiedPass, model.StatusPartial, func(d Delta) int { return len(d.Regressions) }},
		{"partial to fail is regression", model.StatusPartial, model.StatusVerifiedFail, func(d Delta) int { return len(d.Regressions) }},
		{"fail to pass is improvement", model.StatusVerifiedFail, model.StatusVerifiedPass, func(d Delta) int { return len(d.Improvements) }},
		{"fail to partial is improvement", model.StatusVerifiedFail, model.StatusPartial, func(d Delta) int { return len(d.Improvements) }},
		{"partial to pass is improvement", model.StatusPartial, model.StatusVerifiedPass, func(d Delta) int { return len(d.Improvements) }},
		{"pass to not-checkable is coverage loss", model.StatusVerifiedPass, model.StatusNotCheckable, func(d Delta) int { return len(d.CoverageLoss) }},
		{"fail to not-checkable is coverage loss", model.StatusVerifiedFail, model.StatusNotCheckable, func(d Delta) int { return len(d.CoverageLoss) }},
		{"partial to not-checkable is coverage loss", model.StatusPartial, model.StatusNotCheckable, func(d Delta) int { return len(d.CoverageLoss) }},
		{"not-checkable to fail is coverage gain", model.StatusNotCheckable, model.StatusVerifiedFail, func(d Delta) int { return len(d.CoverageGain) }},
		{"not-checkable to pass is coverage gain", model.StatusNotCheckable, model.StatusVerifiedPass, func(d Delta) int { return len(d.CoverageGain) }},
		{"not-checkable to partial is coverage gain", model.StatusNotCheckable, model.StatusPartial, func(d Delta) int { return len(d.CoverageGain) }},
		{"self-attested to pass is other", model.StatusSelfAttested, model.StatusVerifiedPass, func(d Delta) int { return len(d.Other) }},
		{"self-attested to not-checkable is other", model.StatusSelfAttested, model.StatusNotCheckable, func(d Delta) int { return len(d.Other) }},
		// Deliberate bucketing, not an oversight: Status carries no
		// polarity, so a self-attested answer becoming verified-fail may
		// be the tool CONFIRMING a self-attested "no" — auto-classifying
		// it as regression would be wrong half the time. Informational.
		{"self-attested to fail is other", model.StatusSelfAttested, model.StatusVerifiedFail, func(d Delta) int { return len(d.Other) }},
		{"pass to self-attested is other", model.StatusVerifiedPass, model.StatusSelfAttested, func(d Delta) int { return len(d.Other) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := pack("acme", res("C01.x", "acme", "", tc.from, "was"))
			cur := pack("acme", res("C01.x", "acme", "", tc.to, "now"))
			d, err := Compare(base, cur)
			if err != nil {
				t.Fatalf("Compare: %v", err)
			}
			if got := tc.bucket(d); got != 1 {
				t.Fatalf("expected exactly 1 change in the target bucket, delta: %+v", d)
			}
			total := len(d.Regressions) + len(d.Improvements) + len(d.CoverageLoss) + len(d.CoverageGain) + len(d.Other)
			if total != 1 {
				t.Fatalf("change classified into multiple buckets, delta: %+v", d)
			}
		})
	}
}

// A regression must fail continuous mode; every other lone change class
// must not (issue #36's drift contract: coverage changes and checker
// changes are never posture regressions).
func TestHasRegressionsOnlyForRegressions(t *testing.T) {
	base := pack("acme", res("C01.x", "acme", "", model.StatusVerifiedPass, ""))
	cur := pack("acme", res("C01.x", "acme", "", model.StatusNotCheckable, ""))
	d, err := Compare(base, cur)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if d.HasRegressions() {
		t.Fatal("coverage loss alone must not count as a regression")
	}

	cur = pack("acme", res("C01.x", "acme", "", model.StatusVerifiedFail, ""))
	d, err = Compare(base, cur)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !d.HasRegressions() {
		t.Fatal("pass -> fail must count as a regression")
	}
}

func TestCompareIdenticalPacksIsEmpty(t *testing.T) {
	// Reasons and volatile metadata differ; statuses don't. Semantically equal.
	base := pack("acme", res("C01.x", "acme", "", model.StatusVerifiedPass, "5 of 5 repos clean"))
	cur := pack("acme", res("C01.x", "acme", "", model.StatusVerifiedPass, "6 of 6 repos clean"))
	d, err := Compare(base, cur)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !d.Empty() {
		t.Fatalf("expected empty delta, got %+v", d)
	}
}

func TestCompareAddedRemovedAndSorting(t *testing.T) {
	base := pack("acme",
		res("C02.b", "acme", "r1", model.StatusVerifiedPass, ""),
		res("C01.a", "acme", "", model.StatusVerifiedPass, ""),
	)
	cur := pack("acme",
		res("C01.a", "acme", "", model.StatusVerifiedPass, ""),
		res("C09.z", "acme", "r2", model.StatusVerifiedFail, "new check"),
		res("C03.c", "acme", "r1", model.StatusVerifiedFail, "new check"),
	)
	d, err := Compare(base, cur)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.Removed) != 1 || d.Removed[0].CheckID != "C02.b" {
		t.Fatalf("removed: %+v", d.Removed)
	}
	if len(d.Added) != 2 || d.Added[0].CheckID != "C03.c" || d.Added[1].CheckID != "C09.z" {
		t.Fatalf("added not sorted by check ID: %+v", d.Added)
	}
	// A check that only exists in the current pack — even verified-fail —
	// is informational, not a regression: there is no baseline status it
	// worsened from.
	if d.HasRegressions() {
		t.Fatal("added-only checks must not register as regressions")
	}
}

func TestCompareRejectsDifferentOrgs(t *testing.T) {
	_, err := Compare(pack("acme"), pack("globex"))
	if err == nil || !strings.Contains(err.Error(), "different orgs") {
		t.Fatalf("expected different-orgs error, got %v", err)
	}
}

// TestCompareRejectsDifferentPlatforms pins issue #148's checklist item:
// comparing packs from different platforms is an error, the same class as
// comparing different orgs — a github pack and an azuredevops pack cannot
// share a meaningful drift baseline even if (hypothetically) their org
// names happened to collide.
func TestCompareRejectsDifferentPlatforms(t *testing.T) {
	github := pack("acme")
	github.Scope.Platform = "github"
	azuredevops := pack("acme")
	azuredevops.Scope.Platform = "azuredevops"

	_, err := Compare(github, azuredevops)
	if err == nil || !strings.Contains(err.Error(), "different platforms") {
		t.Fatalf("expected different-platforms error, got %v", err)
	}

	// Same check, reverse direction — the guard must not be order-dependent.
	_, err = Compare(azuredevops, github)
	if err == nil || !strings.Contains(err.Error(), "different platforms") {
		t.Fatalf("expected different-platforms error in the reverse direction too, got %v", err)
	}
}

// TestCompareAbsentPlatformEqualsExplicitGitHub proves the pre-#164 self-scan
// drift baseline (no Platform field at all) stays comparable against a new
// pack that writes "github" explicitly (issue #148's writer policy) — an
// absent Platform and an explicit "github" must be treated as the same
// platform, not flagged as a difference.
func TestCompareAbsentPlatformEqualsExplicitGitHub(t *testing.T) {
	absent := pack("acme") // Platform left unset, as every pre-#164 pack is
	explicit := pack("acme")
	explicit.Scope.Platform = "github"

	if _, err := Compare(absent, explicit); err != nil {
		t.Fatalf("Compare(absent, explicit-github) = %v, want nil error (absent means github)", err)
	}
	if _, err := Compare(explicit, absent); err != nil {
		t.Fatalf("Compare(explicit-github, absent) = %v, want nil error (absent means github)", err)
	}
}

// TestCompareRejectsDifferentProjects mirrors TestCompareRejectsDifferentPlatforms
// for the Azure DevOps project axis (found in review of #169): two packs from
// the same org but different ADO projects are the same "not meaningful"
// comparison class as different orgs, since a project is effectively a
// second scope dimension ADO scans add.
func TestCompareRejectsDifferentProjects(t *testing.T) {
	projectA := pack("acme")
	projectA.Scope.Platform = "azuredevops"
	projectA.Scope.Project = "project-a"
	projectB := pack("acme")
	projectB.Scope.Platform = "azuredevops"
	projectB.Scope.Project = "project-b"

	_, err := Compare(projectA, projectB)
	if err == nil || !strings.Contains(err.Error(), "different projects") {
		t.Fatalf("expected different-projects error, got %v", err)
	}

	_, err = Compare(projectB, projectA)
	if err == nil || !strings.Contains(err.Error(), "different projects") {
		t.Fatalf("expected different-projects error in the reverse direction too, got %v", err)
	}
}

// TestCompareGitHubPacksWithEmptyProjectsAreComparable proves the Project
// guard doesn't false-positive on ordinary github packs, which always leave
// Project empty on both sides (no fallback needed — absent-vs-absent is
// already equal).
func TestCompareGitHubPacksWithEmptyProjectsAreComparable(t *testing.T) {
	a, b := pack("acme"), pack("acme")
	if _, err := Compare(a, b); err != nil {
		t.Fatalf("Compare(a, b) = %v, want nil error (both github packs, empty Project on both sides)", err)
	}
}

func TestCompareRejectsDuplicateKeys(t *testing.T) {
	dup := pack("acme",
		res("C01.a", "acme", "r1", model.StatusVerifiedPass, ""),
		res("C01.a", "acme", "r1", model.StatusVerifiedFail, ""),
	)
	_, err := Compare(dup, pack("acme"))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate-key error, got %v", err)
	}
}

func TestCompareContextFlags(t *testing.T) {
	base := pack("acme")
	cur := pack("acme")
	cur.ToolVersion = "0.2.0"
	cur.MappingVersions.SSDF = "1.12.0"
	cur.Scope.Repos = []string{"r1", "r2"}
	d, err := Compare(base, cur)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	ctx := d.Context
	if !ctx.ToolVersionChanged || !ctx.MappingVersionsChanged || !ctx.ReposChanged {
		t.Fatalf("context flags not all set: %+v", ctx)
	}
	if ctx.BaselineToolVersion != "0.1.0" || ctx.CurrentToolVersion != "0.2.0" {
		t.Fatalf("tool versions not recorded: %+v", ctx)
	}

	// Same repos in a different order is not a scope change.
	cur.Scope.Repos = []string{"r1"}
	base.Scope.Repos = []string{"r1"}
	d, _ = Compare(base, cur)
	if d.Context.ReposChanged {
		t.Fatal("repo order must not register as a scope change")
	}
}

func TestDeltaJSONHasNoNulls(t *testing.T) {
	d, err := Compare(pack("acme"), pack("acme"))
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "null") {
		t.Fatalf("empty delta marshals with JSON nulls (automation consumers expect arrays): %s", raw)
	}
}

func TestRenderersCoverEveryClass(t *testing.T) {
	base := pack("acme",
		res("C01.reg", "acme", "", model.StatusVerifiedPass, ""),
		res("C02.imp", "acme", "r1", model.StatusVerifiedFail, ""),
		res("C03.cov", "acme", "r1", model.StatusVerifiedPass, ""),
		res("C05.rem", "acme", "r1", model.StatusVerifiedPass, ""),
		res("C06.oth", "acme", "r1", model.StatusSelfAttested, ""),
	)
	cur := pack("acme",
		res("C01.reg", "acme", "", model.StatusVerifiedFail, "reason|with pipe"),
		res("C02.imp", "acme", "r1", model.StatusVerifiedPass, "fixed"),
		res("C03.cov", "acme", "r1", model.StatusNotCheckable, "token lost perms"),
		res("C04.add", "acme", "r1", model.StatusVerifiedFail, "brand new"),
		res("C06.oth", "acme", "r1", model.StatusVerifiedPass, "now verified"),
	)
	cur.ToolVersion = "0.2.0"
	d, err := Compare(base, cur)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}

	text := RenderText(d)
	for _, want := range []string{"REGRESSIONS", "C01.reg", "Improvements", "Coverage lost", "Only in current pack", "Only in baseline pack", "Other status changes", "tool version changed (0.1.0 -> 0.2.0)"} {
		if !strings.Contains(text, want) {
			t.Errorf("text output missing %q:\n%s", want, text)
		}
	}

	md := RenderMarkdown(d)
	for _, want := range []string{"### Regressions", "C01.reg", "acme (org)", "acme/r1", "reason\\|with pipe", "> Context:"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown output missing %q:\n%s", want, md)
		}
	}
}

// The markdown renderer's destination is a posted drift-issue body, and a
// pack is only trusted as far as its optional sidecar — every cell must
// be escaped, not just reasons, and with the shared mdescape escaper (not
// a weaker local fork; that fork was this test's motivating review
// finding).
func TestRenderMarkdownEscapesEveryCell(t *testing.T) {
	base := pack("acme", res("C01.[evil](x)", "acme", "inject|repo", model.StatusVerifiedPass, ""))
	cur := pack("acme", res("C01.[evil](x)", "acme", "inject|repo", model.StatusVerifiedFail, "[click](javascript:alert(1))\r\nrow|break"))
	cur.ToolVersion = "0.2.0|[v](x)"
	d, err := Compare(base, cur)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	md := RenderMarkdown(d)
	for _, banned := range []string{"[evil](x)", "[click](javascript:", "inject|repo", "\r", "[v](x)"} {
		if strings.Contains(md, banned) {
			t.Errorf("markdown output contains unescaped %q:\n%s", banned, md)
		}
	}
	if !strings.Contains(md, `\[evil\]`) || !strings.Contains(md, `inject\|repo`) {
		t.Errorf("expected escaped forms present:\n%s", md)
	}
}

func TestRenderEmptyDelta(t *testing.T) {
	d, err := Compare(pack("acme"), pack("acme"))
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if got := RenderText(d); !strings.Contains(got, "No semantic differences") {
		t.Errorf("text: %q", got)
	}
	if got := RenderMarkdown(d); !strings.Contains(got, "No semantic differences") {
		t.Errorf("markdown: %q", got)
	}
}
