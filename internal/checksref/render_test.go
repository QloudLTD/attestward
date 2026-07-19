package checksref

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
)

var updateGolden = flag.Bool("update", false, "write golden files instead of comparing against them")

// fixtureInputs builds a small, self-contained SSDF/CISA mapping plus a
// registered-collector slice that exercises: two checks under the same
// collector (so grouping is proven), a check cited by no task, a
// three-status rubric, a two-status rubric, and a legitimately-empty
// Endpoints (the C09-style "fixed fact" case) — deliberately not the real
// embedded mappings/registry, which keeps evolving independently of this
// renderer's own contract (see cmd/attestward/checks_test.go's identical
// choice for buildMatrix's tests).
func fixtureInputs() ([]collect.CheckMeta, *mapping.SSDFMapping, *mapping.CISAMapping, *mapping.SelfAttestationQuestions) {
	ssdf := &mapping.SSDFMapping{
		Version:   "1.11.0",
		Source:    mapping.SSDFSource{URL: "https://csrc.nist.gov/pubs/sp/800/218/final"},
		Retrieved: "2026-01-01",
		Practices: map[string]mapping.SSDFPractice{
			"PO.5": {Title: "Implement supporting toolchains"},
		},
		Tasks: []mapping.SSDFTask{
			{ID: "PO.5.1", Family: "PO", Practice: "PO.5", Text: "Verbatim task text.", Checks: []string{"C01.org.mfa"}},
		},
	}
	ssdf.TaskByID = map[string]mapping.SSDFTask{"PO.5.1": ssdf.Tasks[0]}

	cisa := &mapping.CISAMapping{
		Version:   "2.0",
		Source:    mapping.CISASource{URL: "https://www.cisa.gov/ssda"},
		Retrieved: "2026-01-01",
		Clusters: []mapping.CISACluster{
			{ID: "1", Title: "Secure Development Environment", SSDFTasks: []string{"PO.5.1"}},
		},
	}

	registered := []collect.CheckMeta{
		{
			ID: "C01.org.mfa", Title: "Org MFA enforced", Collector: "C01.org-security",
			TokenScope: "read:org", Remediation: "Enable MFA enforcement in org settings.",
			FixtureRef: "internal/collect/github/orgsecurity/orgsecurity_test.go",
			Endpoints:  []string{"GET /orgs/{org}"},
			Rubric: map[model.Status]string{
				model.StatusVerifiedPass: "the org enforces MFA for all members.",
				model.StatusVerifiedFail: "the org does not enforce MFA.",
				model.StatusNotCheckable: "the org lookup failed.",
			},
		},
		{
			ID: "C01.org.other", Title: "Some other org check", Collector: "C01.org-security",
			TokenScope: "read:org", Remediation: "Do the thing.",
			FixtureRef: "internal/collect/github/orgsecurity/orgsecurity_test.go",
			Endpoints:  nil,
			Rubric: map[model.Status]string{
				model.StatusVerifiedPass: "the fixed fact is true.",
				model.StatusNotCheckable: "always not-checkable by design.",
			},
		},
	}

	saQuestions := &mapping.SelfAttestationQuestions{
		Version: "1.0",
		Questions: []mapping.SelfAttestationQuestion{
			{ID: "SA.dev-training", Question: "Do developers receive security training?"},
		},
	}

	return registered, ssdf, cisa, saQuestions
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
		t.Errorf("%s mismatch:\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

func TestRender_Golden(t *testing.T) {
	registered, ssdf, cisa, saQuestions := fixtureInputs()

	got, err := Render(registered, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	compareOrUpdateGolden(t, "checks-reference.md.golden", got)
}

func TestRender_Deterministic(t *testing.T) {
	registered, ssdf, cisa, saQuestions := fixtureInputs()

	first, err := Render(registered, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("Render (1): %v", err)
	}
	second, err := Render(registered, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("Render (2): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("two Render calls over identical input produced different output")
	}
}

func TestRender_NilSelfAttestationQuestions(t *testing.T) {
	registered, ssdf, cisa, _ := fixtureInputs()

	got, err := Render(registered, ssdf, cisa, nil)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.Contains(got, []byte("## Self-Attestation Questions")) {
		t.Error("expected the Self-Attestation Questions section heading even with nil saQuestions")
	}
}

func TestRender_MissingRubricFailsLoudly(t *testing.T) {
	registered, ssdf, cisa, saQuestions := fixtureInputs()
	registered[0].Rubric = nil

	_, err := Render(registered, ssdf, cisa, saQuestions)
	if err == nil {
		t.Fatal("Render with a check missing Rubric: got nil error, want a loud failure (issue #30: no blank sections)")
	}
}

func TestRender_MissingFixtureRefFailsLoudly(t *testing.T) {
	registered, ssdf, cisa, saQuestions := fixtureInputs()
	registered[0].FixtureRef = ""

	_, err := Render(registered, ssdf, cisa, saQuestions)
	if err == nil {
		t.Fatal("Render with a check missing FixtureRef: got nil error, want a loud failure")
	}
}

func TestRender_MissingRemediationFailsLoudly(t *testing.T) {
	registered, ssdf, cisa, saQuestions := fixtureInputs()
	registered[0].Remediation = ""

	_, err := Render(registered, ssdf, cisa, saQuestions)
	if err == nil {
		t.Fatal("Render with a check missing Remediation: got nil error, want a loud failure")
	}
}

func TestRender_MissingTitleFailsLoudly(t *testing.T) {
	registered, ssdf, cisa, saQuestions := fixtureInputs()
	registered[0].Title = ""

	_, err := Render(registered, ssdf, cisa, saQuestions)
	if err == nil {
		t.Fatal("Render with a check missing Title: got nil error, want a loud failure (a blank '### `id` — ' heading is exactly the silent-blank issue #30 asks the generator to reject)")
	}
}

func TestRender_MissingTokenScopeFailsLoudly(t *testing.T) {
	registered, ssdf, cisa, saQuestions := fixtureInputs()
	registered[0].TokenScope = ""

	_, err := Render(registered, ssdf, cisa, saQuestions)
	if err == nil {
		t.Fatal("Render with a check missing TokenScope: got nil error, want a loud failure")
	}
}

func TestRender_RubricStatusNotInRubricOrderFailsLoudly(t *testing.T) {
	registered, ssdf, cisa, saQuestions := fixtureInputs()
	registered[0].Rubric[model.StatusSelfAttested] = "this status has no display order and must not silently vanish"

	_, err := Render(registered, ssdf, cisa, saQuestions)
	if err == nil {
		t.Fatal("Render with a Rubric status absent from rubricOrder: got nil error, want a loud failure (found in review: this status would otherwise silently disappear from the check's section rather than error)")
	}
}

func TestRender_EmptyEndpointsIsNotAnError(t *testing.T) {
	registered, ssdf, cisa, saQuestions := fixtureInputs()

	got, err := Render(registered, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("Render: %v (C01.org.other has legitimately-nil Endpoints and must not fail)", err)
	}
	if !bytes.Contains(got, []byte("fixed fact, not derived from an API call")) {
		t.Error("expected the empty-Endpoints fallback text for C01.org.other")
	}
}

func TestRender_GroupsByCollectorAndSortsByCheckID(t *testing.T) {
	registered, ssdf, cisa, saQuestions := fixtureInputs()

	got, err := Render(registered, ssdf, cisa, saQuestions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mfaIdx := bytes.Index(got, []byte("C01.org.mfa"))
	otherIdx := bytes.Index(got, []byte("C01.org.other"))
	if mfaIdx == -1 || otherIdx == -1 {
		t.Fatalf("expected both check IDs present in output")
	}
	if mfaIdx > otherIdx {
		t.Error("expected C01.org.mfa (sorted first) to appear before C01.org.other")
	}
	if bytes.Count(got, []byte("## C01.org-security")) != 1 {
		t.Error("expected exactly one '## C01.org-security' collector heading — both checks should group under it, not duplicate the heading")
	}
}
