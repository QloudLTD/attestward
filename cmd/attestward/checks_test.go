package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/mappings"
)

var updateGolden = flag.Bool("update", false, "write golden files instead of comparing against them")

// fixtureMatrixInputs builds a small synthetic SSDF/CISA mapping (not the
// real files under mappings/, which don't reference any checks yet) plus a
// registered-collector slice that deliberately exercises all three matrix
// statuses:
//   - C01.org.mfa: referenced by a task AND registered -> "ok"
//   - C05.sast.tool-detected: referenced by a task but NOT registered -> "unimplemented"
//   - C99.example.unmapped: registered but referenced by no task -> "unmapped"
func fixtureMatrixInputs() (*mapping.SSDFMapping, *mapping.CISAMapping, []collect.CheckMeta) {
	ssdf := &mapping.SSDFMapping{
		Tasks: []mapping.SSDFTask{
			{ID: "PO.5.1", Family: "PO", Practice: "PO.5", Checks: []string{"C01.org.mfa"}},
			{ID: "PW.7.1", Family: "PW", Practice: "PW.7", Checks: []string{"C05.sast.tool-detected"}},
		},
	}
	cisa := &mapping.CISAMapping{
		Clusters: []mapping.CISACluster{
			{ID: "1", SSDFTasks: []string{"PO.5.1"}},
			{ID: "4", SSDFTasks: []string{"PW.7.1"}},
		},
	}
	registered := []collect.CheckMeta{
		{ID: "C01.org.mfa", Title: "Org MFA enforced", Collector: "org-security", TokenScope: "read:org"},
		{ID: "C99.example.unmapped", Title: "Unmapped example", Collector: "example", TokenScope: "n/a"},
	}
	return ssdf, cisa, registered
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

func TestBuildMatrixStatuses(t *testing.T) {
	ssdf, cisa, registered := fixtureMatrixInputs()
	rows := buildMatrix(ssdf, cisa, registered, nil)

	byID := map[string]MatrixRow{}
	for _, r := range rows {
		byID[r.CheckID] = r
	}

	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want 3", len(rows))
	}
	if got := byID["C01.org.mfa"].Status; got != statusOK {
		t.Errorf("C01.org.mfa status = %q, want %q", got, statusOK)
	}
	if got := byID["C05.sast.tool-detected"].Status; got != statusUnimplemented {
		t.Errorf("C05.sast.tool-detected status = %q, want %q", got, statusUnimplemented)
	}
	if got := byID["C99.example.unmapped"].Status; got != statusUnmapped {
		t.Errorf("C99.example.unmapped status = %q, want %q", got, statusUnmapped)
	}
	if got := byID["C01.org.mfa"].Clusters; len(got) != 1 || got[0] != "1" {
		t.Errorf("C01.org.mfa clusters = %v, want [1]", got)
	}
}

// TestBuildMatrix_SameIDUnderTwoPlatformsProducesTwoRows uses a synthetic
// dual-platform registered slice (not collect.Register — that would pollute
// the real global registry and corrupt other tests in this package that
// assert an exact collect.Registered() count) to prove issue #148/#164's
// review finding is fixed: the same check ID registered under two platforms
// must render as two separate rows, each with its own Title/Collector/
// TokenScope, not one row where the second platform silently overwrote the
// first's metadata. Both rows still agree on the SSDF task/cluster
// citation, since that comes from the platform-agnostic mapping data, not
// the registry.
func TestBuildMatrix_SameIDUnderTwoPlatformsProducesTwoRows(t *testing.T) {
	ssdf := &mapping.SSDFMapping{
		Tasks: []mapping.SSDFTask{
			{ID: "PO.5.1", Family: "PO", Practice: "PO.5", Checks: []string{"C01.org.mfa"}},
		},
	}
	cisa := &mapping.CISAMapping{
		Clusters: []mapping.CISACluster{{ID: "1", SSDFTasks: []string{"PO.5.1"}}},
	}
	registered := []collect.CheckMeta{
		{ID: "C01.org.mfa", Platform: "github", Title: "GitHub title", Collector: "org-security", TokenScope: "read:org"},
		{ID: "C01.org.mfa", Platform: "azuredevops", Title: "ADO title", Collector: "org-security", TokenScope: "vso.project"},
	}

	rows := buildMatrix(ssdf, cisa, registered, nil)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2 (one row per platform for the shared check ID): %+v", len(rows), rows)
	}

	byPlatform := map[string]MatrixRow{}
	for _, r := range rows {
		if r.CheckID != "C01.org.mfa" {
			t.Errorf("unexpected row for check %s", r.CheckID)
		}
		byPlatform[r.Platform] = r
	}
	if byPlatform["github"].Title != "GitHub title" || byPlatform["github"].TokenScope != "read:org" {
		t.Errorf("github row = %+v, want Title=GitHub title TokenScope=read:org", byPlatform["github"])
	}
	if byPlatform["azuredevops"].Title != "ADO title" || byPlatform["azuredevops"].TokenScope != "vso.project" {
		t.Errorf("azuredevops row = %+v, want Title=ADO title TokenScope=vso.project", byPlatform["azuredevops"])
	}
	for platform, row := range byPlatform {
		if len(row.SSDFTasks) != 1 || row.SSDFTasks[0] != "PO.5.1" {
			t.Errorf("%s row SSDFTasks = %v, want [PO.5.1] (shared mapping data, independent of platform)", platform, row.SSDFTasks)
		}
		if row.Status != statusOK {
			t.Errorf("%s row status = %q, want ok", platform, row.Status)
		}
	}
}

func TestChecksListGoldenTable(t *testing.T) {
	ssdf, cisa, registered := fixtureMatrixInputs()
	rows := buildMatrix(ssdf, cisa, registered, nil)

	var buf bytes.Buffer
	if err := renderChecksTable(&buf, rows); err != nil {
		t.Fatalf("renderChecksTable: %v", err)
	}
	compareOrUpdateGolden(t, "checks-list.table.golden", buf.Bytes())
}

func TestChecksListGoldenJSON(t *testing.T) {
	ssdf, cisa, registered := fixtureMatrixInputs()
	rows := buildMatrix(ssdf, cisa, registered, nil)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rows); err != nil {
		t.Fatalf("encode json: %v", err)
	}
	compareOrUpdateGolden(t, "checks-list.json.golden", buf.Bytes())
}

func TestChecksListGoldenYAML(t *testing.T) {
	ssdf, cisa, registered := fixtureMatrixInputs()
	rows := buildMatrix(ssdf, cisa, registered, nil)

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	if err := enc.Encode(rows); err != nil {
		t.Fatalf("encode yaml: %v", err)
	}
	if err := enc.Close(); err != nil {
		t.Fatalf("close yaml encoder: %v", err)
	}
	compareOrUpdateGolden(t, "checks-list.yaml.golden", buf.Bytes())
}

func TestBuildMatrixAgainstRealEmbeddedMappings(t *testing.T) {
	// Smoke test against the exact code path the shipped binary runs
	// (runChecksList calls these same LoadSSDFFS/LoadCISAFS functions
	// against mappings.FS, and collect.Registered() reflects every
	// collector package's init()-time registration — here, github's
	// orgsecurity, repoprotection, envseparation, secretshygiene,
	// sasthistory, scahistory, provenance, actionssecurity, auditlogging,
	// and vdp, plus azuredevops' own orgsecurity, repoprotection (both
	// issue #150, S4's two PRs), envseparation, secretshygiene (both issue
	// #151, S5's two PRs), sasthistory (issue #152, S6's first collector
	// PR), auditlogging, vdp (both issue #154, S8's two PRs), and
	// provenance (issue #153, S7's first collector PR),
	// transitively imported via scan.go) — not the disk-based loaders or
	// synthetic fixtures the other tests in this file use, which would
	// miss a broken //go:embed pattern, a renamed file, or a check
	// registered on one side (registry or mapping) but not the other.
	//
	// wantIDs lists each shared check ID once per platform that registers
	// it — the four C01.org.* IDs, the six C02.branch.* IDs (both issue
	// #150), the four C03.env.* IDs and five of C04's six IDs (issue #151
	// — C04.vars.secret-hygiene is the sixth, azuredevops-only, so it
	// appears just once, not twice; see its own doc comment), the four
	// C05.sast.* IDs (issue #152), the four C09.* IDs, and the four
	// C10.vdp.* IDs (both issue #154) are each registered under both
	// azuredevops and github (same ID, per-platform metadata; see issue
	// #34's check-identity model), so buildMatrix's own
	// one-row-per-(platform,ID) contract (TestBuildMatrix_SameID...) means
	// each appears twice here, sorted by CheckID then Platform —
	// "azuredevops" sorts before "github", so the ADO row comes first.
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
	rows := buildMatrix(ssdf, cisa, collect.Registered(), saQuestions.Questions)

	wantIDs := []string{
		"C01.org.2fa-required",
		"C01.org.2fa-required",
		"C01.org.default-repo-permission",
		"C01.org.default-repo-permission",
		"C01.org.members-can-create-public",
		"C01.org.members-can-create-public",
		"C01.org.members-without-2fa",
		"C01.org.members-without-2fa",
		"C02.branch.admin-enforced",
		"C02.branch.admin-enforced",
		"C02.branch.deletion-blocked",
		"C02.branch.deletion-blocked",
		"C02.branch.force-push-blocked",
		"C02.branch.force-push-blocked",
		"C02.branch.protection-exists",
		"C02.branch.protection-exists",
		"C02.branch.required-reviews",
		"C02.branch.required-reviews",
		"C02.branch.required-status-checks",
		"C02.branch.required-status-checks",
		"C03.env.branch-policy",
		"C03.env.branch-policy",
		"C03.env.exists",
		"C03.env.exists",
		"C03.env.protection-rules",
		"C03.env.protection-rules",
		"C03.env.required-reviewers",
		"C03.env.required-reviewers",
		"C04.deps.dependabot-alerts",
		"C04.deps.dependabot-alerts",
		"C04.org.security-defaults",
		"C04.org.security-defaults",
		"C04.secrets.advanced-security",
		"C04.secrets.advanced-security",
		"C04.secrets.push-protection",
		"C04.secrets.push-protection",
		"C04.secrets.scanning-enabled",
		"C04.secrets.scanning-enabled",
		"C04.vars.secret-hygiene",
		"C05.sast.cadence",
		"C05.sast.cadence",
		"C05.sast.default-setup",
		"C05.sast.default-setup",
		"C05.sast.ran-per-release",
		"C05.sast.ran-per-release",
		"C05.sast.tool-configured",
		"C05.sast.tool-configured",
		"C06.sca.alerts-triaged",
		"C06.sca.dependabot-config",
		"C06.sca.dependency-review",
		"C06.sca.ran-per-release",
		"C06.sca.tool-configured",
		// C07's five checks are now registered under both platforms (issue
		// #153, S7, the first ADO collector of this story) — each ID sorts
		// next to its own duplicate, the same azuredevops-before-github
		// ordering as C05/C09/C10 above.
		"C07.provenance.commit-linkage",
		"C07.provenance.commit-linkage",
		"C07.provenance.workflow",
		"C07.provenance.workflow",
		"C07.release.checksums",
		"C07.release.checksums",
		"C07.release.signatures",
		"C07.release.signatures",
		"C07.release.tags-signed",
		"C07.release.tags-signed",
		"C08.actions.oidc-vs-secrets",
		"C08.actions.pinned",
		"C08.actions.pull-request-target",
		"C08.actions.self-hosted",
		"C08.actions.token-permissions",
		// C09's four checks are now registered under both platforms (issue
		// #154, S8, the first ADO collector landed) — each ID sorts next
		// to its own duplicate (azuredevops before github, since rows are
		// sorted CheckID then Platform ascending and "azuredevops" <
		// "github").
		"C09.audit.log-streaming",
		"C09.audit.log-streaming",
		"C09.audit.org-log-available",
		"C09.audit.org-log-available",
		"C09.audit.retention-awareness",
		"C09.audit.retention-awareness",
		"C09.repo.webhooks",
		"C09.repo.webhooks",
		"C10.vdp.intake-channel",
		"C10.vdp.intake-channel",
		"C10.vdp.private-reporting",
		"C10.vdp.private-reporting",
		"C10.vdp.security-md",
		"C10.vdp.security-md",
		"C10.vdp.security-policy-org",
		"C10.vdp.security-policy-org",
		"SA.agency-notification-process",
		"SA.audit-log-export-fallback",
		"SA.dev-security-training",
		"SA.threat-modeling",
		"SA.vuln-remediation-sla",
		"SA.vuln-triage-sla",
	}
	if len(rows) != len(wantIDs) {
		t.Fatalf("len(rows) = %d, want %d (%v)", len(rows), len(wantIDs), wantIDs)
	}
	for i, id := range wantIDs {
		if rows[i].CheckID != id {
			t.Errorf("rows[%d].CheckID = %q, want %q", i, rows[i].CheckID, id)
		}
		if rows[i].Status != statusOK {
			t.Errorf("rows[%d] (%s) status = %q, want %q — every registered check must also be cited by a mapping task, and vice versa", i, rows[i].CheckID, rows[i].Status, statusOK)
		}
	}
}

// TestAllC01ThroughC10ChecksHaveRemediation is the final slice of issue
// #26's acceptance criterion "every C01-C10 fail mode has non-empty
// remediation" — the backfill landed collector-group by collector-group
// across three PRs (like the collectors themselves did in issues
// #11-#22: C01-C04, then C05-C07, then this last group, C08-C10), and
// this is the widened assertion covering the complete registry. Every
// check collect.Registered() returns is a C0X check (self-attestation
// questions never call collect.Register — see registry.go's doc comment
// on CheckMeta.Remediation), so no prefix filtering is needed here,
// unlike the narrower per-group predecessors of this test. The
// found-count assertion guards against this silently covering zero
// checks if the registry were ever emptied by an import change. The count
// grew from 46 to 78 across issues #150 (S4, two PRs: C01 then C02), #151
// (S5, two PRs: C03 then C04), #152 (S6, its first collector PR, C05),
// and #154 (S8, two PRs: C09 then C10): azuredevops' own C01 org-security
// (4 checks), C02 repo-protection (6 checks), C03 env-separation (4
// checks), C05 sast-history (4 checks), C09 audit-logging (4 checks), C10
// vdp (4 checks), and C07 provenance (5 checks, issue #153, S7's first
// collector PR) each register the same check IDs their GitHub twins
// already do (issue #34's check-identity model — same ID, per-platform
// metadata), each a distinct (Platform, ID) registry entry. C04
// secrets-hygiene is different: it registers 6 checks, but only 5 mirror
// a GitHub twin (scanning-enabled, push-protection, advanced-security,
// dependabot-alerts, org-security-defaults) — the sixth,
// C04.vars.secret-hygiene, is azuredevops-only with no GitHub twin at all
// (see its own package doc comment), so it's a wholly new registry entry,
// not a second platform for an existing one. Total: 46 + 4 + 6 + 4 + 6 +
// 4 + 4 + 4 + 5 = 83.
func TestAllC01ThroughC10ChecksHaveRemediation(t *testing.T) {
	registered := collect.Registered()
	for _, meta := range registered {
		if meta.Remediation == "" {
			t.Errorf("%s (%s) has no Remediation text", meta.ID, meta.Title)
		}
	}
	if len(registered) != 83 {
		t.Fatalf("len(collect.Registered()) = %d, want 83 — did the registered check count change?", len(registered))
	}
}
