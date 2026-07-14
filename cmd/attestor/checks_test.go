package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sioakim/ssdf/internal/collect"
	"github.com/sioakim/ssdf/internal/mapping"
	"github.com/sioakim/ssdf/mappings"
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
	rows := buildMatrix(ssdf, cisa, registered)

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

func TestChecksListGoldenTable(t *testing.T) {
	ssdf, cisa, registered := fixtureMatrixInputs()
	rows := buildMatrix(ssdf, cisa, registered)

	var buf bytes.Buffer
	if err := renderChecksTable(&buf, rows); err != nil {
		t.Fatalf("renderChecksTable: %v", err)
	}
	compareOrUpdateGolden(t, "checks-list.table.golden", buf.Bytes())
}

func TestChecksListGoldenJSON(t *testing.T) {
	ssdf, cisa, registered := fixtureMatrixInputs()
	rows := buildMatrix(ssdf, cisa, registered)

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
	rows := buildMatrix(ssdf, cisa, registered)

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
	// collector package's init()-time registration — here, orgsecurity's,
	// repoprotection's, envseparation's, secretshygiene's, sasthistory's,
	// scahistory's, provenance's, actionssecurity's, auditlogging's, and
	// vdp's, transitively imported via scan.go) — not the
	// disk-based loaders or synthetic fixtures the other tests in this
	// file use, which would miss a broken //go:embed pattern, a renamed
	// file, or a check registered on one side (registry or mapping) but
	// not the other.
	ssdf, err := mapping.LoadSSDFFS(mappings.FS, "ssdf-800-218.yaml")
	if err != nil {
		t.Fatalf("LoadSSDFFS: %v", err)
	}
	cisa, err := mapping.LoadCISAFS(mappings.FS, "cisa-ssda-form.yaml", ssdf)
	if err != nil {
		t.Fatalf("LoadCISAFS: %v", err)
	}
	rows := buildMatrix(ssdf, cisa, collect.Registered())

	wantIDs := []string{
		"C01.org.2fa-required",
		"C01.org.default-repo-permission",
		"C01.org.members-can-create-public",
		"C01.org.members-without-2fa",
		"C02.branch.admin-enforced",
		"C02.branch.deletion-blocked",
		"C02.branch.force-push-blocked",
		"C02.branch.protection-exists",
		"C02.branch.required-reviews",
		"C02.branch.required-status-checks",
		"C03.env.branch-policy",
		"C03.env.exists",
		"C03.env.protection-rules",
		"C03.env.required-reviewers",
		"C04.deps.dependabot-alerts",
		"C04.org.security-defaults",
		"C04.secrets.advanced-security",
		"C04.secrets.push-protection",
		"C04.secrets.scanning-enabled",
		"C05.sast.cadence",
		"C05.sast.default-setup",
		"C05.sast.ran-per-release",
		"C05.sast.tool-configured",
		"C06.sca.alerts-triaged",
		"C06.sca.dependabot-config",
		"C06.sca.dependency-review",
		"C06.sca.ran-per-release",
		"C06.sca.tool-configured",
		"C07.provenance.commit-linkage",
		"C07.provenance.workflow",
		"C07.release.checksums",
		"C07.release.signatures",
		"C07.release.tags-signed",
		"C08.actions.oidc-vs-secrets",
		"C08.actions.pinned",
		"C08.actions.pull-request-target",
		"C08.actions.self-hosted",
		"C08.actions.token-permissions",
		"C09.audit.log-streaming",
		"C09.audit.org-log-available",
		"C09.audit.retention-awareness",
		"C09.repo.webhooks",
		"C10.vdp.intake-channel",
		"C10.vdp.private-reporting",
		"C10.vdp.security-md",
		"C10.vdp.security-policy-org",
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
