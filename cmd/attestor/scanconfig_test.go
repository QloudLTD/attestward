package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadScanConfigFile_ExampleFileParses is a regression test on the
// actual shipped examples/attestor.yaml: if a future edit breaks its YAML
// or introduces an unrecognized key, this catches it in CI rather than
// leaving users of the README quickstart to discover it themselves.
func TestLoadScanConfigFile_ExampleFileParses(t *testing.T) {
	cfg, err := loadScanConfigFile("../../examples/attestor.yaml")
	if err != nil {
		t.Fatalf("loadScanConfigFile(examples/attestor.yaml): %v", err)
	}
	if cfg.Org == "" {
		t.Error("example config's org is empty")
	}
	if err := cfg.validate(); err != nil {
		t.Errorf("example config fails validate(): %v", err)
	}
}

// TestLoadScanConfigFile_EmptyOrAllCommentsIsNotAnError guards against the
// bare "parse foo.yaml: EOF" the Fable 5 review found: yaml.v3's Decode
// returns io.EOF for an empty document stream, which includes a file that's
// entirely comments — plausible, since examples/attestor.yaml explicitly
// encourages commenting fields out. This must be treated as "everything
// left to defaults," with validate() giving a clear "org is required"
// message downstream, not a confusing bare EOF.
func TestLoadScanConfigFile_EmptyOrAllCommentsIsNotAnError(t *testing.T) {
	dir := t.TempDir()

	for name, content := range map[string]string{
		"empty.yaml":        "",
		"all-comments.yaml": "# org: my-org\n# repos: [a, b]\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}

		cfg, err := loadScanConfigFile(path)
		if err != nil {
			t.Errorf("loadScanConfigFile(%s) = %v, want nil error (empty config, not a parse failure)", name, err)
		}
		if err := cfg.validate(); err == nil {
			t.Errorf("empty config from %s passed validate(), want the missing-org error", name)
		}
	}
}

func TestLoadScanConfigFile_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "attestor.yaml")
	content := "org: attestor-demo\nrepos: [good-repo, other-repo]\nout: ./evidence/\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cfg, err := loadScanConfigFile(path)
	if err != nil {
		t.Fatalf("loadScanConfigFile: %v", err)
	}
	if cfg.Org != "attestor-demo" {
		t.Errorf("Org = %q, want attestor-demo", cfg.Org)
	}
	if len(cfg.Repos) != 2 {
		t.Errorf("len(Repos) = %d, want 2", len(cfg.Repos))
	}
}

func TestLoadScanConfigFile_RejectsUnknownKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "attestor.yaml")
	// "respos" is a realistic typo for "repos" — the whole point of strict
	// parsing is that this must error, not silently scan everything.
	content := "org: attestor-demo\nrespos: [good-repo]\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	_, err := loadScanConfigFile(path)
	if err == nil {
		t.Fatal("loadScanConfigFile with an unknown key = nil error, want an error naming the typo")
	}
}

func TestMergeScanConfig_FlagsOverrideFileWhenSet(t *testing.T) {
	file := scanConfig{Org: "file-org", Repos: []string{"file-repo"}, Concurrency: 8}
	flags := scanConfig{Org: "flag-org"}
	flagsSet := map[string]bool{"org": true}

	merged := mergeScanConfig(file, flags, flagsSet)
	if merged.Org != "flag-org" {
		t.Errorf("Org = %q, want flag-org (flag was set)", merged.Org)
	}
	if len(merged.Repos) != 1 || merged.Repos[0] != "file-repo" {
		t.Errorf("Repos = %v, want [file-repo] (repo flag was not set, file value preserved)", merged.Repos)
	}
	if merged.Concurrency != 8 {
		t.Errorf("Concurrency = %d, want 8 (from file, no flag override)", merged.Concurrency)
	}
}

func TestMergeScanConfig_DefaultsFillUnsetFields(t *testing.T) {
	merged := mergeScanConfig(scanConfig{Org: "x"}, scanConfig{}, nil)

	if merged.ReleaseTagPattern != defaultReleaseTagPattern {
		t.Errorf("ReleaseTagPattern = %q, want %q", merged.ReleaseTagPattern, defaultReleaseTagPattern)
	}
	if merged.LookbackReleases != defaultLookbackReleases {
		t.Errorf("LookbackReleases = %d, want %d", merged.LookbackReleases, defaultLookbackReleases)
	}
	if merged.LookbackMonths != defaultLookbackMonths {
		t.Errorf("LookbackMonths = %d, want %d", merged.LookbackMonths, defaultLookbackMonths)
	}
	if merged.Out != defaultOut {
		t.Errorf("Out = %q, want %q", merged.Out, defaultOut)
	}
	if merged.Concurrency == 0 {
		t.Error("Concurrency = 0, want a nonzero default")
	}
}

func TestScanConfigValidate_RequiresOrg(t *testing.T) {
	if err := (scanConfig{}).validate(); err == nil {
		t.Error("validate() on an empty config = nil error, want an error requiring org")
	}
	if err := (scanConfig{Org: "attestor-demo"}).validate(); err != nil {
		t.Errorf("validate() with org set = %v, want nil", err)
	}
}
