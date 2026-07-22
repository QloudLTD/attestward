package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadScanConfigFile_ExampleFileParses is a regression test on the
// actual shipped examples/attestward.yaml: if a future edit breaks its YAML
// or introduces an unrecognized key, this catches it in CI rather than
// leaving users of the README quickstart to discover it themselves.
func TestLoadScanConfigFile_ExampleFileParses(t *testing.T) {
	cfg, err := loadScanConfigFile("../../examples/attestward.yaml")
	if err != nil {
		t.Fatalf("loadScanConfigFile(examples/attestward.yaml): %v", err)
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
// entirely comments — plausible, since examples/attestward.yaml explicitly
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
	path := filepath.Join(dir, "attestward.yaml")
	content := "org: attestward-demo\nrepos: [good-repo, other-repo]\nout: ./evidence/\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cfg, err := loadScanConfigFile(path)
	if err != nil {
		t.Fatalf("loadScanConfigFile: %v", err)
	}
	if cfg.Org != "attestward-demo" {
		t.Errorf("Org = %q, want attestward-demo", cfg.Org)
	}
	if len(cfg.Repos) != 2 {
		t.Errorf("len(Repos) = %d, want 2", len(cfg.Repos))
	}
}

func TestLoadScanConfigFile_RejectsUnknownKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "attestward.yaml")
	// "respos" is a realistic typo for "repos" — the whole point of strict
	// parsing is that this must error, not silently scan everything.
	content := "org: attestward-demo\nrespos: [good-repo]\n"
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

// TestMergeScanConfig_SignFlagsOverrideFileWhenSet mirrors
// TestMergeScanConfig_FlagsOverrideFileWhenSet for the issue #27 fields —
// Sign/SignArgs need the same flagsSet-gated override behavior as every
// other field (a flag the user didn't pass must never clobber a value the
// config file set).
func TestMergeScanConfig_SignFlagsOverrideFileWhenSet(t *testing.T) {
	file := scanConfig{Org: "x", Sign: true, SignArgs: []string{"--key=file.key"}}

	// Neither --sign nor --sign-args passed: file values survive.
	merged := mergeScanConfig(file, scanConfig{}, nil)
	if !merged.Sign {
		t.Error("Sign = false, want true (from file, no flag override)")
	}
	if len(merged.SignArgs) != 1 || merged.SignArgs[0] != "--key=file.key" {
		t.Errorf("SignArgs = %v, want [--key=file.key] (from file, no flag override)", merged.SignArgs)
	}

	// --sign-args passed (but not --sign): only SignArgs overrides.
	merged = mergeScanConfig(file, scanConfig{SignArgs: []string{"--key=flag.key"}}, map[string]bool{"sign-args": true})
	if !merged.Sign {
		t.Error("Sign = false, want true (--sign not passed, file value preserved)")
	}
	if len(merged.SignArgs) != 1 || merged.SignArgs[0] != "--key=flag.key" {
		t.Errorf("SignArgs = %v, want [--key=flag.key] (--sign-args was passed)", merged.SignArgs)
	}

	// --sign passed explicitly false (e.g. a config file sets sign: true
	// but this one invocation wants it off): flag wins.
	merged = mergeScanConfig(file, scanConfig{Sign: false}, map[string]bool{"sign": true})
	if merged.Sign {
		t.Error("Sign = true, want false (--sign was explicitly passed as false)")
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

// TestMergeScanConfig_DefaultsFillNegativeLookbackValues guards against a
// regression the C05 review caught: a negative --lookback-months or
// --lookback-releases (a malformed flag, not a deliberate zero) must be
// clamped to the documented default just like an unset (zero) value would
// be — otherwise it flows through to the collector as-is, producing a
// windowStart in the future and silently-misleading "no releases match"
// output instead of a clear validation error or a sane default.
func TestMergeScanConfig_DefaultsFillNegativeLookbackValues(t *testing.T) {
	merged := mergeScanConfig(scanConfig{Org: "x", LookbackReleases: -3, LookbackMonths: -1}, scanConfig{}, nil)

	if merged.LookbackReleases != defaultLookbackReleases {
		t.Errorf("LookbackReleases = %d, want %d (negative input clamped to default)", merged.LookbackReleases, defaultLookbackReleases)
	}
	if merged.LookbackMonths != defaultLookbackMonths {
		t.Errorf("LookbackMonths = %d, want %d (negative input clamped to default)", merged.LookbackMonths, defaultLookbackMonths)
	}
}

func TestScanConfigValidate_RequiresOrg(t *testing.T) {
	if err := (scanConfig{}).validate(); err == nil {
		t.Error("validate() on an empty config = nil error, want an error requiring org")
	}
	if err := (scanConfig{Org: "attestward-demo"}).validate(); err != nil {
		t.Errorf("validate() with org set = %v, want nil", err)
	}
}

// TestScanConfigValidate_PlatformProjectMatrix pins issue #148's CLI
// validation matrix: --project is required for azuredevops, rejected for
// github (including the empty-Platform case, which mergeScanConfig would
// otherwise have defaulted to github before validate() ever normally sees
// it — this test calls validate() directly, as TestScanConfigValidate_
// RequiresOrg above does, to prove the empty case is handled here too, not
// only downstream of mergeScanConfig).
func TestScanConfigValidate_PlatformProjectMatrix(t *testing.T) {
	cases := []struct {
		name    string
		cfg     scanConfig
		wantErr bool
	}{
		{"github, no project", scanConfig{Org: "x", Platform: "github"}, false},
		{"empty platform, no project", scanConfig{Org: "x"}, false},
		{"github, project given", scanConfig{Org: "x", Platform: "github", Project: "proj"}, true},
		{"empty platform, project given", scanConfig{Org: "x", Project: "proj"}, true},
		{"azuredevops, project given", scanConfig{Org: "x", Platform: "azuredevops", Project: "proj"}, false},
		{"azuredevops, no project", scanConfig{Org: "x", Platform: "azuredevops"}, true},
		{"unrecognized platform", scanConfig{Org: "x", Platform: "gitlab"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if tc.wantErr && err == nil {
				t.Errorf("validate() = nil error, want an error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validate() = %v, want nil", err)
			}
		})
	}
}

func TestMergeScanConfig_PlatformDefaultsToGitHubAndProjectPassesThrough(t *testing.T) {
	merged := mergeScanConfig(scanConfig{Org: "x"}, scanConfig{}, nil)
	if merged.Platform != platformGitHub {
		t.Errorf("Platform = %q, want %q", merged.Platform, platformGitHub)
	}

	merged = mergeScanConfig(scanConfig{Org: "x"}, scanConfig{Platform: "azuredevops", Project: "proj"}, map[string]bool{"platform": true, "project": true})
	if merged.Platform != "azuredevops" {
		t.Errorf("Platform = %q, want azuredevops (flag was set)", merged.Platform)
	}
	if merged.Project != "proj" {
		t.Errorf("Project = %q, want proj (flag was set)", merged.Project)
	}
}

// TestMergeScanConfig_PlatformProjectFlagsDoNotClobberFileWhenUnset mirrors
// TestMergeScanConfig_FlagsOverrideFileWhenSet for the new fields: a flag
// the user didn't pass must never clobber a value the config file set.
func TestMergeScanConfig_PlatformProjectFlagsDoNotClobberFileWhenUnset(t *testing.T) {
	file := scanConfig{Org: "x", Platform: "azuredevops", Project: "file-proj"}
	merged := mergeScanConfig(file, scanConfig{}, nil)
	if merged.Platform != "azuredevops" {
		t.Errorf("Platform = %q, want azuredevops (from file, no flag override)", merged.Platform)
	}
	if merged.Project != "file-proj" {
		t.Errorf("Project = %q, want file-proj (from file, no flag override)", merged.Project)
	}
}
