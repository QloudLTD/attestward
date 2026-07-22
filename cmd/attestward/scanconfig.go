package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/github"
)

// Default values applied to any field left unset by both the config file
// and flags — see mergeScanConfig.
const (
	defaultReleaseTagPattern = "v*"
	defaultLookbackReleases  = 5
	defaultLookbackMonths    = 12
	defaultOut               = "./evidence/"
)

// Platform names scanConfig.Platform can take — the only two this build
// understands (issue #148's v0.2 platform seam; azuredevops has no real
// collectors yet, see defaultAzureDevOpsCollectors). platformGitHub is
// collect.DefaultPlatform under another name for readability at this
// package's many call sites, not a second source of truth for what the
// default actually is.
const (
	platformGitHub      = collect.DefaultPlatform
	platformAzureDevOps = "azuredevops"
)

// effectivePlatform returns platform, defaulting an empty value to
// platformGitHub — collect.NormalizePlatform, the single place this
// fallback is decided (internal/checksref and internal/packdiff call the
// same function). mergeScanConfig already fills this in for the normal CLI
// path, but callers that build a scanConfig directly (bypassing
// mergeScanConfig — e.g. the live integration test) still get correct
// behavior rather than writing an empty Platform into a pack or a "no
// collectors registered for platform \"\"" error.
func effectivePlatform(platform string) string {
	return collect.NormalizePlatform(platform)
}

// scanConfig is the parsed, merged configuration for `attestward scan`. Flags
// override file values field by field (mergeScanConfig); any field left
// unset by both gets its documented default.
type scanConfig struct {
	Org                 string   `yaml:"org"`
	Repos               []string `yaml:"repos"`
	ReleaseTagPattern   string   `yaml:"release_tag_pattern"`
	LookbackReleases    int      `yaml:"lookback_releases"`
	LookbackMonths      int      `yaml:"lookback_months"`
	SelfAttestationFile string   `yaml:"self_attestation_file"`
	Out                 string   `yaml:"out"`
	Concurrency         int      `yaml:"concurrency"`
	// Sign/SignArgs are issue #27's cosign integration: Sign is whether
	// to sign evidence.json after writing it, SignArgs is passed through
	// to `cosign sign-blob` verbatim (e.g. --key=cosign.key; empty for
	// keyless). See ADR-0006 for why this shells out rather than vendors
	// a Sigstore client.
	Sign     bool     `yaml:"sign"`
	SignArgs []string `yaml:"sign_args"`
	// Platform selects which platform to scan: "github" (default) or
	// "azuredevops" (issue #148's v0.2 platform seam). Project is the
	// Azure DevOps project name — required iff Platform is "azuredevops",
	// rejected otherwise (validate()).
	Platform string `yaml:"platform"`
	Project  string `yaml:"project"`
}

// loadScanConfigFile strictly parses a config file: unknown keys are
// errors, not silently ignored — a typo'd "respos:" that ends up scanning
// everything instead of the intended subset would be a truthfulness bug in
// a tool whose entire point is truthful evidence.
func loadScanConfigFile(path string) (scanConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return scanConfig{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)

	var cfg scanConfig
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			// An empty document (a zero-byte file, or one that's entirely
			// comments — plausible, since examples/attestward.yaml encourages
			// commenting fields out) isn't a parse failure; it's a config
			// with everything left to defaults. Downstream validate() gives
			// a much clearer error ("org is required") than a bare EOF would.
			return scanConfig{}, nil
		}
		return scanConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// mergeScanConfig layers flags over a (possibly zero-value, if no --config
// was given) file config, then fills in documented defaults for anything
// still unset. flags wins field by field: a flag value overrides the file
// only when the flag was actually set by the user (flagsSet), so an
// unset flag never clobbers a value the file provided.
func mergeScanConfig(file scanConfig, flags scanConfig, flagsSet map[string]bool) scanConfig {
	merged := file

	if flagsSet["org"] {
		merged.Org = flags.Org
	}
	if flagsSet["repo"] {
		merged.Repos = flags.Repos
	}
	if flagsSet["release-tag-pattern"] {
		merged.ReleaseTagPattern = flags.ReleaseTagPattern
	}
	if flagsSet["lookback-releases"] {
		merged.LookbackReleases = flags.LookbackReleases
	}
	if flagsSet["lookback-months"] {
		merged.LookbackMonths = flags.LookbackMonths
	}
	if flagsSet["self-attestation-file"] {
		merged.SelfAttestationFile = flags.SelfAttestationFile
	}
	if flagsSet["out"] {
		merged.Out = flags.Out
	}
	if flagsSet["concurrency"] {
		merged.Concurrency = flags.Concurrency
	}
	if flagsSet["sign"] {
		merged.Sign = flags.Sign
	}
	if flagsSet["sign-args"] {
		merged.SignArgs = flags.SignArgs
	}
	if flagsSet["platform"] {
		merged.Platform = flags.Platform
	}
	if flagsSet["project"] {
		merged.Project = flags.Project
	}

	if merged.ReleaseTagPattern == "" {
		merged.ReleaseTagPattern = defaultReleaseTagPattern
	}
	if merged.LookbackReleases <= 0 {
		merged.LookbackReleases = defaultLookbackReleases
	}
	if merged.LookbackMonths <= 0 {
		merged.LookbackMonths = defaultLookbackMonths
	}
	if merged.Out == "" {
		merged.Out = defaultOut
	}
	if merged.Concurrency == 0 {
		merged.Concurrency = github.DefaultConcurrency
	}
	if merged.Platform == "" {
		merged.Platform = platformGitHub
	}

	return merged
}

// validate checks scanConfig invariants, including the --platform/--project
// matrix (issue #148): Project is required iff Platform is azuredevops, and
// rejected otherwise — a --project passed against a github scan is a
// user-confusion bug this rejects rather than silently ignores. Platform
// itself may be empty here (validate() runs both after mergeScanConfig,
// which always defaults it, and directly against a raw scanConfig in
// tests) — an empty Platform is treated exactly like "github" throughout,
// never as its own third invalid state.
func (c scanConfig) validate() error {
	if c.Org == "" {
		return fmt.Errorf("org is required (--org or config file's org:)")
	}

	switch c.Platform {
	case "", platformGitHub, platformAzureDevOps:
	default:
		return fmt.Errorf("platform %q is not recognized (must be %q or %q; --platform or config file's platform:)", c.Platform, platformGitHub, platformAzureDevOps)
	}

	isADO := effectivePlatform(c.Platform) == platformAzureDevOps
	switch {
	case isADO && c.Project == "":
		return fmt.Errorf("project is required when platform is %q (--project or config file's project:)", platformAzureDevOps)
	case !isADO && c.Project != "":
		return fmt.Errorf("--project (or config file's project:) is only valid when platform is %q (got platform %q)", platformAzureDevOps, effectivePlatform(c.Platform))
	}
	return nil
}
