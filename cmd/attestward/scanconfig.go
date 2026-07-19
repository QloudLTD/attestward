package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

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

	return merged
}

func (c scanConfig) validate() error {
	if c.Org == "" {
		return fmt.Errorf("org is required (--org or config file's org:)")
	}
	return nil
}
