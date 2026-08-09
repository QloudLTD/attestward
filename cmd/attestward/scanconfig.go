package main

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/github"
)

// Default values applied to any field left unset by both the config file
// and flags — see mergeScanConfig.
const (
	defaultReleaseTagPattern = "v*"
	defaultLookbackReleases  = 5
	defaultLookbackMonths    = 12
	defaultOut               = "./evidence/"
)

// Platform names scanConfig.Platform can take — the only three this build
// understands (issue #148's v0.2 platform seam; azuredevops has no real
// collectors yet, see defaultAzureDevOpsCollectors). platformGitHub is
// collect.DefaultPlatform under another name for readability at this
// package's many call sites, not a second source of truth for what the
// default actually is.
//
// platformGogs is the self-hosted-Gogs target (Gogs issue #3). Unlike the
// other two it has no hosted instance to default to — every Gogs install
// lives at its own hostname — so GogsURL is required alongside it, the same
// way Project is required alongside platformAzureDevOps.
const (
	platformGitHub      = collect.DefaultPlatform
	platformAzureDevOps = "azuredevops"
	platformGogs        = "gogs"
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
	// Platform selects which platform to scan: "github" (default),
	// "azuredevops" (issue #148's v0.2 platform seam) or "gogs" (Gogs
	// issue #3). Project is the Azure DevOps project name — required iff
	// Platform is "azuredevops", rejected otherwise (validate()).
	Platform string `yaml:"platform"`
	Project  string `yaml:"project"`
	// GogsURL is the base URL of the self-hosted Gogs instance to scan
	// (e.g. https://gogs.example.com) — required iff Platform is "gogs",
	// rejected otherwise, since there is no hosted Gogs service to fall
	// back on the way api.github.com serves platformGitHub. The value is
	// the browser-facing root, not the API root: the collect/gogs client
	// appends /api/v1 itself, so a user pastes what's in their address
	// bar. A path prefix is allowed rather than rejected — Gogs genuinely
	// supports being served under a suburl (its own templates carry a
	// data-suburl attribute), so https://example.com/gogs is a real
	// deployment, not a user mistake.
	GogsURL string `yaml:"gogs_url"`
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
	if flagsSet["gogs-url"] {
		merged.GogsURL = flags.GogsURL
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
// user-confusion bug this rejects rather than silently ignores. --gogs-url
// gets the identical treatment for platformGogs (Gogs issue #3). Platform
// itself may be empty here (validate() runs both after mergeScanConfig,
// which always defaults it, and directly against a raw scanConfig in
// tests) — an empty Platform is treated exactly like "github" throughout,
// never as its own third invalid state.
func (c scanConfig) validate() error {
	if c.Org == "" {
		return fmt.Errorf("org is required (--org or config file's org:)")
	}

	switch c.Platform {
	case "", platformGitHub, platformAzureDevOps, platformGogs:
	default:
		return fmt.Errorf("platform %q is not recognized (must be %q, %q or %q; --platform or config file's platform:)", c.Platform, platformGitHub, platformAzureDevOps, platformGogs)
	}

	isADO := effectivePlatform(c.Platform) == platformAzureDevOps
	switch {
	case isADO && c.Project == "":
		return fmt.Errorf("project is required when platform is %q (--project or config file's project:)", platformAzureDevOps)
	case !isADO && c.Project != "":
		return fmt.Errorf("--project (or config file's project:) is only valid when platform is %q (got platform %q)", platformAzureDevOps, effectivePlatform(c.Platform))
	}

	isGogs := effectivePlatform(c.Platform) == platformGogs
	switch {
	case isGogs && c.GogsURL == "":
		return fmt.Errorf("gogs_url is required when platform is %q (--gogs-url or config file's gogs_url:)", platformGogs)
	case !isGogs && c.GogsURL != "":
		return fmt.Errorf("--gogs-url (or config file's gogs_url:) is only valid when platform is %q (got platform %q)", platformGogs, effectivePlatform(c.Platform))
	case isGogs:
		if err := validateGogsURL(c.GogsURL); err != nil {
			return err
		}
	}
	return nil
}

// validateGogsURL rejects a --gogs-url that can't be a Gogs instance root
// before any scan work starts, so the failure names the config error
// instead of surfacing later as an opaque request failure. It deliberately
// does not reach the network: reachability is the scan's job to discover
// and report honestly, not a precondition to parse a flag.
//
// http is permitted alongside https — a Gogs instance on a LAN or behind a
// tunnel terminator is a real deployment, and refusing it would push users
// toward worse workarounds. The threat model already treats transport
// security as the operator's responsibility.
func validateGogsURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		// The url.Error this would wrap embeds the original string, so
		// even %w leaks a password-bearing URL — hence neither the value
		// nor the underlying error is included.
		return fmt.Errorf("gogs_url is not a valid URL")
	}
	// Checked first, before every other rule — but ordering alone is not
	// what makes this safe. No error below echoes the URL back either, and
	// that is the actual guarantee: a scheme-less paste like
	// "admin:s3cr3t@gogs.example.com" parses with Scheme "admin" and User
	// nil, so this check never fires for it, and the bad-scheme message
	// would have printed the password verbatim into stderr and CI logs.
	// Refusing to quote the input at all removes the whole class rather
	// than enumerating the parse shapes that leak. The user knows what they
	// passed; what they need is the rule they broke.
	//
	// Rejected rather than stripped, and duplicated in collect/gogs'
	// NewClient rather than deferred to it: credentials cannot work at all
	// (the Gogs API rejects basic auth even when correct), and the base URL
	// is recorded into the evidence pack, where url.URL.String() prints the
	// password verbatim. Catching it here names the config key the user got
	// wrong, before a scan starts.
	if u.User != nil {
		return fmt.Errorf("gogs_url must not contain credentials — the Gogs API rejects basic auth, and this URL is recorded in the evidence pack; set GOGS_TOKEN instead")
	}
	switch u.Scheme {
	case "http", "https":
	case "":
		return fmt.Errorf("gogs_url needs an http:// or https:// scheme (e.g. https://gogs.example.com)")
	default:
		return fmt.Errorf("gogs_url must use http or https (e.g. https://gogs.example.com)")
	}
	if u.Host == "" {
		return fmt.Errorf("gogs_url has no host (e.g. https://gogs.example.com)")
	}
	// ForceQuery catches a bare trailing "?", which leaves RawQuery empty
	// but survives into u.String() — a base that would concatenate into
	// "https://host?/api/v1", requesting path "/" with the API path as a
	// query string, and failing opaquely rather than loudly.
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("gogs_url must be a base URL, without a query string or fragment")
	}
	return nil
}
