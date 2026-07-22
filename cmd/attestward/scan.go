package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/azuredevops"
	adoauditlogging "github.com/sioakim/attestward/internal/collect/azuredevops/auditlogging"
	adoenvseparation "github.com/sioakim/attestward/internal/collect/azuredevops/envseparation"
	adoorgsecurity "github.com/sioakim/attestward/internal/collect/azuredevops/orgsecurity"
	adoprovenance "github.com/sioakim/attestward/internal/collect/azuredevops/provenance"
	adorepoprotection "github.com/sioakim/attestward/internal/collect/azuredevops/repoprotection"
	adosasthistory "github.com/sioakim/attestward/internal/collect/azuredevops/sasthistory"
	adosecretshygiene "github.com/sioakim/attestward/internal/collect/azuredevops/secretshygiene"
	advdp "github.com/sioakim/attestward/internal/collect/azuredevops/vdp"
	ghcollect "github.com/sioakim/attestward/internal/collect/github"
	"github.com/sioakim/attestward/internal/collect/github/actionssecurity"
	"github.com/sioakim/attestward/internal/collect/github/auditlogging"
	"github.com/sioakim/attestward/internal/collect/github/envseparation"
	"github.com/sioakim/attestward/internal/collect/github/orgsecurity"
	"github.com/sioakim/attestward/internal/collect/github/provenance"
	"github.com/sioakim/attestward/internal/collect/github/repoprotection"
	"github.com/sioakim/attestward/internal/collect/github/sasthistory"
	"github.com/sioakim/attestward/internal/collect/github/scahistory"
	"github.com/sioakim/attestward/internal/collect/github/secretshygiene"
	"github.com/sioakim/attestward/internal/collect/github/vdp"
	"github.com/sioakim/attestward/internal/integrity"
	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
	"github.com/sioakim/attestward/mappings"
)

// logf writes a progress/warning line to w, ignoring the write error: this
// is user-facing progress output, not data whose delivery the program's
// correctness depends on, and there's nothing actionable to do if stdout
// itself is broken.
func logf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// Exit codes per issue #10: 0 all verified-pass, 2 gaps found (any
// verified-fail/partial — self-attested/not-checkable alone never trigger
// this), 1 execution error.
const (
	exitOK    = 0
	exitGaps  = 2
	exitError = 1
)

var (
	scanFlags       scanConfig
	scanConfigPath  string
	scanCheckFilter []string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a GitHub org/repo and emit an evidence pack",
	Long: `attestward scan resolves scope, runs every registered collector, rolls
results up through the SSDF/CISA mappings, and writes evidence.json into
--out.

Exit codes: 0 all verified-pass, 2 gaps found (any verified-fail/partial —
self-attested and not-checkable results alone never cause this), 1 execution
error.`,
	RunE: runScanCmd,
}

func init() {
	scanCmd.Flags().StringVar(&scanFlags.Org, "org", "", "GitHub account to scan — an org or a personal user account (required, unless set in --config)")
	scanCmd.Flags().StringArrayVar(&scanFlags.Repos, "repo", nil, "repo to scan (repeatable); empty scans all non-archived, non-fork repos")
	scanCmd.Flags().StringVar(&scanConfigPath, "config", "", "path to a YAML config file (see examples/attestward.yaml); flags override its values")
	scanCmd.Flags().StringVar(&scanFlags.ReleaseTagPattern, "release-tag-pattern", "", "glob (filepath.Match syntax, not regex) for release tags in scope (default \"v*\")")
	scanCmd.Flags().IntVar(&scanFlags.LookbackReleases, "lookback-releases", 0, "releases to look back over (default 5)")
	scanCmd.Flags().IntVar(&scanFlags.LookbackMonths, "lookback-months", 0, "months to look back over (default 12)")
	scanCmd.Flags().StringVar(&scanFlags.SelfAttestationFile, "self-attestation-file", "", "path to a self-attestation answers file (issue #23)")
	scanCmd.Flags().StringVar(&scanFlags.Out, "out", "", "output directory (default \"./evidence/\")")
	scanCmd.Flags().IntVar(&scanFlags.Concurrency, "concurrency", 0, "collector concurrency (default 4)")
	scanCmd.Flags().StringSliceVar(&scanCheckFilter, "check", nil, "comma-separated check-ID prefixes to run (e.g. C01,C05); default runs every registered collector")
	scanCmd.Flags().BoolVar(&scanFlags.Sign, "sign", false, "sign evidence.json with cosign sign-blob after writing it (issue #27; requires cosign on PATH)")
	scanCmd.Flags().StringArrayVar(&scanFlags.SignArgs, "sign-args", nil, "extra arg passed through to cosign sign-blob verbatim (repeatable, e.g. --sign-args=--key=cosign.key); omit for keyless signing")
	scanCmd.Flags().StringVar(&scanFlags.Platform, "platform", "", "platform to scan: github or azuredevops (default \"github\")")
	scanCmd.Flags().StringVar(&scanFlags.Project, "project", "", "Azure DevOps project name (required iff --platform azuredevops; rejected otherwise)")
	rootCmd.AddCommand(scanCmd)
}

// defaultGitHubCollectors builds the full set of real GitHub collectors
// authenticated with token — the same wiring runScanCmd uses for a github
// scan, extracted so the integration test (issue #15) exercises the exact
// same collector set the shipped binary runs, without duplicating this list
// and risking drift as new collectors land. Each real collector gets its
// own dedicated Client instance rather than sharing one: Client.Provenance()
// reflects every call made through it, and each collector attributes
// provenance to its CheckResults by diffing that log, which only stays
// correct if nothing else (another collector run concurrently) issues calls
// through the same Client. repoprotection/envseparation/secretshygiene/
// sasthistory/scahistory/provenance/actionssecurity/auditlogging/vdp take
// the token directly rather than a pre-built Client since they construct a
// fresh Client per repo internally (see their own doc comments for why).
func defaultGitHubCollectors(token string) []collect.Collector {
	return append(collect.Collectors(),
		orgsecurity.New(ghcollect.NewClient(token)),
		repoprotection.New(token),
		envseparation.New(token),
		secretshygiene.New(token),
		sasthistory.New(token),
		scahistory.New(token),
		provenance.New(token),
		actionssecurity.New(token),
		auditlogging.New(token),
		vdp.New(token),
	)
}

// defaultAzureDevOpsCollectors mirrors defaultGitHubCollectors' role for a
// --platform azuredevops scan. C01 org-security, C02 repo-protection (both
// issue #150, S4's two PRs), C03 env-separation, C04 secrets-hygiene (both
// issue #151, S5's two PRs), C05 sast-history (issue #152, S6's first of
// three PRs — pipelinehistory landed first, sca-history follows), C09
// audit-logging, C10 vdp (both issue #154, S8's two PRs), and C07
// provenance (issue #153, S7's first of two PRs) are the eight ADO
// collectors landed so far. org-security and auditlogging are both
// org-scoped only (auditlogging reads project from collect.Scope.Project
// at Collect time rather than a constructor argument), so both take a
// pre-built Client sharing one org+pat pair. repoprotection, envseparation,
// sasthistory, and provenance are also project-scoped rather than truly
// per-repo — envseparation's own two backing calls (environments,
// per-environment check configurations) each happen once per Collect, not
// once per repo, and its results carry Scope.Project with Scope.Repo left
// empty (see its own package doc comment); sasthistory's and provenance's
// own pipeline discovery (ListPipelines, MatchPipelines) and repository
// listing likewise happen exactly once per Collect, the same as
// repoprotection's two backing calls, filtered client-side per repo — so
// all four take a pre-built Client the same way. vdp and secretshygiene are
// different: both are genuinely per-repo (Azure DevOps has no per-repo
// webhook concept the way GitHub does, but SECURITY.md and GHAzDO repo
// enablement are each genuinely per-repo), so — mirroring their own GitHub
// twins' per-repo collectors — both constructors take (org, pat) directly
// and build a fresh Client per repo internally, rather than sharing one
// Client the way the six project/org-scoped collectors above do.
// secretshygiene is also the first ADO collector spanning all three scope
// levels at once (org, project, and per-repo) in a single Collect() call —
// see its own package doc comment for how it isolates provenance across
// all three.
//
// repoprotection was the first ADO collector to actually consult
// scope.Repos; vdp, sasthistory, secretshygiene, and provenance do too:
// buildScanDeps below still has no ADO repoLister, so a real `attestward
// scan --platform azuredevops` invocation needs an explicit --repo
// (resolveRepos' own nil-lister guard is what enforces that) until a later
// story adds one. envseparation never consults scope.Repos at all
// (environments are project-scoped, not repo-scoped), so it doesn't change
// that requirement either way. Collectors for the remaining stories (the
// rest of S6, S7) append here the same way as they land.
func defaultAzureDevOpsCollectors(org, _, pat string) []collect.Collector {
	return append(collect.Collectors(),
		adoorgsecurity.New(azuredevops.NewClient(org, pat)),
		adorepoprotection.New(azuredevops.NewClient(org, pat)),
		adoenvseparation.New(azuredevops.NewClient(org, pat)),
		adoauditlogging.New(azuredevops.NewClient(org, pat)),
		advdp.New(org, pat),
		adosasthistory.New(azuredevops.NewClient(org, pat)),
		adosecretshygiene.New(org, pat),
		adoprovenance.New(azuredevops.NewClient(org, pat)),
	)
}

// runScanCmd is cobra's entry point: it resolves config, builds real
// dependencies (a live client from the platform-appropriate token env var,
// the real repo lister, the collector registry), and delegates to the
// testable core (runScan). Exit codes 0/1/2 are custom (cobra's own RunE-error
// path only ever yields 0 or 1 via root.go's Execute), so a gaps-found result
// calls os.Exit(exitGaps) directly rather than returning an error.
func runScanCmd(cmd *cobra.Command, _ []string) error {
	var fileCfg scanConfig
	if scanConfigPath != "" {
		var err error
		fileCfg, err = loadScanConfigFile(scanConfigPath)
		if err != nil {
			return err
		}
	}

	flagsSet := map[string]bool{}
	cmd.Flags().Visit(func(f *pflag.Flag) { flagsSet[f.Name] = true })
	cfg := mergeScanConfig(fileCfg, scanFlags, flagsSet)
	if err := cfg.validate(); err != nil {
		return err
	}

	token, err := resolveScanToken(cfg.Platform)
	if err != nil {
		return err
	}
	deps, err := buildScanDeps(cfg, token, cmd.OutOrStdout())
	if err != nil {
		return err
	}

	result, err := runScan(cmd.Context(), cfg, scanCheckFilter, deps)
	if err != nil {
		return err
	}

	hash, err := writeEvidencePack(result.pack, cfg.Out)
	if err != nil {
		return err
	}
	evidencePath := filepath.Join(cfg.Out, "evidence.json")
	if err := integrity.WriteSidecar(evidencePath, hash); err != nil {
		return err
	}
	logf(deps.stdout, "wrote %s\n", evidencePath)
	logf(deps.stdout, "sha256: %s\n", hash)

	// Signing runs regardless of exitOK/exitGaps below — a pack showing
	// real gaps needs a genuine signature at least as much as a clean
	// one, arguably more (a producer proving the evidence wasn't altered
	// to look better than it does). It must run before the exit-code
	// branch, which terminates the process immediately.
	if cfg.Sign {
		bundlePath, err := deps.signer.SignBlob(cmd.Context(), evidencePath, cfg.SignArgs)
		if err != nil {
			return fmt.Errorf("--sign: %w", err)
		}
		logf(deps.stdout, "signed: %s\n", bundlePath)
	}

	if result.exitCode != exitOK {
		os.Exit(result.exitCode)
	}
	return nil
}

// resolveScanToken picks the credential env var for platform: GITHUB_TOKEN
// for github (unchanged from before issue #148 — every existing setup keeps
// working), AZURE_DEVOPS_EXT_PAT for azuredevops (the az-CLI convention, so
// an existing az-CLI environment already has it set). GITHUB_TOKEN is never
// consulted for an azuredevops scan, and the error says so explicitly
// rather than leaving a user with GITHUB_TOKEN exported to guess why it
// didn't help.
func resolveScanToken(platform string) (string, error) {
	if effectivePlatform(platform) == platformAzureDevOps {
		pat := os.Getenv("AZURE_DEVOPS_EXT_PAT")
		if pat == "" {
			return "", fmt.Errorf("AZURE_DEVOPS_EXT_PAT is not set (GITHUB_TOKEN is ignored for --platform azuredevops)")
		}
		return pat, nil
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return "", fmt.Errorf("GITHUB_TOKEN is not set")
	}
	return token, nil
}

// buildScanDeps wires the real dependencies runScanCmd passes to runScan,
// branching on cfg.Platform: a github scan gets a live GitHub client plus
// its repo lister/org checker; an azuredevops scan still leaves
// repoLister/orgChecker nil, since there's no ADO implementation of either
// yet — a real gap, but not this collector's to close. orgChecker is moot
// for ADO regardless (Azure DevOps orgs have no personal-account/
// organization distinction the way GitHub does — see collect.AccountType's
// own doc comment). repoLister is a real, now-live gap as of C02
// repo-protection (issue #150, S4's second PR): unlike C01/C09, it
// genuinely consults scope.Repos, so an azuredevops scan run without an
// explicit --repo hits resolveRepos' nil-lister guard for real (an
// actionable error asking for --repo, not a silent no-op or a panic) —
// previously this path was reachable but moot, since nothing yet in scope
// read scope.Repos at all. --repo is required for a useful ADO scan today;
// the first story to add a proper ADO repoLister (issue #34) is what
// removes that requirement, not this one.
//
// An azuredevops scan with zero collectors errors here rather than being
// let through to runScan (which — matching its established contract, see
// e.g. TestRunScan_SelfAttestationFileProvided_AnsweredQuestionsAreSelfAttested
// — tolerates an empty collector set and just runs self-attestation, a
// deliberate testing seam, not a production signal): a real `attestward
// scan --platform azuredevops` invocation producing a pack with zero
// API-verified results would look like a clean, fully-verified scan
// instead of the honest "this platform isn't implemented yet" it actually
// is, so the CLI wiring layer is where that gets refused. This guard is
// dead code once at least one ADO collector is registered (true as of
// issue #150), but it's left in place rather than removed: an empty result
// from defaultAzureDevOpsCollectors would again mean "nothing implemented",
// not "nothing applicable to this scan" (every registered collector always
// runs), so the same honest refusal is still the right behavior if that
// ever recurs.
func buildScanDeps(cfg scanConfig, token string, stdout io.Writer) (scanDeps, error) {
	if effectivePlatform(cfg.Platform) == platformAzureDevOps {
		collectors := defaultAzureDevOpsCollectors(cfg.Org, cfg.Project, token)
		if len(collectors) == 0 {
			return scanDeps{}, fmt.Errorf("no collectors registered for platform %q yet (see issue #34's epic)", platformAzureDevOps)
		}
		return scanDeps{
			collectors: collectors,
			stdout:     stdout,
			signer:     integrity.CosignSigner{},
		}, nil
	}

	client := ghcollect.NewClient(token)
	return scanDeps{
		repoLister: &restRepoLister{client: client.REST},
		orgChecker: &restOrgChecker{client: client.REST},
		client:     client,
		collectors: defaultGitHubCollectors(token),
		stdout:     stdout,
		signer:     integrity.CosignSigner{},
	}, nil
}

// scanDeps are runScan's injected dependencies — real ones from
// runScanCmd, fixture/fake ones from tests.
type scanDeps struct {
	repoLister repoLister
	orgChecker orgChecker
	client     *ghcollect.Client
	collectors []collect.Collector
	stdout     io.Writer
	// now overrides how runScan reads the current time (ScanStartedAt/
	// ScanEndedAt); nil defaults to time.Now. Exists so a determinism test
	// can run runScan twice with an identical fixed clock and assert the
	// two resulting evidence.json byte streams are exactly equal (issue
	// #24's "same inputs => byte-identical output" requirement) — real
	// scans always leave this nil, since two independent scans genuinely
	// happening at different wall-clock times is correct, not a bug.
	now func() time.Time
	// signer is the real or fake cosign wrapper runScanCmd calls after
	// writeEvidencePack when --sign is set. Not used by runScan itself
	// (signing happens after runScan returns, over the written file) —
	// lives here anyway so every real-vs-fake dependency swap for tests
	// stays in one struct rather than splitting the convention.
	signer integrity.Signer
}

type scanResult struct {
	pack     model.EvidencePack
	exitCode int
}

// runScan is the testable core of `attestward scan`: preflight, resolve
// scope, run collectors, roll up, assemble the pack. It does not write any
// file — that's writeEvidencePack, called separately so tests can assert on
// the assembled pack without touching the filesystem.
func runScan(ctx context.Context, cfg scanConfig, checkFilter []string, deps scanDeps) (scanResult, error) {
	now := deps.now
	if now == nil {
		now = time.Now
	}
	startedAt := now().UTC()

	// Preflight: confirm the account is actually visible with this token
	// (issue #10's explicit "org visible" requirement) *before* resolving
	// scope or collecting, and (issue #102) discover whether it's an
	// Organization or a personal User account — every collector that makes
	// an org-scoped call needs this to give an honest, specific
	// not-checkable reason for a user-account target instead of guessing
	// from a 404. This doubles as the guaranteed first authenticated call:
	// the write-scope warning below reads Client.HasWriteScope(), which has
	// nothing to report on until at least one authenticated response has
	// been observed (scopes.go) — so checking write-scope before any call
	// ever fires would silently skip the warning whenever repos are given
	// explicitly (resolveRepos then makes zero API calls).
	//
	// accountType is left at its zero value (collect.AccountTypeUnknown)
	// when deps.orgChecker is nil (every test that doesn't exercise
	// preflight directly) — collect.AccountTypeUnknown's own doc comment
	// requires collectors to treat it exactly like
	// collect.AccountTypeOrganization, so this preserves every existing
	// test's behavior unchanged.
	var accountType collect.AccountType
	if deps.orgChecker != nil {
		at, err := deps.orgChecker.CheckAccount(ctx, cfg.Org)
		if err != nil {
			return scanResult{}, fmt.Errorf("preflight: account %s not visible: %w", cfg.Org, err)
		}
		accountType = at
	}

	repos, err := resolveRepos(ctx, deps.repoLister, cfg.Org, accountType, cfg.Repos, func(msg string) {
		logf(deps.stdout, "warning: %s\n", msg)
	})
	if err != nil {
		return scanResult{}, fmt.Errorf("resolve repos: %w", err)
	}

	scope := collect.Scope{
		Org:               cfg.Org,
		AccountType:       accountType,
		Repos:             repos,
		Project:           cfg.Project,
		ReleaseTagPattern: cfg.ReleaseTagPattern,
		LookbackReleases:  cfg.LookbackReleases,
		LookbackMonths:    cfg.LookbackMonths,
	}
	accountTypeLabel := string(scope.AccountType)
	if accountTypeLabel == "" {
		accountTypeLabel = "unknown"
	}
	logf(deps.stdout, "scope: org=%s account_type=%s repos=%d release_tag_pattern=%s lookback=%d releases/%d months\n",
		scope.Org, accountTypeLabel, len(scope.Repos), scope.ReleaseTagPattern, scope.LookbackReleases, scope.LookbackMonths)

	if deps.client != nil && deps.client.HasWriteScope() {
		logf(deps.stdout, "warning: token has scopes beyond read-only: %v (least-privilege guidance: use a read-only fine-grained PAT)\n", deps.client.Scopes())
	}

	collectors := filterCollectors(deps.collectors, checkFilter)
	if len(checkFilter) > 0 && len(collectors) == 0 && len(deps.collectors) > 0 {
		return scanResult{}, fmt.Errorf("--check %s matched no registered collector (check for a typo)", strings.Join(checkFilter, ","))
	}
	logf(deps.stdout, "running %d collector(s)\n", len(collectors))

	results, outcomes := runCollectors(ctx, collectors, scope, cfg.Concurrency)
	for _, o := range outcomes {
		status := "done"
		if o.err != nil {
			status = "failed: " + o.err.Error()
		}
		logf(deps.stdout, "  %s: %s\n", o.id, status)
	}
	if ctx.Err() != nil {
		// A collector run that was interrupted mid-flight must not produce
		// a plausible-looking pack at exit 0 — see runCollectors' doc
		// comment for what happens to not-yet-started collectors.
		return scanResult{}, fmt.Errorf("scan canceled: %w", ctx.Err())
	}

	ssdf, err := mapping.LoadSSDFFS(mappings.FS, "ssdf-800-218.yaml")
	if err != nil {
		return scanResult{}, fmt.Errorf("load ssdf mapping: %w", err)
	}
	cisa, err := mapping.LoadCISAFS(mappings.FS, "cisa-ssda-form.yaml", ssdf)
	if err != nil {
		return scanResult{}, fmt.Errorf("load cisa mapping: %w", err)
	}

	saQuestions, err := mapping.LoadSelfAttestationQuestionsFS(mappings.FS, "self-attestation-questions.yaml", ssdf)
	if err != nil {
		return scanResult{}, fmt.Errorf("load self-attestation questions: %w", err)
	}
	var saAnswers *mapping.SelfAttestationAnswers
	if cfg.SelfAttestationFile != "" {
		saAnswers, err = mapping.LoadSelfAttestationAnswers(cfg.SelfAttestationFile, saQuestions)
		if err != nil {
			return scanResult{}, fmt.Errorf("load self-attestation answers: %w", err)
		}
	} else {
		logf(deps.stdout, "warning: no self-attestation answers file given (--self-attestation-file) — %d self-attestation question(s) will be not-checkable\n", len(saQuestions.Questions))
	}
	results = append(results, mapping.BuildSelfAttestedResults(saQuestions, saAnswers, cfg.Org)...)
	// Re-sort after appending self-attestation results — runCollectors
	// already sorted the API-check results by CheckID, but that sort ran
	// before these existed; the pack's own sorted-output guarantee (see
	// runCollectors' doc comment) must hold across the full Results slice,
	// not just the portion collectors produced.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].CheckID != results[j].CheckID {
			return results[i].CheckID < results[j].CheckID
		}
		return results[i].Scope.Repo < results[j].Scope.Repo
	})

	// The orchestrator, not each collector, is the single source of truth
	// for which platform a result belongs to (found in review of #164): a
	// pack is one scan of one platform (no mixed-platform packs), so every
	// result — including the not-checkable ones runCollectors and
	// BuildSelfAttestedResults synthesize themselves, which never set
	// Scope.Platform — is stamped here, unconditionally, rather than
	// trusting N different collector implementations across N platforms to
	// all remember to set it themselves.
	stampResultsWithPlatform(results, effectivePlatform(cfg.Platform), cfg.Project)

	rollup := mapping.BuildRollup(results, ssdf, cisa)

	endedAt := now().UTC()

	pack := model.EvidencePack{
		SchemaVersion: model.SchemaVersion,
		ToolVersion:   version,
		MappingVersions: model.MappingVersions{
			SSDF:            ssdf.Version,
			CISAForm:        cisa.Version,
			SelfAttestation: saQuestions.Version,
		},
		// Built field-by-field, not a model.ScanScope(scope) conversion:
		// collect.Scope carries AccountType (issue #102), which the
		// persisted evidence-pack schema doesn't need — the same
		// information already surfaces per-check via each not-checkable
		// CheckResult's own Reason text, so it'd be redundant schema
		// surface, not new honesty.
		//
		// Platform is always written explicitly (effectivePlatform, never
		// cfg.Platform raw) rather than left absent, even when it's
		// "github" and absent would mean the same thing: a long-lived
		// legal artifact should be self-describing, not lean on an
		// implicit default a reader years from now has to already know to
		// assume.
		Scope: model.ScanScope{
			Org:               scope.Org,
			Repos:             scope.Repos,
			ReleaseTagPattern: scope.ReleaseTagPattern,
			LookbackReleases:  scope.LookbackReleases,
			LookbackMonths:    scope.LookbackMonths,
			Platform:          effectivePlatform(cfg.Platform),
			Project:           cfg.Project,
		},
		ScanStartedAt: startedAt,
		ScanEndedAt:   endedAt,
		Results:       results,
		Rollup:        &rollup,
	}
	pack.Scrub()

	// Advisory only — see ValidateFactsSizes' doc comment for why an
	// oversized fact warns instead of aborting the write: a large org's
	// genuinely large finding count (many unpinned actions, a long
	// release history) is a real, correct result this tool exists to
	// report, not a reason to discard the entire scan's evidence.
	if err := pack.ValidateFactsSizes(); err != nil {
		logf(deps.stdout, "warning: %v\n", err)
	}

	return scanResult{pack: pack, exitCode: computeExitCode(results)}, nil
}

// stampResultsWithPlatform sets every result's Scope.Platform/Project to
// the scan's own platform/project, in place, overwriting whatever (if
// anything) a collector already set — the orchestrator is authoritative
// here, not each collector; see runScan's call site for why.
func stampResultsWithPlatform(results []model.CheckResult, platform, project string) {
	for i := range results {
		results[i].Scope.Platform = platform
		results[i].Scope.Project = project
	}
}

// computeExitCode implements issue #10's exit-code table: any
// verified-fail/partial is a gap (2); self-attested/not-checkable alone
// never trigger a gap exit — they're visible in the report but aren't
// verified failures.
func computeExitCode(results []model.CheckResult) int {
	for _, r := range results {
		if r.Status == model.StatusVerifiedFail || r.Status == model.StatusPartial {
			return exitGaps
		}
	}
	return exitOK
}

// filterCollectors applies --check: a collector runs if its ID has any of
// the filter prefixes (e.g. "C01" matches "C01.org-security"). An empty
// filter runs every collector.
func filterCollectors(all []collect.Collector, checkFilter []string) []collect.Collector {
	if len(checkFilter) == 0 {
		return all
	}
	out := make([]collect.Collector, 0, len(all))
	for _, c := range all {
		for _, prefix := range checkFilter {
			if strings.HasPrefix(c.ID(), prefix) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// collectorOutcome is one collector's run result, kept alongside the
// flattened CheckResults so callers can print an accurate per-collector
// summary line (issue #10's "summary line per collector") without
// re-deriving which collector failed from the synthesized not-checkable
// results.
type collectorOutcome struct {
	id  string
	err error
}

// runCollectors runs every collector with up to concurrency in flight at
// once. A collector error never aborts the scan: it's recorded as a single
// not-checkable CheckResult and every other collector still runs to
// completion (issue #9's Collector contract) — but the caller must still
// check ctx.Err() afterward: a canceled context surfaces here as exactly
// that kind of per-collector "error", which would otherwise let a scan
// interrupted mid-flight produce a plausible-looking pack instead of
// failing loudly. Results are sorted by CheckID (SliceStable, since the
// comparator isn't a total order across repos within the same check —
// full determinism guarantees are issue #24's job).
func runCollectors(ctx context.Context, collectors []collect.Collector, scope collect.Scope, concurrency int) ([]model.CheckResult, []collectorOutcome) {
	if concurrency <= 0 {
		concurrency = ghcollect.DefaultConcurrency
	}

	type rawOutcome struct {
		id      string
		results []model.CheckResult
		err     error
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	outcomes := make([]rawOutcome, len(collectors))

	for i, c := range collectors {
		// Explicit pre-check, not just the select below: when ctx is
		// already canceled AND the semaphore has room (the common case for
		// the first collector, or whenever concurrency exceeds what's
		// currently in flight), both select cases are immediately ready
		// and Go picks between them at random — so an already-canceled
		// context could still let a collector through on chance alone
		// without this fast path.
		if ctx.Err() != nil {
			outcomes[i] = rawOutcome{id: c.ID(), err: ctx.Err()}
			continue
		}
		select {
		case <-ctx.Done():
			outcomes[i] = rawOutcome{id: c.ID(), err: ctx.Err()}
			continue
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(i int, c collect.Collector) {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := c.Collect(ctx, scope)
			outcomes[i] = rawOutcome{id: c.ID(), results: res, err: err}
		}(i, c)
	}
	wg.Wait()

	var all []model.CheckResult
	summaries := make([]collectorOutcome, 0, len(outcomes))
	for _, o := range outcomes {
		summaries = append(summaries, collectorOutcome{id: o.id, err: o.err})
		if o.err != nil {
			all = append(all, model.CheckResult{
				CheckID:    o.id,
				Status:     model.StatusNotCheckable,
				Reason:     "collector failed: " + o.err.Error(),
				Scope:      model.ScopeRef{Org: scope.Org},
				Provenance: []model.Provenance{},
			})
			continue
		}
		all = append(all, o.results...)
	}
	if all == nil {
		all = []model.CheckResult{}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].CheckID != all[j].CheckID {
			return all[i].CheckID < all[j].CheckID
		}
		return all[i].Scope.Repo < all[j].Scope.Repo
	})
	return all, summaries
}

// writeEvidencePack validates pack, marshals it, and writes it to
// <outDir>/evidence.json atomically (issue #24): pre-write schema
// validation fails loudly rather than ever shipping an invalid pack, and
// the write itself goes through a temp file plus rename so an
// interrupted scan (killed mid-write, disk full) never leaves a
// half-written evidence.json where a complete one used to be —
// os.Rename within the same directory is atomic on every platform this
// project ships for. ScrubBytes runs as a last line of defense alongside
// pack.Scrub() (already applied by runScan). Facts-size validation
// (ValidateFactsSizes) deliberately does NOT gate this write — see
// runScan, which already ran it as a warning: unlike a schema violation,
// an oversized fact can be a genuine, correct finding at real-world
// scale, and this is the last place in the pipeline that should ever
// destroy a scan's evidence over it.
//
// The returned hash is integrity.Hash of the exact bytes written (after
// scrubbing) — issue #27's single source of truth for "the hash of this
// pack", which the caller prints to stdout and writes to the .sha256
// sidecar. It's computed here, not by re-reading the file back, so it can
// never drift from what's actually on disk.
func writeEvidencePack(pack model.EvidencePack, outDir string) (hash string, err error) {
	if err := pack.ValidateAgainstSchema(); err != nil {
		return "", fmt.Errorf("evidence pack failed pre-write schema validation: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", outDir, err)
	}

	data, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal evidence pack: %w", err)
	}
	data = model.ScrubBytes(data)
	hash = integrity.Hash(data)

	path := filepath.Join(outDir, "evidence.json")
	tmp, err := os.CreateTemp(outDir, ".evidence-*.json.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp file in %s: %w", outDir, err)
	}
	tmpPath := tmp.Name()
	// Always attempt cleanup on any early return; once the rename below
	// succeeds this becomes a harmless no-such-file no-op, so the error is
	// deliberately discarded rather than shadowing whatever real error (if
	// any) is already being returned.
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return "", fmt.Errorf("rename %s to %s: %w", tmpPath, path, err)
	}
	return hash, nil
}
