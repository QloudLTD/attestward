package collect

import (
	"sort"

	"github.com/sioakim/attestward/internal/model"
)

// CheckMeta is the static metadata a collector registers for one check:
// title, which collector implements it, and the token permission it needs.
// Collector packages register these from an init() (or explicit wiring in
// cmd/attestward) as each collector lands in issues #11-22 — nothing is
// registered yet as of this issue, which is deliberate: `attestward checks
// list` must work correctly against an empty registry (see #8).
type CheckMeta struct {
	ID string
	// Platform is which platform this check runs against — "github" or
	// "azuredevops" (issue #34's v0.2 epic). Register defaults an empty
	// Platform to "github", so pre-v0.2 code that never set it keeps
	// meaning exactly what it always meant; every github collector package
	// sets it explicitly anyway (mechanically backfilled), since relying on
	// the implicit default is fine for the registry but reads as an
	// oversight in package source a future contributor has to re-derive.
	Platform   string
	Title      string
	Collector  string
	TokenScope string
	// Remediation is concrete, platform-specific guidance for fixing a
	// verified-fail/partial result for this check (issue #26's poam.md
	// renderer looks this up per finding). It describes the fix in terms
	// of the check itself, independent of any one scan's result, so it's
	// per-check static metadata rather than something a CheckResult
	// carries. Every C01-C10 check registers a non-empty value —
	// self-attestation questions (SA.*) don't register a CheckMeta at
	// all, since there's nothing for this tool to remediate on the
	// producer's behalf for an answer only they can give.
	Remediation string
	// Rubric explains, concretely, what each status this specific check
	// can actually produce means — not model.Status's generic definition,
	// but this check's own version of it (e.g. what exact API field/value
	// distinguishes verified-pass from verified-fail here). Keyed by
	// status; only the statuses this check can genuinely produce are
	// present — most API-verified checks in this codebase are binary
	// pass/fail with a not-checkable fallback, not partial. Issue #30's
	// checks-reference generator is the primary consumer: the acceptance
	// criterion "a reader can answer 'what exactly does X mean' from the
	// reference alone" depends on this being genuinely per-check, not a
	// paraphrase of the status enum.
	Rubric map[model.Status]string
	// Endpoints lists the GitHub REST API endpoint(s) (METHOD + path
	// template, e.g. "GET /orgs/{org}") this check's own result depends
	// on, always "GET" or "HEAD" — enforced by the completeness test in
	// every collector package, since this project is read-only forever
	// (ADR-0004), and a check registering a write verb here would be a
	// real, structural violation of that invariant, not just a docs bug.
	// When a query parameter changes what the endpoint actually returns
	// (e.g. "?filter=2fa_disabled" restricts the result set, not just
	// paginates it), include it — the endpoint string should describe
	// what data the check is actually looking at, not just the path
	// template. Static reference documentation, not runtime data —
	// contrast with model.Provenance, which records what a specific scan
	// actually called. Not necessarily every endpoint the collector's
	// package calls (a collector may share one upstream call — like an
	// org GET — across several checks); this lists what backs THIS
	// check's status specifically. May legitimately be empty (nil/[]) for a
	// check whose result is a fixed, documented fact rather than an
	// API-derived one — e.g. C09.audit.log-streaming, which reports
	// not-checkable unconditionally because no org-scoped endpoint for
	// that control exists at all (see that check's own doc comment).
	Endpoints []string
	// FixtureRef is the path (repo-relative, no "#TestFunc" suffix — as
	// of this writing every collector package's tests are scenario-based
	// across the whole Collect() call, not one test per check, so a
	// function-level pointer would be false precision) to the test file
	// that exercises this check, so a reference reader can see it proven
	// against a real scenario rather than only described in prose.
	FixtureRef string
}

// defaultPlatform is what an empty CheckMeta.Platform means — the only
// platform this tool supported before the v0.2 Azure DevOps epic (#34), and
// the fallback Lookup still assumes so every pre-v0.2 call site (every
// github collector package's own tests, cmd/attestward/report.go, ...)
// keeps working unmodified.
const defaultPlatform = "github"

// registryKey is the registry's actual identity: a check ID is only unique
// within one platform, not globally — GitHub and Azure DevOps collectors
// deliberately reuse the same check ID for the same SSDF-mapped control
// (issue #34's "check identity" model), so ID alone can't be the map key
// once a second platform registers anything.
type registryKey struct {
	Platform string
	ID       string
}

var registry = map[registryKey]CheckMeta{}

// Register adds a check's metadata to the global registry, keyed by
// (Platform, ID) — an empty Platform defaults to "github". Panics on a
// duplicate (Platform, ID) pair — that is a programming error to catch at
// collector-package init time, not a runtime condition any caller should
// need to handle. Two different platforms registering the same ID is not a
// duplicate; it's the intended shape for check parity across platforms.
func Register(meta CheckMeta) {
	if meta.Platform == "" {
		meta.Platform = defaultPlatform
	}
	key := registryKey{Platform: meta.Platform, ID: meta.ID}
	if _, exists := registry[key]; exists {
		panic("collect: duplicate check id registered for platform " + meta.Platform + ": " + meta.ID)
	}
	registry[key] = meta
}

// Registered returns every currently registered check across every
// platform, sorted by Platform then ID for deterministic output.
func Registered() []CheckMeta {
	out := make([]CheckMeta, 0, len(registry))
	for _, meta := range registry {
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Platform != out[j].Platform {
			return out[i].Platform < out[j].Platform
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// LookupPlatform returns a check's metadata for a specific platform (an
// empty platform defaults to "github", same as Register) and whether it
// was found.
func LookupPlatform(platform, id string) (CheckMeta, bool) {
	if platform == "" {
		platform = defaultPlatform
	}
	meta, ok := registry[registryKey{Platform: platform, ID: id}]
	return meta, ok
}

// Lookup returns a GitHub check's metadata and whether it was found —
// shorthand for LookupPlatform("github", id), preserved so the dozens of
// existing GitHub-only call sites (every collector package's own tests)
// don't need to learn about platforms at all.
func Lookup(id string) (CheckMeta, bool) {
	return LookupPlatform(defaultPlatform, id)
}

// collectors holds every Collector the orchestrator (issue #10) runs during
// `attestward scan`. Separate from the CheckMeta registry above: CheckMeta is
// display metadata for `attestward checks list`, while this is the actual
// executable implementation — a collector package registers both, typically
// from its own init(). Nothing is registered yet; real collectors start
// with issue #11.
var collectors []Collector

var collectorIDs = map[string]bool{}

// RegisterCollector adds c to the set `attestward scan` runs. Panics on a
// duplicate ID, same as Register — a double-registered collector would
// otherwise silently run twice and duplicate every result it produces.
func RegisterCollector(c Collector) {
	if collectorIDs[c.ID()] {
		panic("collect: duplicate collector id registered: " + c.ID())
	}
	collectorIDs[c.ID()] = true
	collectors = append(collectors, c)
}

// Collectors returns every currently registered Collector, in registration
// order (registration order is deterministic within a single binary, since
// it follows Go's deterministic init() ordering).
func Collectors() []Collector {
	return append([]Collector{}, collectors...)
}
