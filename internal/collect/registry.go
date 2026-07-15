package collect

import (
	"sort"

	"github.com/sioakim/ssdf/internal/model"
)

// CheckMeta is the static metadata a collector registers for one check:
// title, which collector implements it, and the token permission it needs.
// Collector packages register these from an init() (or explicit wiring in
// cmd/attestor) as each collector lands in issues #11-22 — nothing is
// registered yet as of this issue, which is deliberate: `attestor checks
// list` must work correctly against an empty registry (see #8).
type CheckMeta struct {
	ID         string
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
	// check's status specifically.
	Endpoints []string
	// FixtureRef is the path (repo-relative, no "#TestFunc" suffix — as
	// of this writing every collector package's tests are scenario-based
	// across the whole Collect() call, not one test per check, so a
	// function-level pointer would be false precision) to the test file
	// that exercises this check, so a reference reader can see it proven
	// against a real scenario rather than only described in prose.
	FixtureRef string
}

var registry = map[string]CheckMeta{}

// Register adds a check's metadata to the global registry. Panics on a
// duplicate ID — that is a programming error to catch at collector-package
// init time, not a runtime condition any caller should need to handle.
func Register(meta CheckMeta) {
	if _, exists := registry[meta.ID]; exists {
		panic("collect: duplicate check id registered: " + meta.ID)
	}
	registry[meta.ID] = meta
}

// Registered returns every currently registered check, sorted by ID for
// deterministic output.
func Registered() []CheckMeta {
	out := make([]CheckMeta, 0, len(registry))
	for _, meta := range registry {
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Lookup returns a check's metadata and whether it was found.
func Lookup(id string) (CheckMeta, bool) {
	meta, ok := registry[id]
	return meta, ok
}

// collectors holds every Collector the orchestrator (issue #10) runs during
// `attestor scan`. Separate from the CheckMeta registry above: CheckMeta is
// display metadata for `attestor checks list`, while this is the actual
// executable implementation — a collector package registers both, typically
// from its own init(). Nothing is registered yet; real collectors start
// with issue #11.
var collectors []Collector

var collectorIDs = map[string]bool{}

// RegisterCollector adds c to the set `attestor scan` runs. Panics on a
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
