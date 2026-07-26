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
	// ScopeLevel disambiguates the one case ScopeRef alone can't resolve
	// (issue #176): a check whose results always have Repo empty could be
	// genuinely org-scoped (e.g. C01 org-security) or, on Azure DevOps,
	// project-scoped (e.g. C03 env-separation, C08 pipeline-security) —
	// and, for a Repo-empty result specifically, ScopeRef.Project can't be
	// used to derive it either, because it's the other way around: the
	// orchestrator populates ScopeRef.Project FROM this field for a
	// Repo-empty result (issue #221; a Repo-non-empty result gets it too,
	// but from Repo's presence, not from ScopeLevel — see ScopeRef.Project's
	// own doc comment for the full rule), so inferring scope level from
	// Project's presence would just be reading back what this field already
	// determined for the one case that matters here. Renderers consult this
	// rather than inferring scope level from (Repo, Project) presence at
	// each call site, which is what let #176 happen. Left unset for the
	// large majority of checks: a non-empty Repo resolves directly, and an
	// unset value defaults to "org" — correct for GitHub and every
	// genuinely org-scoped ADO check. (Unset is NOT literally ScopeLevelOrg
	// — that's a real, distinct value; see ScopeLevelOrg's own doc comment
	// for why the two must be compared differently.) Only set
	// ScopeLevelProject for a check whose Repo is always empty AND whose
	// control is project-scoped, not org-scoped.
	ScopeLevel ScopeLevel
}

// ScopeLevel is CheckMeta.ScopeLevel's type — see that field's doc comment.
// A plain string type, not exported cross-package to internal/report
// (ADR-0005): cmd/attestward converts it to a plain string at the package
// boundary when building the scopeLevelByCheckID map renderers accept.
type ScopeLevel string

const (
	// ScopeLevelOrg is the org-scoped value. Leaving the field unset is
	// equivalent FOR RENDERING — consumers test for ScopeLevelProject and
	// treat everything else as org — but it is NOT literally the zero value,
	// which is "". So `meta.ScopeLevel == ScopeLevelOrg` is false for every
	// check that never sets the field, i.e. almost all of them. Compare
	// against ScopeLevelProject, or handle "" explicitly.
	ScopeLevelOrg ScopeLevel = "org"
	// ScopeLevelProject marks a check whose results are always scoped to
	// an Azure DevOps project, never the whole org. No GitHub check ever
	// uses this — GitHub has no project concept.
	ScopeLevelProject ScopeLevel = "project"
)

// DefaultPlatform is what an empty platform value means everywhere in this
// codebase — the only platform this tool supported before the v0.2 Azure
// DevOps epic (#34), and the fallback Lookup still assumes so every pre-v0.2
// call site (every github collector package's own tests, cmd/attestward's
// CLI) keeps working unmodified.
const DefaultPlatform = "github"

// NormalizePlatform returns platform, defaulting an empty value to
// DefaultPlatform. This is the single place "absent platform means github"
// is decided — Register/LookupPlatform below, cmd/attestward's CLI wiring,
// internal/checksref's renderer, and internal/packdiff's pack comparison
// all call this rather than each re-deriving the same fallback locally
// (found in review of #169: four independent copies of the same one-line
// check is exactly the kind of drift risk a single exported helper exists
// to prevent).
func NormalizePlatform(platform string) string {
	if platform == "" {
		return DefaultPlatform
	}
	return platform
}

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
// duplicate; it's the intended shape for check parity across platforms —
// but only if every platform agrees on which Collector implements it: an ID
// registered under two different Collector strings would make
// internal/checksref (which groups by Collector, then merges same-ID
// entries into one heading with per-platform subsections) silently render
// the same ID as two unrelated, duplicated sections instead of one merged
// check — an outcome worse than the last-write-wins bug that grouping
// replaced (found in review of #169), so it's rejected here structurally
// rather than left to be caught by a renderer's own output.
func Register(meta CheckMeta) {
	meta.Platform = NormalizePlatform(meta.Platform)
	key := registryKey{Platform: meta.Platform, ID: meta.ID}
	if _, exists := registry[key]; exists {
		panic("collect: duplicate check id registered for platform " + meta.Platform + ": " + meta.ID)
	}
	for k, existing := range registry {
		if k.ID == meta.ID && existing.Collector != meta.Collector {
			panic("collect: check " + meta.ID + " registered under platform " + meta.Platform + " with collector " +
				meta.Collector + ", but platform " + k.Platform + " already registered it under collector " +
				existing.Collector + " — every platform registering the same check ID must agree on its Collector")
		}
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
	meta, ok := registry[registryKey{Platform: NormalizePlatform(platform), ID: id}]
	return meta, ok
}

// Lookup returns a GitHub check's metadata and whether it was found —
// shorthand for LookupPlatform("github", id), preserved so the dozens of
// existing GitHub-only call sites (every collector package's own tests)
// don't need to learn about platforms at all.
func Lookup(id string) (CheckMeta, bool) {
	return LookupPlatform(DefaultPlatform, id)
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
