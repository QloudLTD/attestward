package collect

import "sort"

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
