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
