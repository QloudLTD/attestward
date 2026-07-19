package model

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/sioakim/attestward/docs/schema"
)

const evidencePackSchemaName = "evidence-pack.v1.schema.json"

// ValidateAgainstSchema marshals p and validates it against the embedded
// evidence-pack JSON Schema — the same schema
// docs/schema/evidence-pack.v1.schema.json and this package's own
// schema_test.go validate against, compiled here from docs/schema's
// embedded copy so it works in the shipped binary too (ADR-0002: single
// static binary, no on-disk file dependency at runtime). Called by the
// evidence.json writer (issue #24) before ever writing a byte, so an
// internal bug that produces a schema-invalid pack fails loudly instead
// of shipping a broken file.
func (p EvidencePack) ValidateAgainstSchema() error {
	sch, err := compileEvidencePackSchema()
	if err != nil {
		return fmt.Errorf("compile evidence pack schema: %w", err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal evidence pack: %w", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("unmarshal evidence pack for validation: %w", err)
	}
	if err := sch.Validate(doc); err != nil {
		return fmt.Errorf("evidence pack failed schema validation: %w", err)
	}
	return nil
}

func compileEvidencePackSchema() (*jsonschema.Schema, error) {
	f, err := schema.FS.Open(evidencePackSchemaName)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	c := jsonschema.NewCompiler()
	// Draft 2020-12 treats "format" as annotation-only unless the compiler
	// is told to assert it — without this, a bogus scan_started_at value
	// would pass validation despite the schema declaring format: date-time.
	c.AssertFormat = true
	if err := c.AddResource(evidencePackSchemaName, f); err != nil {
		return nil, err
	}
	return c.Compile(evidencePackSchemaName)
}

// MaxFactValueBytes is the soft cap on any single top-level Facts value's
// marshaled JSON size — a guardrail against a collector accidentally
// embedding something payload-shaped (a full API response, a large
// file's raw content) rather than the "minimal extracted key/value data"
// CheckResult.Facts' own doc comment promises. Set high enough that no
// legitimate finding list should ever realistically reach it: a C07
// per_release table or C08 unpinned-action list has no enforced upper
// bound on item count (an org can set --lookback-releases arbitrarily
// high, or simply have many unpinned actions — exactly the finding this
// check exists to surface, not suppress), so this cap exists to catch a
// raw-payload-shaped mistake (typically tens of KB to MB), not to police
// how many real findings a single check can legitimately report. See
// ValidateFactsSizes' doc comment for why a violation warns rather than
// blocks the write.
const MaxFactValueBytes = 65536

// OversizedFacts returns the keys of c.Facts whose marshaled JSON value
// exceeds MaxFactValueBytes, sorted, or nil if none do. A key whose value
// can't be marshaled at all isn't reported here — json.Marshal on the
// whole pack will fail loudly for that on its own, which is a different
// (and worse) problem than this function exists to catch.
func (c *CheckResult) OversizedFacts() []string {
	var oversized []string
	for k, v := range c.Facts {
		raw, err := json.Marshal(v)
		if err != nil {
			continue
		}
		if len(raw) > MaxFactValueBytes {
			oversized = append(oversized, k)
		}
	}
	sort.Strings(oversized)
	return oversized
}

// ValidateFactsSizes checks every result's Facts against OversizedFacts'
// soft cap and returns an error describing the first violation found
// (Results are already sorted by CheckID, so which one is "first" is
// deterministic), or nil if none. Deliberately advisory, not a hard
// pre-write gate the way ValidateAgainstSchema is: unlike a schema
// violation (always a real bug — the pack shape itself is wrong), an
// oversized fact can be entirely legitimate at real-world scale (a large
// org's genuine finding count), and destroying an entire scan's worth of
// evidence over one honestly-oversized fact would be strictly worse than
// writing the pack anyway — see cmd/attestor/scan.go's runScan, which
// logs this as a warning rather than aborting.
func (p EvidencePack) ValidateFactsSizes() error {
	for _, r := range p.Results {
		if oversized := r.OversizedFacts(); len(oversized) > 0 {
			return fmt.Errorf("check %s (repo=%q): facts %v exceed the %d-byte soft cap — looks like a raw payload leaked into Facts instead of minimal extracted data",
				r.CheckID, r.Scope.Repo, oversized, MaxFactValueBytes)
		}
	}
	return nil
}
