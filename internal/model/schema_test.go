package model

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

const schemaPath = "../../docs/schema/evidence-pack.v1.schema.json"

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	// Draft 2020-12 treats "format" as annotation-only unless the compiler
	// is told to assert it — without this, a bogus "scan_started_at":
	// "not-a-timestamp" would pass validation despite the schema declaring
	// format: date-time.
	c.AssertFormat = true
	sch, err := c.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile %s: %v", schemaPath, err)
	}
	return sch
}

func loadJSONDoc(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return doc
}

// TestFixturePackValidatesAgainstSchema proves the committed fixture pack —
// what collector/renderer tests build against — is itself schema-valid.
func TestFixturePackValidatesAgainstSchema(t *testing.T) {
	sch := compileSchema(t)
	if err := sch.Validate(loadJSONDoc(t, "testdata/fixture-pack.json")); err != nil {
		t.Fatalf("fixture-pack.json failed schema validation: %v", err)
	}
}

// TestSchemaAssertsDateTimeFormat proves AssertFormat is actually wired up:
// a bogus timestamp must fail validation, not silently pass as an
// annotation-only "format" hint would let it.
func TestSchemaAssertsDateTimeFormat(t *testing.T) {
	sch := compileSchema(t)
	doc := loadJSONDoc(t, "testdata/fixture-pack.json")
	m, ok := doc.(map[string]any)
	if !ok {
		t.Fatal("fixture-pack.json did not decode to a JSON object")
	}
	m["scan_started_at"] = "not-a-timestamp"
	if err := sch.Validate(doc); err == nil {
		t.Fatal("expected a bogus scan_started_at to fail schema validation, but it passed")
	}
}

// TestBrokenPackFailsSchemaValidation proves the schema actually rejects an
// invalid pack (a bad status enum value) rather than accepting anything.
func TestBrokenPackFailsSchemaValidation(t *testing.T) {
	sch := compileSchema(t)
	if err := sch.Validate(loadJSONDoc(t, "testdata/broken-pack.json")); err == nil {
		t.Fatal("expected broken-pack.json to fail schema validation, but it passed")
	}
}

// TestEvidencePackRoundTripsAndValidates hand-builds an EvidencePack in Go,
// marshals it, round-trips it back, and validates the marshaled JSON against
// the published schema — proving the Go types and the schema cannot drift
// apart silently.
func TestEvidencePackRoundTripsAndValidates(t *testing.T) {
	pack := EvidencePack{
		SchemaVersion: SchemaVersion,
		ToolVersion:   "0.0.0-test",
		MappingVersions: MappingVersions{
			SSDF:     "1.0.0",
			CISAForm: "1.0.0",
		},
		Scope: ScanScope{
			Org:               "attestor-demo",
			Repos:             []string{"good-repo"},
			ReleaseTagPattern: "v*",
			LookbackReleases:  5,
		},
		ScanStartedAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
		ScanEndedAt:   time.Date(2026, 7, 13, 12, 0, 5, 0, time.UTC),
		Results: []CheckResult{
			{
				CheckID: "C02.repo-protection.required-reviews",
				Title:   "Branch protection requires reviews",
				Status:  StatusVerifiedPass,
				Reason:  "main requires 1 approving review and passing status checks",
				Scope:   ScopeRef{Org: "attestor-demo", Repo: "good-repo"},
				Provenance: []Provenance{
					{
						Endpoint:       "/repos/attestor-demo/good-repo/rulesets",
						Method:         "GET",
						Timestamp:      time.Date(2026, 7, 13, 12, 0, 1, 0, time.UTC),
						HTTPStatus:     200,
						ResponseSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
				Facts: map[string]any{"required_approving_review_count": 1},
			},
		},
	}

	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var roundTripped EvidencePack
	if err := json.Unmarshal(raw, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if roundTripped.Results[0].CheckID != pack.Results[0].CheckID {
		t.Fatalf("round trip mismatch: got %q want %q", roundTripped.Results[0].CheckID, pack.Results[0].CheckID)
	}
	if roundTripped.Results[0].Status != StatusVerifiedPass {
		t.Fatalf("round trip lost status: got %q", roundTripped.Results[0].Status)
	}

	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal to any: %v", err)
	}
	sch := compileSchema(t)
	if err := sch.Validate(doc); err != nil {
		t.Fatalf("hand-built EvidencePack failed schema validation: %v", err)
	}
}

// TestNilSlicesFailSchemaValidation locks in the invariant documented on
// EvidencePack: a zero-value-ish pack (nil Results/Repos/Provenance, which
// Go happily constructs and encoding/json marshals as JSON null) fails its
// own schema, since the schema declares those fields `type: array`. If a
// future MarshalJSON hook normalizes nils to empty slices, this test should
// start failing loudly — update the EvidencePack doc comment alongside it.
func TestNilSlicesFailSchemaValidation(t *testing.T) {
	pack := EvidencePack{
		SchemaVersion: SchemaVersion,
		ToolVersion:   "0.0.0-test",
		Scope:         ScanScope{Org: "attestor-demo"}, // Repos left nil
		ScanStartedAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
		ScanEndedAt:   time.Date(2026, 7, 13, 12, 0, 5, 0, time.UTC),
		Results:       nil, // left nil
	}
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal to any: %v", err)
	}
	sch := compileSchema(t)
	if err := sch.Validate(doc); err == nil {
		t.Fatal("expected a pack with nil Results/Repos to fail schema validation (documented invariant), but it passed")
	}
}

func TestStatusValid(t *testing.T) {
	valid := []Status{StatusVerifiedPass, StatusVerifiedFail, StatusPartial, StatusSelfAttested, StatusNotCheckable}
	for _, s := range valid {
		if !s.Valid() {
			t.Errorf("Status(%q).Valid() = false, want true", s)
		}
	}
	if Status("not-a-real-status").Valid() {
		t.Error(`Status("not-a-real-status").Valid() = true, want false`)
	}
}
