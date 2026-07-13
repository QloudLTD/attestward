package mapping

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// loadYAMLAsJSONDoc reads a YAML file and re-encodes it through JSON so it
// can be validated with a JSON Schema validator (yaml.v3 decodes into
// map[string]interface{} with map keys as strings already, which is
// JSON-schema-library compatible once round-tripped through encoding/json).
func loadYAMLAsJSONDoc(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var y any
	if err := yaml.Unmarshal(raw, &y); err != nil {
		t.Fatalf("unmarshal yaml %s: %v", path, err)
	}
	jsonBytes, err := json.Marshal(y)
	if err != nil {
		t.Fatalf("marshal %s to json: %v", path, err)
	}
	var doc any
	if err := json.Unmarshal(jsonBytes, &doc); err != nil {
		t.Fatalf("unmarshal %s json doc: %v", path, err)
	}
	return doc
}

// compileMappingSchema mirrors internal/model's compileSchema: draft 2020-12
// treats "format" (date, uri) as annotation-only unless the compiler is told
// to assert it, so without this a bogus "retrieved": "yesterday" would pass
// validation despite the schema declaring format: date.
func compileMappingSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat = true
	sch, err := c.Compile(path)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return sch
}

func TestSSDFMappingValidatesAgainstSchema(t *testing.T) {
	sch := compileMappingSchema(t, "../../docs/schema/mapping-ssdf-800-218.schema.json")
	if err := sch.Validate(loadYAMLAsJSONDoc(t, "../../mappings/ssdf-800-218.yaml")); err != nil {
		t.Fatalf("mappings/ssdf-800-218.yaml failed schema validation: %v", err)
	}
}

// TestSSDFSchemaAssertsDateFormat proves AssertFormat is wired up: a bogus
// "retrieved" date must fail validation, not silently pass.
func TestSSDFSchemaAssertsDateFormat(t *testing.T) {
	sch := compileMappingSchema(t, "../../docs/schema/mapping-ssdf-800-218.schema.json")
	doc := loadYAMLAsJSONDoc(t, "../../mappings/ssdf-800-218.yaml")
	m, ok := doc.(map[string]any)
	if !ok {
		t.Fatal("ssdf-800-218.yaml did not decode to a JSON object")
	}
	m["retrieved"] = "not-a-date"
	if err := sch.Validate(doc); err == nil {
		t.Fatal("expected a bogus retrieved date to fail schema validation, but it passed")
	}
}
