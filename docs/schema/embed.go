// Package schema embeds the JSON Schema files describing attestward's
// versioned file formats (evidence.json, the mappings/*.yaml files) into
// the binary — ADR-0002 (single static binary) means schema data can't
// depend on files existing next to the executable at runtime, the same
// reasoning mappings/embed.go documents for the mapping YAML files
// themselves. Tests reading a schema straight from this directory (e.g.
// internal/model/schema_test.go) are unaffected — this embed exists
// specifically for runtime consumers (issue #24's pre-write validation)
// that can't rely on a repo checkout being present.
package schema

import "embed"

// FS embeds every docs/schema/*.json file into the binary.
//
//go:embed *.json
var FS embed.FS
