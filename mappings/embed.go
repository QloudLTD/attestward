// Package mappings embeds the SSDF/CISA-form/scanner-signature YAML files
// shipped inside the attestward binary — ADR-0002 (single static binary) means
// mapping data can't depend on files existing next to the executable at
// runtime. The YAML files remain plain, human-editable data (ADR-0003); this
// file is pure build-time plumbing, no logic.
package mappings

import "embed"

// FS embeds every mappings/*.yaml file into the binary.
//
//go:embed *.yaml
var FS embed.FS
