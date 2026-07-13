// Package model defines the versioned evidence and check data types shared by
// every other package: CheckResult (with evidence provenance), the check status
// vocabulary (verified-pass | verified-fail | partial | self-attested |
// not-checkable), and the top-level EvidencePack assembled into evidence.json.
// It has no dependency on collect, mapping, or report — everything else depends
// on model, never the reverse.
package model
