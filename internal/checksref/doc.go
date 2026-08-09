// Package checksref renders docs/checks-reference.md: the generated,
// authoritative reference of every registered check — what it verifies,
// its status rubric, the API evidence it depends on, its SSDF/CISA-form
// citations, remediation guidance, and its fixture proof. Like
// internal/report, Render is a pure function of its inputs — no I/O, no
// clock reads — so `attestward checks docs` and its CI drift check can prove
// determinism by rendering twice and comparing bytes (issue #30).
package checksref
