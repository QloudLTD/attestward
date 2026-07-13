// Package report renders an evidence pack into human-readable output:
// report.md, report.html, and poam.md. Renderers are pure functions over
// model.EvidencePack — never internal collector state — which is what lets
// `attestor report` regenerate byte-identical output from a saved pack.
package report
