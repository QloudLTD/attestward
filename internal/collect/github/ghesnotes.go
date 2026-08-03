package github

// GHESNoteSupported, GHESNoteLicenceGated, and GHESNoteUnverified are the
// three canonical collect.CheckMeta.GHESNote values every GitHub collector
// package's own per-check GHES divergence audit (issue #13) uses, so the
// wording stays identical across all ten collector packages rather than
// drifting into ten independent paraphrases of the same three judgments.
//
// This audit is fixture-only, per the GHES epic's own explicit acceptance
// ("there is no GHES instance to test against... document plainly"): every
// note below says so, and none of the three claims this tool has actually
// exercised the endpoint against a real install.
const (
	// GHESNoteSupported is for a check whose endpoint(s) are basic REST
	// API surface (org/repo/branch/webhook/release/workflow-run reads,
	// etc.) with no GitHub Advanced Security or other Enterprise-license
	// dependency — expected to behave the same on GHES as on github.com.
	GHESNoteSupported = "a basic REST endpoint, not gated by GitHub Advanced Security or any other " +
		"licensed add-on. Expected to work on GHES releases that ship the endpoint at all — note that is a " +
		"licensing statement, not an availability one: an endpoint introduced after a given GHES release " +
		"simply does not exist there, and answers 404 exactly as a licence gate would. Not independently " +
		"verified against a real GHES install (this epic is fixture-only, per its own acceptance)."

	// GHESNoteLicenceGated is for a check whose endpoint depends on GitHub
	// Advanced Security or another Enterprise-licensed add-on (code
	// scanning, secret scanning, push protection) — the same licensing
	// dependency github.com already has for private repos, which GHES
	// installs additionally need enabled at the instance level.
	GHESNoteLicenceGated = "depends on GitHub Advanced Security (or another Enterprise-licensed add-on) " +
		"being enabled on this GHES install, the same license dependency github.com already has for a " +
		"private repo — expect a not-checkable/licence-gated result on an unlicensed install, never a " +
		"false verified-fail. Not independently verified against a real GHES install (issue #13)."

	// GHESNoteUnverified is for a check whose endpoint is recent enough on
	// github.com (or otherwise unusual, e.g. depends on GitHub Connect
	// syncing github.com-sourced data to a GHES install) that this tool's
	// authors do not have confident, verified knowledge of its GHES
	// availability or minimum required version — an honest "don't know"
	// rather than a guess presented as fact.
	GHESNoteUnverified = "recent or unusual enough on github.com (or dependent on GitHub Connect syncing " +
		"github.com data to the install) that this tool's authors do not have verified knowledge of its " +
		"GHES availability or minimum version. Treat any GHES result for this check with extra scrutiny " +
		"until a real install confirms it (issue #13)."
)
