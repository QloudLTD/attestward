package model

// Status is the outcome of a single check. Exactly these five values exist;
// nothing else may ever appear in an evidence pack. Each carries the precise
// semantics a reader (or a lawyer, per the product's stakes) relies on.
type Status string

const (
	// StatusVerifiedPass means the tool queried the platform API and the
	// returned state satisfies the check's pass condition. The strongest
	// claim the tool makes — it is never inferred, only observed.
	StatusVerifiedPass Status = "verified-pass"

	// StatusVerifiedFail means the tool queried the platform API and the
	// returned state does NOT satisfy the check's pass condition. Just as
	// definitive as verified-pass — the tool knows the answer and it's no.
	StatusVerifiedFail Status = "verified-fail"

	// StatusPartial means the tool queried the platform API and got a
	// mixed or incomplete signal: some but not all of a check's
	// sub-conditions hold, or the evidence is suggestive but not
	// conclusive proof either way. Use this instead of rounding up to
	// verified-pass or down to verified-fail when the API genuinely
	// can't settle the question — never as a default for "unsure why".
	StatusPartial Status = "partial"

	// StatusSelfAttested means no API call can verify this control at
	// all; the answer comes from the user-authored self-attestation
	// questionnaire (issue #23) instead of platform evidence. A
	// self-attested result never upgrades a CISA form cluster to fully
	// verified — see the rollup truth table defined with #7.
	//
	// RESOLVED (was a "known gap" flagged by an earlier Fable 5 review for
	// issue #23 to decide): this status deliberately carries no polarity.
	// A questionnaire answer of "yes, we do this" and "no, we don't" both
	// produce StatusSelfAttested — the distinction lives in
	// CheckResult.Facts["answer"] (see
	// internal/mapping.BuildSelfAttestedResults), not in Status itself.
	// This was a considered choice, not an oversight: Rollup's precedence
	// table (internal/mapping/rollup.go) already ranks self-attested below
	// verified-pass and below not-checkable/partial/verified-fail
	// regardless of the answer's content, so correct rollup behavior never
	// depended on Status carrying polarity — adding a second pair of
	// statuses (a breaking SchemaVersion bump, since Status is exhaustive
	// by design — see docs/architecture.md's versioning policy) would have
	// been new model surface with no rollup-correctness payoff. A report
	// or POA&M generator (issues #25/#26) that wants to render or flag a
	// "self-attested no" differently from a "self-attested yes" reads
	// Facts["answer"] for that, the same way it already would for any
	// other check's Facts-carried detail.
	StatusSelfAttested Status = "self-attested"

	// StatusNotCheckable means the tool could not determine an answer at
	// all: the API/feature is plan-gated, the token lacks permission, or
	// a self-attestable check has no answer on file. This is an honest
	// "unknown" — it must never be inferred as a pass or a fail.
	StatusNotCheckable Status = "not-checkable"
)

// Valid reports whether s is one of the five defined statuses.
func (s Status) Valid() bool {
	switch s {
	case StatusVerifiedPass, StatusVerifiedFail, StatusPartial, StatusSelfAttested, StatusNotCheckable:
		return true
	default:
		return false
	}
}
