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
	// KNOWN GAP (Fable 5 review, flagged for issue #23 to resolve, not
	// fixed here): this status has no polarity. A questionnaire answer of
	// "yes, we do this" and "no, we don't" both produce StatusSelfAttested
	// today — nothing in the model distinguishes an affirmative claim from
	// an admitted gap, and Reason/Facts can't carry that distinction into
	// the rollup engine, which only switches on Status. Before #23 lands,
	// this needs a decision: split into affirmative/negative statuses (a
	// breaking SchemaVersion bump, since Status is exhaustive by design —
	// see docs/architecture.md's versioning policy) or find another way to
	// surface a "self-attested no" as an actionable POA&M gap (#26).
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
