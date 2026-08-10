package gitlab

import "fmt"

// Vulnerability states GitLab reports on a finding.
const (
	StateDetected  = "detected"
	StateConfirmed = "confirmed"
	StateDismissed = "dismissed"
	StateResolved  = "resolved"
)

// IsOpenVulnerability reports whether a finding in the given state should count
// against a producer.
//
// This is a predicate rather than a line inside some future collector because
// getting it wrong is silent and expensive in both directions:
//
//   - Counting dismissed findings as open turns a triage decision the producer
//     already made, deliberately and with a reason recorded, into a finding
//     against them. That is the fastest way for a scanner to be dismissed as
//     noise.
//   - Counting resolved findings as open reports work that was already done.
//
// And the inverse — treating confirmed as closed because it is not "detected"
// — hides the findings a human has explicitly verified as real, which are the
// ones that matter most.
//
// An unrecognised state is an error, never a default. Guessing here would put
// an unsupported conclusion into a signed attestation, which is the failure
// this package exists to avoid; a new state in a future GitLab release should
// stop the scan and be read by a person, not be silently bucketed.
func IsOpenVulnerability(state string) (bool, error) {
	switch state {
	case StateDetected, StateConfirmed:
		return true, nil
	case StateDismissed, StateResolved:
		return false, nil
	default:
		return false, fmt.Errorf("collect/gitlab: unrecognised vulnerability state %q; refusing to guess whether it counts as open", state)
	}
}

// ResolvedOnDefaultBranch is the one case where the two obvious signals
// disagree, and it is worth naming rather than leaving as a surprise.
//
// A finding can be state "detected" while resolved_on_default_branch is true:
// the vulnerability is still open as a record, but the scanner no longer finds
// it on the default branch — typically fixed on a branch not yet merged, or
// fixed without the record being updated. Reading either field alone gives a
// different answer, so a collector must decide explicitly which question it is
// answering: "what does the project's vulnerability record say" (state) or
// "what is actually in the shipping code" (this).
//
// The recorded fixture deliberately contains such a finding so that whichever
// collector is written next has to confront the case rather than discover it
// in production.
func ResolvedOnDefaultBranch(state string, resolvedOnDefault bool) bool {
	return resolvedOnDefault && state != StateResolved
}
