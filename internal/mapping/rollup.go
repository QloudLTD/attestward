package mapping

import "github.com/sioakim/ssdf/internal/model"

// rollupPrecedence ranks statuses from most to least dominant for Rollup, in
// order — the truth table is documented in full in mappings/cisa-ssda-form.yaml's
// header comment (kept in one place so the YAML and the code can't drift
// apart in what they claim the semantics are).
var rollupPrecedence = []model.Status{
	model.StatusVerifiedFail,
	model.StatusPartial,
	model.StatusNotCheckable,
	model.StatusSelfAttested,
	model.StatusVerifiedPass,
}

// Rollup reduces a set of child statuses (check statuses rolling up to a
// task, or task statuses rolling up to a cluster) to a single parent status:
// the highest-ranked status present in rollupPrecedence wins. This is what
// makes "any verified-fail poisons the parent" and "self-attested never
// upgrades to verified-pass" true by construction rather than by a special
// case. Empty input rolls up to StatusNotCheckable — no evidence at all is
// definitionally not verified.
//
// Any status that isn't one of the five defined values (model.Status.Valid()
// reports false) is normalized to StatusNotCheckable *before* ranking, not
// silently dropped — an invalid status mixed with otherwise-valid ones must
// still make the result at least as cautious as not-checkable, never quietly
// vanish and let a clean status win by omission. This matters most for the
// exact case this function is meant to protect against: a future
// evidence.json reader deserializing a corrupted or newer-schema status
// string alongside good ones.
func Rollup(statuses []model.Status) model.Status {
	if len(statuses) == 0 {
		return model.StatusNotCheckable
	}
	present := make(map[model.Status]bool, len(statuses))
	for _, s := range statuses {
		if !s.Valid() {
			s = model.StatusNotCheckable
		}
		present[s] = true
	}
	for _, candidate := range rollupPrecedence {
		if present[candidate] {
			return candidate
		}
	}
	// Unreachable: every status was normalized to one of the five values
	// above, and rollupPrecedence lists all five. Fail safe anyway rather
	// than silently claiming pass if that invariant is ever broken.
	return model.StatusNotCheckable
}
