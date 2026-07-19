package mapping

import (
	"testing"

	"github.com/sioakim/attestward/internal/model"
)

func TestRollup(t *testing.T) {
	pass := model.StatusVerifiedPass
	fail := model.StatusVerifiedFail
	partial := model.StatusPartial
	self := model.StatusSelfAttested
	unknown := model.StatusNotCheckable

	tests := []struct {
		name string
		in   []model.Status
		want model.Status
	}{
		{"empty input is not-checkable", nil, unknown},
		{"single verified-pass", []model.Status{pass}, pass},
		{"single verified-fail", []model.Status{fail}, fail},
		{"single partial", []model.Status{partial}, partial},
		{"single self-attested", []model.Status{self}, self},
		{"single not-checkable", []model.Status{unknown}, unknown},
		{"all verified-pass stays verified-pass", []model.Status{pass, pass, pass}, pass},

		{"any verified-fail dominates over pass", []model.Status{pass, fail}, fail},
		{"any verified-fail dominates over partial", []model.Status{partial, fail}, fail},
		{"any verified-fail dominates over self-attested", []model.Status{self, fail}, fail},
		{"any verified-fail dominates over not-checkable", []model.Status{unknown, fail}, fail},
		{"verified-fail dominates over everything else mixed", []model.Status{pass, partial, self, unknown, fail}, fail},

		{"partial dominates over pass", []model.Status{pass, partial}, partial},
		{"partial dominates over self-attested", []model.Status{self, partial}, partial},
		{"partial dominates over not-checkable", []model.Status{unknown, partial}, partial},

		{"not-checkable dominates over pass", []model.Status{pass, unknown}, unknown},
		{"not-checkable dominates over self-attested", []model.Status{self, unknown}, unknown},

		{"self-attested never upgrades to verified-pass", []model.Status{pass, self}, self},
		{"self-attested plus many verified-pass still self-attested", []model.Status{pass, pass, pass, self}, self},

		// Regression: an invalid status used to silently vanish when mixed
		// with valid ones (only the empty-input / all-invalid path fell
		// back to not-checkable), so Rollup([pass, "bogus"]) incorrectly
		// returned pass instead of not-checkable.
		{"invalid status mixed with verified-pass normalizes to not-checkable", []model.Status{pass, model.Status("bogus")}, unknown},
		{"invalid status mixed with self-attested normalizes to not-checkable (outranks self-attested)", []model.Status{self, model.Status("bogus")}, unknown},
		{"invalid status alone normalizes to not-checkable", []model.Status{model.Status("bogus")}, unknown},
		{"invalid status never outranks verified-fail", []model.Status{fail, model.Status("bogus")}, fail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Rollup(tt.in)
			if got != tt.want {
				t.Errorf("Rollup(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestRollupExhaustivePairs proves the full precedence order holds for every
// ordered pair of the five statuses, not just the hand-picked cases above.
func TestRollupExhaustivePairs(t *testing.T) {
	rank := map[model.Status]int{
		model.StatusVerifiedFail: 0,
		model.StatusPartial:      1,
		model.StatusNotCheckable: 2,
		model.StatusSelfAttested: 3,
		model.StatusVerifiedPass: 4,
	}
	all := []model.Status{
		model.StatusVerifiedFail,
		model.StatusPartial,
		model.StatusNotCheckable,
		model.StatusSelfAttested,
		model.StatusVerifiedPass,
	}

	for _, a := range all {
		for _, b := range all {
			want := a
			if rank[b] < rank[a] {
				want = b
			}
			got := Rollup([]model.Status{a, b})
			if got != want {
				t.Errorf("Rollup([%q, %q]) = %q, want %q (lower rank wins)", a, b, got, want)
			}
		}
	}
}
