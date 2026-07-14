package sasthistory

import (
	"math"
	"testing"
)

func approxEqual(a, b, epsilon float64) bool {
	return math.Abs(a-b) < epsilon
}

func TestComputeCadence(t *testing.T) {
	windowStart := day(0)
	windowEnd := day(70) // 10 weeks

	tests := []struct {
		name           string
		runs           []runInfo
		wantCount      int
		wantRunsPerWk  float64
		wantLongestGap float64
	}{
		{
			name:           "no runs in window",
			runs:           nil,
			wantCount:      0,
			wantRunsPerWk:  0,
			wantLongestGap: 0,
		},
		{
			name: "runs outside the window are excluded",
			runs: []runInfo{
				{CreatedAt: day(-10)},
				{CreatedAt: day(100)},
			},
			wantCount:      0,
			wantRunsPerWk:  0,
			wantLongestGap: 0,
		},
		{
			name: "evenly spaced runs: 10 runs over 10 weeks = 1/week",
			runs: []runInfo{
				{CreatedAt: day(7)}, {CreatedAt: day(14)}, {CreatedAt: day(21)}, {CreatedAt: day(28)}, {CreatedAt: day(35)},
				{CreatedAt: day(42)}, {CreatedAt: day(49)}, {CreatedAt: day(56)}, {CreatedAt: day(63)}, {CreatedAt: day(70)},
			},
			wantCount:      10,
			wantRunsPerWk:  1.0,
			wantLongestGap: 7, // every gap (including start-to-first) is exactly 7 days
		},
		{
			name: "silent tail after the last run dominates the longest gap",
			runs: []runInfo{
				{CreatedAt: day(1)}, {CreatedAt: day(2)}, {CreatedAt: day(3)},
			},
			wantCount:      3,
			wantRunsPerWk:  0.3, // 3 runs / 10 weeks
			wantLongestGap: 67,  // day(3) to day(70)
		},
		{
			name: "silent start before the first run dominates the longest gap",
			runs: []runInfo{
				{CreatedAt: day(65)}, {CreatedAt: day(68)},
			},
			wantCount:      2,
			wantRunsPerWk:  0.2,
			wantLongestGap: 65, // windowStart (day 0) to first run (day 65)
		},
		{
			name:           "single run: longest gap is max(start-to-run, run-to-end)",
			runs:           []runInfo{{CreatedAt: day(60)}},
			wantCount:      1,
			wantRunsPerWk:  0.1,
			wantLongestGap: 60, // max(60, 10)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeCadence(tt.runs, windowStart, windowEnd)
			if got.RunCount != tt.wantCount {
				t.Errorf("RunCount = %d, want %d", got.RunCount, tt.wantCount)
			}
			if !approxEqual(got.RunsPerWeek, tt.wantRunsPerWk, 0.01) {
				t.Errorf("RunsPerWeek = %v, want %v", got.RunsPerWeek, tt.wantRunsPerWk)
			}
			if !approxEqual(got.LongestGapDays, tt.wantLongestGap, 0.01) {
				t.Errorf("LongestGapDays = %v, want %v", got.LongestGapDays, tt.wantLongestGap)
			}
		})
	}
}
