package pipelinehistory

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
		runs           []RunInfo
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
			runs: []RunInfo{
				{QueueTime: day(-10)},
				{QueueTime: day(100)},
			},
			wantCount:      0,
			wantRunsPerWk:  0,
			wantLongestGap: 0,
		},
		{
			name: "evenly spaced runs: 10 runs over 10 weeks = 1/week",
			runs: []RunInfo{
				{QueueTime: day(7)}, {QueueTime: day(14)}, {QueueTime: day(21)}, {QueueTime: day(28)}, {QueueTime: day(35)},
				{QueueTime: day(42)}, {QueueTime: day(49)}, {QueueTime: day(56)}, {QueueTime: day(63)}, {QueueTime: day(70)},
			},
			wantCount:      10,
			wantRunsPerWk:  1.0,
			wantLongestGap: 7,
		},
		{
			name: "silent tail after the last run dominates the longest gap",
			runs: []RunInfo{
				{QueueTime: day(1)}, {QueueTime: day(2)}, {QueueTime: day(3)},
			},
			wantCount:      3,
			wantRunsPerWk:  0.3,
			wantLongestGap: 67,
		},
		{
			name: "silent start before the first run dominates the longest gap",
			runs: []RunInfo{
				{QueueTime: day(65)}, {QueueTime: day(68)},
			},
			wantCount:      2,
			wantRunsPerWk:  0.2,
			wantLongestGap: 65,
		},
		{
			name:           "single run: longest gap is max(start-to-run, run-to-end)",
			runs:           []RunInfo{{QueueTime: day(60)}},
			wantCount:      1,
			wantRunsPerWk:  0.1,
			wantLongestGap: 60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeCadence(tt.runs, windowStart, windowEnd)
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
