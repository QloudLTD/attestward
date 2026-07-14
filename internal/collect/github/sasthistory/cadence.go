package sasthistory

import (
	"sort"
	"time"
)

// cadenceStats summarizes how often a matched SAST tool actually ran
// within a lookback window — fact-only (issue #17: "fact-rich, feeds the
// report"); this package's own checkCadence derives a pass/fail verdict
// from RunCount alone (is there any operational history at all to
// report), not from whether the cadence itself looks "good."
type cadenceStats struct {
	RunCount       int
	RunsPerWeek    float64
	LongestGapDays float64
}

// computeCadence considers only runs whose CreatedAt falls within
// [windowStart, windowEnd], and measures the longest silent stretch across
// the whole window — including from windowStart to the first run and from
// the last run to windowEnd, not just gaps between consecutive runs — so a
// tool that ran three times in the first week of a year-long window and
// then went silent reports a long gap, not a misleadingly small
// average-of-consecutive-gaps number.
func computeCadence(runs []runInfo, windowStart, windowEnd time.Time) cadenceStats {
	var inWindow []time.Time
	for _, r := range runs {
		if !r.CreatedAt.Before(windowStart) && !r.CreatedAt.After(windowEnd) {
			inWindow = append(inWindow, r.CreatedAt)
		}
	}
	if len(inWindow) == 0 {
		return cadenceStats{}
	}
	sort.Slice(inWindow, func(i, j int) bool { return inWindow[i].Before(inWindow[j]) })

	windowDays := windowEnd.Sub(windowStart).Hours() / 24
	var runsPerWeek float64
	if windowDays > 0 {
		runsPerWeek = float64(len(inWindow)) / (windowDays / 7)
	}

	longestGap := inWindow[0].Sub(windowStart)
	for i := 1; i < len(inWindow); i++ {
		if gap := inWindow[i].Sub(inWindow[i-1]); gap > longestGap {
			longestGap = gap
		}
	}
	if tail := windowEnd.Sub(inWindow[len(inWindow)-1]); tail > longestGap {
		longestGap = tail
	}

	return cadenceStats{
		RunCount:       len(inWindow),
		RunsPerWeek:    runsPerWeek,
		LongestGapDays: longestGap.Hours() / 24,
	}
}
