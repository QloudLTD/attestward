package pipelinehistory

import (
	"sort"
	"time"
)

// CadenceStats summarizes how often a matched pipeline actually ran within
// a lookback window — mirrors runhistory.CadenceStats exactly; fact-only,
// a collector's own check derives a pass/fail verdict from RunCount alone.
type CadenceStats struct {
	RunCount       int
	RunsPerWeek    float64
	LongestGapDays float64
}

// ComputeCadence is an exact mirror of runhistory.ComputeCadence, adapted
// to this package's RunInfo (QueueTime in place of CreatedAt): considers
// only runs whose QueueTime falls within [windowStart, windowEnd], and
// measures the longest silent stretch across the whole window — including
// from windowStart to the first run and from the last run to windowEnd.
func ComputeCadence(runs []RunInfo, windowStart, windowEnd time.Time) CadenceStats {
	var inWindow []time.Time
	for _, r := range runs {
		if !r.QueueTime.Before(windowStart) && !r.QueueTime.After(windowEnd) {
			inWindow = append(inWindow, r.QueueTime)
		}
	}
	if len(inWindow) == 0 {
		return CadenceStats{}
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

	return CadenceStats{
		RunCount:       len(inWindow),
		RunsPerWeek:    runsPerWeek,
		LongestGapDays: longestGap.Hours() / 24,
	}
}
