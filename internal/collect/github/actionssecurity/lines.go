package actionssecurity

import "strings"

// lineFinder locates the line number of a distinctive substring within one
// workflow file's raw text, on a best-effort basis: each call to Find
// returns the (n+1)-th not-yet-consumed occurrence of substr, where n is
// how many times Find has already matched that exact substr on this
// finder — so two structurally-different findings that happen to share
// identical text (e.g. the same "uses: actions/checkout@v5" line appearing
// in two different jobs) each get a distinct real line number rather than
// both pointing at the first occurrence. Iteration order elsewhere in this
// package is alphabetical by job name, not document order, so a rare exact
// duplicate can still get attributed to the "wrong" (but still real and
// still flagged) occurrence — a cosmetic limitation, not a correctness
// one. A finder is scoped to a single file's raw content; Find returns 0
// (unknown) if substr never matches, or is empty.
type lineFinder struct {
	lines    []string
	consumed map[string]int
}

func newLineFinder(raw string) *lineFinder {
	return &lineFinder{lines: strings.Split(raw, "\n"), consumed: map[string]int{}}
}

func (f *lineFinder) Find(substr string) int {
	if substr == "" {
		return 0
	}
	skip := f.consumed[substr]
	seen := 0
	for i, line := range f.lines {
		if strings.Contains(line, substr) {
			if seen == skip {
				f.consumed[substr] = skip + 1
				return i + 1
			}
			seen++
		}
	}
	return 0
}
