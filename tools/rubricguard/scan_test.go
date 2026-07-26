package main

import (
	"go/token"
	"testing"
)

const sampleFile = `package sample

import "github.com/sioakim/attestward/internal/model"

var checkRubrics = map[string]map[model.Status]string{
	"C99.sample.check": {
		model.StatusVerifiedPass: "it passed",
		model.StatusVerifiedFail: "it failed",
	},
}

// computeStatus mentions model.StatusPartial in prose here, in a comment,
// which must never be treated the same as a real code reference.
func computeStatus(ok bool) model.Status {
	if ok {
		return model.StatusVerifiedPass
	}
	return model.StatusVerifiedFail
}
`

func TestRubricSpan(t *testing.T) {
	fset := token.NewFileSet()
	span, err := rubricSpan(fset, []byte(sampleFile))
	if err != nil {
		t.Fatalf("rubricSpan: %v", err)
	}
	if !span.valid() {
		t.Fatal("expected a valid span for checkRubrics")
	}
	// Line 5 is "var checkRubrics = ...", line 10 is its closing "}".
	if span.Start != 5 || span.End != 10 {
		t.Errorf("span = %+v, want {5 10}", span)
	}
}

func TestRubricSpan_Absent(t *testing.T) {
	fset := token.NewFileSet()
	span, err := rubricSpan(fset, []byte("package sample\n\nfunc f() {}\n"))
	if err != nil {
		t.Fatalf("rubricSpan: %v", err)
	}
	if span.valid() {
		t.Errorf("expected no span when checkRubrics is absent, got %+v", span)
	}
}

// TestStatusLines_IgnoresRubricBlockAndComments is the precision claim
// this whole guard rests on: a model.Status reference only counts if
// it's real code (an *ast.SelectorExpr node), and only outside the
// excluded checkRubrics span. The sample file above has five candidate
// occurrences of "model.Status..." — two inside checkRubrics (excluded
// by span), one in a comment (never visited by ast.Inspect at all), one
// the bare model.Status *type* in computeStatus's own signature
// (excluded because it names a type, not a status value — it can never
// indicate which status gets assigned), and two real status-*value*
// references inside computeStatus's body (lines 16 and 18) — only those
// last two should be reported.
func TestStatusLines_IgnoresRubricBlockAndComments(t *testing.T) {
	fset := token.NewFileSet()
	excl, err := rubricSpan(fset, []byte(sampleFile))
	if err != nil {
		t.Fatalf("rubricSpan: %v", err)
	}

	fset2 := token.NewFileSet() // statusLines re-parses; keep positions independent of the span parse above
	lines, err := statusLines(fset2, []byte(sampleFile), excl)
	if err != nil {
		t.Fatalf("statusLines: %v", err)
	}
	// excl's line numbers came from fset, but statusLines' own positions
	// come from fset2 — both parse the identical source from byte 0, so
	// line numbers are numerically identical across the two FileSets;
	// only the token.Pos *values* differ, which is exactly why exclusion
	// is compared by line number, not by token.Pos.
	want := map[int]bool{16: true, 18: true}
	if len(lines) != len(want) {
		t.Fatalf("statusLines = %v, want %v", lines, want)
	}
	for line := range want {
		if !lines[line] {
			t.Errorf("expected line %d to be reported, got %v", line, lines)
		}
	}
}

func TestParseHunks(t *testing.T) {
	diff := `diff --git a/f.go b/f.go
index 111..222 100644
--- a/f.go
+++ b/f.go
@@ -3 +3 @@ func f() {
-old line
+new line
@@ -10,2 +10,0 @@ func g() {
-removed line one
-removed line two
@@ -20,0 +19,3 @@ func h() {
+added line one
+added line two
+added line three
`
	hunks := parseHunks(diff)
	if len(hunks) != 3 {
		t.Fatalf("got %d hunks, want 3: %+v", len(hunks), hunks)
	}
	// Hunk 1: a 1-line replacement.
	if hunks[0].Old != (lineRange{3, 3}) || hunks[0].New != (lineRange{3, 3}) {
		t.Errorf("hunk 0 = %+v", hunks[0])
	}
	// Hunk 2: pure deletion — new side has count 0, must be invalid (zero value).
	if hunks[1].Old != (lineRange{10, 11}) || hunks[1].New.valid() {
		t.Errorf("hunk 1 = %+v, want old={10 11}, new invalid", hunks[1])
	}
	// Hunk 3: pure addition — old side has count 0, must be invalid.
	if hunks[2].Old.valid() || hunks[2].New != (lineRange{19, 21}) {
		t.Errorf("hunk 2 = %+v, want old invalid, new={19 21}", hunks[2])
	}
}

func TestAggregate_FlagsWhenRubricUntouchedAndStatusChanged(t *testing.T) {
	findings := []fileFinding{
		{Path: "checks.go", RubricTouched: false, StatusLines: []int{42}},
	}
	pf := aggregate("internal/collect/github/example", findings, true)
	if pf == nil {
		t.Fatal("expected a finding")
	}
	if len(pf.Files) != 1 || pf.Files[0].Path != "checks.go" {
		t.Errorf("unexpected finding contents: %+v", pf)
	}
}

func TestAggregate_SilentWhenRubricAlsoTouched(t *testing.T) {
	// The #203 shape: both files changed in the same PR, including the
	// rubric — must not flag, even though a status line also changed.
	findings := []fileFinding{
		{Path: "checks.go", RubricTouched: false, StatusLines: []int{42}},
		{Path: "example.go", RubricTouched: true, StatusLines: nil},
	}
	if pf := aggregate("internal/collect/github/example", findings, true); pf != nil {
		t.Errorf("expected no finding when checkRubrics was touched in the same package, got %+v", pf)
	}
}

func TestAggregate_SilentWhenNoStatusChange(t *testing.T) {
	findings := []fileFinding{
		{Path: "example.go", RubricTouched: false, StatusLines: nil},
	}
	if pf := aggregate("internal/collect/github/example", findings, true); pf != nil {
		t.Errorf("expected no finding when no status line changed, got %+v", pf)
	}
}

// TestAggregate_SilentWhenPackageHasNoLocalRubric is the runhistory case:
// a shared helper package with no checkRubrics of its own at all. There
// is nothing for a reviewer to update, so flagging it would be pure
// noise, not a wave-off-able false positive.
func TestAggregate_SilentWhenPackageHasNoLocalRubric(t *testing.T) {
	findings := []fileFinding{
		{Path: "runhistory.go", RubricTouched: false, StatusLines: []int{7}},
	}
	if pf := aggregate("internal/collect/github/runhistory", findings, false); pf != nil {
		t.Errorf("expected no finding for a package with no local checkRubrics, got %+v", pf)
	}
}

// TestFuncStatusRefs_GroupsByFunctionName proves the basic shape: every
// distinct model.Status* value referenced inside computeStatus's body
// lands in one entry keyed by its name; checkRubrics' own two references
// (never inside a FuncDecl) never produce an entry of their own.
func TestFuncStatusRefs_GroupsByFunctionName(t *testing.T) {
	fset := token.NewFileSet()
	refs, err := funcStatusRefs(fset, []byte(sampleFile))
	if err != nil {
		t.Fatalf("funcStatusRefs: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("got %d function entries, want 1 (computeStatus only): %v", len(refs), refs)
	}
	got, ok := refs["computeStatus"]
	if !ok {
		t.Fatalf("expected an entry for computeStatus, got keys in %v", refs)
	}
	if !sameNames(got.Names, []string{"StatusVerifiedFail", "StatusVerifiedPass"}) {
		t.Errorf("Names = %v, want [StatusVerifiedFail StatusVerifiedPass]", got.Names)
	}
	if len(got.Lines) != 2 {
		t.Errorf("Lines = %v, want 2 entries (one per reference)", got.Lines)
	}
}

// TestFuncStatusRefs_OmitsFunctionsWithNoStatusReferences confirms a
// function that never touches model.Status at all contributes no entry —
// analyzeFile's old-vs-new comparison relies on "absent" and "present
// with an empty set" meaning the same thing, so there must only ever be
// one of those two representations. Also covers a body-less function
// declaration (Body == nil — a //go:linkname or assembly stub, "external"
// below): must be skipped, not panic on a nil-pointer Inspect.
func TestFuncStatusRefs_OmitsFunctionsWithNoStatusReferences(t *testing.T) {
	fset := token.NewFileSet()
	refs, err := funcStatusRefs(fset, []byte("package sample\n\nfunc helper() int { return 42 }\n\nfunc external()\n"))
	if err != nil {
		t.Fatalf("funcStatusRefs: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no entries for a function with no model.Status references, got %v", refs)
	}
}

func TestSameNames(t *testing.T) {
	cases := []struct {
		a, b []string
		want bool
	}{
		{nil, nil, true},
		{[]string{"StatusVerifiedPass"}, []string{"StatusVerifiedPass"}, true},
		{[]string{"StatusVerifiedPass"}, []string{"StatusVerifiedFail"}, false},
		{[]string{"StatusVerifiedPass"}, []string{"StatusVerifiedPass", "StatusVerifiedFail"}, false},
		// The pure occurrence-count case — same single distinct name on
		// both sides, different count. This is the entire reason
		// funcStatusRef is a multiset rather than a deduplicated set (see
		// its own doc comment, and #103's corpus finding in CHANGELOG's
		// #262 entry): a plain set comparison would call these equal.
		{[]string{"StatusVerifiedPass"}, []string{"StatusVerifiedPass", "StatusVerifiedPass"}, false},
	}
	for _, c := range cases {
		if got := sameNames(c.a, c.b); got != c.want {
			t.Errorf("sameNames(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// computeStatusBaseline is the shared "before" fixture for the three
// analyzeFile regression cases below — all three ask the same question
// (given this exact function, did something genuinely change?) against a
// different "after".
const computeStatusBaseline = `package sample

import "github.com/sioakim/attestward/internal/model"

func computeStatus(ok bool) model.Status {
	if ok {
		return model.StatusVerifiedPass
	}
	return model.StatusVerifiedFail
}
`

// TestAnalyzeFile_PositionInsensitiveComparison covers issue #262's core
// case at the analyzeFile level (main_test.go has the real-git-repo
// equivalent for the "silent" subtest) plus its companion proof that
// detection still works.
func TestAnalyzeFile_PositionInsensitiveComparison(t *testing.T) {
	t.Run("silent when only line position moved", func(t *testing.T) {
		// The #261 shape: a named var + fall-through return moves
		// model.StatusVerifiedFail's line with no behavior change. The hunk
		// deliberately overlaps the moved lines — the pre-#262 algorithm
		// would have flagged this alone, proving the test exercises the fix.
		fset := token.NewFileSet()
		newSrc := []byte(`package sample

import "github.com/sioakim/attestward/internal/model"

func computeStatus(ok bool) model.Status {
	status := model.StatusVerifiedFail
	if ok {
		status = model.StatusVerifiedPass
	}
	return status
}
`)
		hunks := []hunk{{Old: lineRange{6, 9}, New: lineRange{6, 10}}}
		ff, err := analyzeFile(fset, "checks.go", []byte(computeStatusBaseline), newSrc, hunks)
		if err != nil {
			t.Fatalf("analyzeFile: %v", err)
		}
		if len(ff.StatusLines) != 0 {
			t.Errorf("StatusLines = %v, want none — the status multiset is unchanged, only line positions moved", ff.StatusLines)
		}
	})

	t.Run("flags a status replaced with a different one", func(t *testing.T) {
		// Companion proof: replacing which status a branch returns (here,
		// StatusVerifiedFail -> StatusPartial, at an UNCHANGED line) must
		// still be caught — the multiset genuinely changes (a name is lost,
		// a different one gained). NOT the same as exchanging which of two
		// EXISTING names sits in which branch (a true swap) — that leaves
		// the multiset identical and is a confirmed, documented blind spot
		// (main.go's own doc comment, issue #262's re-review). Once
		// flagged, the whole function's lines are reported (7 and 9, not
		// just 9) — a changed multiset is a whole-function finding,
		// matching this guard's "coarse, not exhaustive" design.
		fset := token.NewFileSet()
		newSrc := []byte(`package sample

import "github.com/sioakim/attestward/internal/model"

func computeStatus(ok bool) model.Status {
	if ok {
		return model.StatusVerifiedPass
	}
	return model.StatusPartial
}
`)
		hunks := []hunk{{Old: lineRange{9, 9}, New: lineRange{9, 9}}}
		ff, err := analyzeFile(fset, "checks.go", []byte(computeStatusBaseline), newSrc, hunks)
		if err != nil {
			t.Fatalf("analyzeFile: %v", err)
		}
		want := []int{7, 9}
		if len(ff.StatusLines) != len(want) || ff.StatusLines[0] != want[0] || ff.StatusLines[1] != want[1] {
			t.Errorf("StatusLines = %v, want %v — a swapped status constant at an unchanged line must still be caught", ff.StatusLines, want)
		}
	})
}
