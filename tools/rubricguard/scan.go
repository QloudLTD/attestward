// Package main implements rubricguard: a CI guard for issue #209 — a
// collector can change what status it assigns while its checkRubrics
// entry (what docs/checks-reference.md publishes, what a compliance
// reader relies on) stays stale, and nothing catches that today.
// make checks-docs-check only compares the generated doc against the
// rubric *source*; it has no opinion on whether the rubric matches the
// collector's own status-assignment logic. This does, from the other
// direction: for each internal/collect/** package touched by a diff, flag
// one whose non-test .go files gained/changed a genuine `model.Status*`
// reference outside its own `checkRubrics` var while checkRubrics itself
// went untouched.
//
// Deliberately coarse, not exhaustive (see this package's own doc
// comment in main.go for why): it flags "a status reference changed
// somewhere in the package, and checkRubrics didn't," not "this specific
// check's specific rubric clause is now wrong." A reviewer reads the
// flagged diff and decides; the guard's job is making sure a reviewer
// looks, the way #202's review round 1 had to happen by chance.
//
// A green run is not proof status behavior is unchanged — see main.go's
// own doc comment for the two known false-negative classes (a condition
// flipping without any status-constant line changing; aggregate's
// package-wide OR below, a partial-#202 shape this guard can't see).
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// lineRange is an inclusive [Start, End] line range, 1-indexed. The zero
// value is "no such range" (e.g. checkRubrics doesn't exist in this
// file, or a hunk is pure-addition/pure-deletion on one side).
type lineRange struct {
	Start, End int
}

func (r lineRange) valid() bool { return r.Start > 0 && r.End >= r.Start }

func (r lineRange) overlaps(other lineRange) bool {
	if !r.valid() || !other.valid() {
		return false
	}
	return r.Start <= other.End && other.Start <= r.End
}

// hunk is one unified-diff hunk's old/new line ranges, from `git diff
// -U0` (zero context — every line in a hunk is one that actually
// changed, so overlap-with-a-span checks are exact, not approximate).
type hunk struct {
	Old, New lineRange
}

var hunkHeaderRe = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

// parseHunks extracts every hunk's old/new ranges from a `git diff -U0`
// unified-diff text (for one file). A count of 0 (git's convention for a
// pure addition or pure deletion on one side) becomes an invalid
// (zero-value) lineRange on that side, so it never spuriously overlaps
// anything — the correct behavior for "no old/new lines here to compare
// a span against," not a special case to reason about at each call site.
func parseHunks(diff string) []hunk {
	var hunks []hunk
	for _, line := range strings.Split(diff, "\n") {
		m := hunkHeaderRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		oldStart, _ := strconv.Atoi(m[1])
		oldCount := 1
		if m[2] != "" {
			oldCount, _ = strconv.Atoi(m[2])
		}
		newStart, _ := strconv.Atoi(m[3])
		newCount := 1
		if m[4] != "" {
			newCount, _ = strconv.Atoi(m[4])
		}
		var h hunk
		if oldCount > 0 {
			h.Old = lineRange{oldStart, oldStart + oldCount - 1}
		}
		if newCount > 0 {
			h.New = lineRange{newStart, newStart + newCount - 1}
		}
		hunks = append(hunks, h)
	}
	return hunks
}

// rubricSpan returns the line range of the package-level
// `var checkRubrics = ...` declaration in src, or the zero lineRange if
// no such declaration exists in this file. Every collector package in
// this repo uses exactly this name (verified across all 20 GitHub/Azure
// DevOps collector packages, issue #209) — a single, consistent target,
// not a guess at conventions that might vary.
func rubricSpan(fset *token.FileSet, src []byte) (lineRange, error) {
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		return lineRange{}, err
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, name := range vs.Names {
				if name.Name == "checkRubrics" {
					return lineRange{
						Start: fset.Position(gd.Pos()).Line,
						End:   fset.Position(gd.End()).Line,
					}, nil
				}
			}
		}
	}
	return lineRange{}, nil
}

// statusLines returns the line numbers of every genuine model.Status*
// reference in src — an *ast.SelectorExpr whose X is the identifier
// "model" and whose Sel name is a Status *value* constant
// (StatusVerifiedPass, StatusPartial, ...), not the bare model.Status
// *type* itself (a function signature or field typed model.Status
// doesn't assert which status gets produced, so it isn't evidence of a
// status-assignment change) — that falls outside excl. Walking the AST
// rather than scanning text means a comment or a rubric string that
// merely *mentions* "model.StatusPartial" in prose (this codebase's own
// doc comments do that routinely) can never appear here: ast.Inspect
// only visits real syntax nodes, never comment text or string-literal
// contents.
func statusLines(fset *token.FileSet, src []byte, excl lineRange) (map[int]bool, error) {
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		return nil, err
	}
	lines := map[int]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "model" {
			return true
		}
		if !strings.HasPrefix(sel.Sel.Name, "Status") || sel.Sel.Name == "Status" {
			return true
		}
		line := fset.Position(sel.Pos()).Line
		if excl.valid() && line >= excl.Start && line <= excl.End {
			return true
		}
		lines[line] = true
		return true
	})
	return lines, nil
}

// declaresRubric reports whether src declares a package-level
// checkRubrics var at all — distinct from rubricSpan's "is it valid",
// used to decide whether a package has any local rubric to go stale in
// the first place. A shared helper package (e.g. runhistory, consumed by
// both sasthistory and scahistory but not itself a rubric-publishing
// collector) has none; flagging a status-line change there would point a
// reviewer at a rubric that doesn't exist and never will.
func declaresRubric(fset *token.FileSet, src []byte) (bool, error) {
	span, err := rubricSpan(fset, src)
	if err != nil {
		return false, err
	}
	return span.valid(), nil
}

// funcStatusRef is one function's model.Status* footprint: every status
// name it references, one entry per occurrence — a multiset, sorted, NOT
// deduplicated — plus Lines, kept only for reporting once a genuine
// change is found. Multiset, not a deduplicated set: a set lets a new
// branch reusing an already-referenced status name go unnoticed (found
// empirically — see CHANGELOG's #262 entry). sameNames' plain positional
// comparison of two sorted slices works unmodified as a multiset check.
type funcStatusRef struct {
	Names []string
	Lines []int
}

// funcStatusRefs walks every top-level function declaration in src (nil
// Body — an external/assembly declaration — contributes nothing) and
// returns each one's funcStatusRef, keyed by name (receiver-qualified,
// e.g. "Foo.Bar", so two same-named methods on different types can't
// collide — no check function here currently has a receiver, but the key
// shape shouldn't assume that stays true). A function with no status
// references is omitted entirely, not present with an empty Names/Lines —
// "absent from oldFuncs" and "a newly added function" mean the same thing
// in analyzeFile's comparison below.
func funcStatusRefs(fset *token.FileSet, src []byte) (map[string]funcStatusRef, error) {
	f, err := parser.ParseFile(fset, "", src, 0)
	if err != nil {
		return nil, err
	}
	refs := map[string]funcStatusRef{}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		key := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			if t := recvTypeName(fd.Recv.List[0].Type); t != "" {
				key = t + "." + key
			}
		}
		var names []string
		var lines []int
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "model" {
				return true
			}
			if !strings.HasPrefix(sel.Sel.Name, "Status") || sel.Sel.Name == "Status" {
				return true
			}
			names = append(names, sel.Sel.Name)
			lines = append(lines, fset.Position(sel.Pos()).Line)
			return true
		})
		if len(names) == 0 {
			continue
		}
		// Sorted independently, not as parallel keys: Names feeds
		// sameNames' multiset comparison, which only needs Names in some
		// consistent order, and Lines is collected purely for reporting
		// (fileFinding.StatusLines, sorted again on its own at the end of
		// analyzeFile). Sorting each on its own terms means Names[i] and
		// Lines[i] do NOT correspond to the same occurrence once i > 0.
		// Harmless today — nothing reads them as a pair — but don't add a
		// "which line is name X at" feature on top of this without fixing
		// that first.
		sort.Strings(names)
		sort.Ints(lines)
		refs[key] = funcStatusRef{Names: names, Lines: lines}
	}
	return refs, nil
}

// recvTypeName extracts a method receiver's bare type name (T from "t T"
// or "t *T") — anything else yields "", and funcStatusRefs falls back to
// the bare method name as its key.
//
// A generic receiver ("t Foo[T]", *ast.IndexExpr, or "t Foo[K, V]",
// *ast.IndexListExpr) is one such anything-else: it yields "", so two
// generic methods sharing a bare name would collide on the same
// unqualified key in funcStatusRefs' map, and the later declaration's
// funcStatusRef would silently overwrite the earlier one's. That's not a
// silent miss, though — the overwritten function's lines drop out of
// inFunc in analyzeFile, so they fall through to the hunk-overlap safety
// net (scan.go's own comment above that block) instead of being exempted
// outright. Degrades safely, not fixed, because there are zero generic
// receivers under internal/collect today (verified directly) — not worth
// the complexity of a richer key until one exists.
func recvTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return recvTypeName(t.X)
	default:
		return ""
	}
}

// sameNames reports whether a and b (both already sorted by
// funcStatusRefs) are the identical multiset of status names — a plain
// positional comparison of two sorted slices, which is exactly what a
// multiset equality check is; no separate counting step needed. See
// funcStatusRef's own doc comment for why this must be occurrence-count-
// sensitive, not a deduplicated set comparison.
func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fileFinding is one changed file's contribution to a package's result:
// whether it touched checkRubrics, and which of its own (new-version)
// lines belong to a function whose model.Status* footprint genuinely
// changed.
type fileFinding struct {
	Path          string
	RubricTouched bool
	StatusLines   []int
}

// analyzeFile computes one changed file's fileFinding. oldSrc is nil for
// a newly added file (nothing to diff checkRubrics's old span, or any
// function's old status set, against — correct, since a brand-new file's
// content, checkRubrics included, is being created in this very diff,
// which counts as "touched"/"changed").
func analyzeFile(fset *token.FileSet, path string, oldSrc, newSrc []byte, hunks []hunk) (fileFinding, error) {
	ff := fileFinding{Path: path}

	newRubric, err := rubricSpan(fset, newSrc)
	if err != nil {
		return ff, err
	}
	var oldRubric lineRange
	if oldSrc != nil {
		oldRubric, err = rubricSpan(fset, oldSrc)
		if err != nil {
			return ff, err
		}
	}
	for _, h := range hunks {
		if h.New.overlaps(newRubric) || h.Old.overlaps(oldRubric) {
			ff.RubricTouched = true
			break
		}
	}

	// The position-insensitive comparison (issue #262): a function with an
	// unchanged multiset is exempt no matter where its status references
	// now sit. Only a function whose multiset genuinely changed — or
	// that's new outright — contributes its (new-version) lines.
	newFuncs, err := funcStatusRefs(fset, newSrc)
	if err != nil {
		return ff, err
	}
	var oldFuncs map[string]funcStatusRef
	if oldSrc != nil {
		oldFuncs, err = funcStatusRefs(fset, oldSrc)
		if err != nil {
			return ff, err
		}
	}
	hitSet := map[int]bool{}
	inFunc := map[int]bool{}
	for name, nf := range newFuncs {
		for _, l := range nf.Lines {
			inFunc[l] = true
		}
		if of, existed := oldFuncs[name]; existed && sameNames(of.Names, nf.Names) {
			continue
		}
		for _, l := range nf.Lines {
			hitSet[l] = true
		}
	}

	// Safety net, deliberately untested (this codebase's check-function
	// convention doesn't produce this shape — verified directly): a
	// model.Status* reference outside both checkRubrics and every
	// function has no multiset to compare — fall back to the original
	// hunk-overlap check rather than silently exempting it.
	newStatus, err := statusLines(fset, newSrc, newRubric)
	if err != nil {
		return ff, err
	}
	for line := range newStatus {
		if inFunc[line] {
			continue
		}
		for _, h := range hunks {
			if h.New.valid() && line >= h.New.Start && line <= h.New.End {
				hitSet[line] = true
			}
		}
	}

	hits := make([]int, 0, len(hitSet))
	for l := range hitSet {
		hits = append(hits, l)
	}
	sort.Ints(hits)
	ff.StatusLines = hits
	return ff, nil
}

// packageFinding is the aggregated, package-level verdict: flagged only
// if at least one changed file in the package gained a status reference
// outside checkRubrics, checkRubrics itself was untouched anywhere in the
// package's changed files, and the package has a local checkRubrics
// declaration at all (skipping shared helper packages with none).
//
// "checkRubrics itself was untouched anywhere in the package's changed
// files" is a package-wide OR (rubricTouched below), not per-check — a
// known false negative (round 2 review, F2), not a bug: a genuine new
// status case in check A, with no rubric update, silently escapes
// detection if the same diff also touches check B's rubric string for
// any reason at all, cosmetic or not, since every check's rubric lives
// in one shared checkRubrics map per package. This is exactly the
// partial-#202 shape ("updated one check's rubric, forgot the other's")
// this guard is blindest to; per-check tracking would need to associate
// each status reference with a specific check ID, which the AST alone
// doesn't give without a real dataflow analysis this guard doesn't do.
type packageFinding struct {
	Dir   string
	Files []fileFinding // only files with StatusLines, for reporting
}

func aggregate(dir string, findings []fileFinding, hasRubric bool) *packageFinding {
	if !hasRubric {
		return nil
	}
	rubricTouched := false
	var withHits []fileFinding
	for _, ff := range findings {
		if ff.RubricTouched {
			rubricTouched = true
		}
		if len(ff.StatusLines) > 0 {
			withHits = append(withHits, ff)
		}
	}
	if rubricTouched || len(withHits) == 0 {
		return nil
	}
	return &packageFinding{Dir: dir, Files: withHits}
}
