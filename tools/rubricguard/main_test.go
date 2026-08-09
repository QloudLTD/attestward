package main

import (
	"fmt"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise run() end-to-end against a real, throwaway git
// repository — all local disk operations, no network calls, same as any
// other os.MkdirTemp-based fixture in this repo's test suite. A real git
// repo (rather than hand-built diff text) is what actually proves the
// merge-base handling and file-content plumbing work, not just the
// AST/hunk-overlap logic scan_test.go already covers in isolation.

const exampleRubricV1 = `package example

import "gitlab.com/sioakeim/attestward/internal/model"

var checkRubrics = map[string]map[model.Status]string{
	"C99.example.check": {
		model.StatusVerifiedPass: "it passed",
		model.StatusVerifiedFail: "it failed",
	},
}
`

const exampleRubricV2 = `package example

import "gitlab.com/sioakeim/attestward/internal/model"

var checkRubrics = map[string]map[model.Status]string{
	"C99.example.check": {
		model.StatusVerifiedPass:  "it passed",
		model.StatusVerifiedFail:  "it failed",
		model.StatusNotCheckable: "could not be determined",
	},
}
`

const exampleChecksV1 = `package example

import "gitlab.com/sioakeim/attestward/internal/model"

func computeStatus(ok bool) model.Status {
	if ok {
		return model.StatusVerifiedPass
	}
	return model.StatusVerifiedFail
}
`

// exampleChecksV1Reduced is exampleChecksV1 with the fail branch removed —
// used only by the naive-direct-diff proof below, to construct a case
// where a naive base..head diff (not merge-base based) shows a status
// reference reappearing on the "new" side even though the PR that
// "head" belongs to never touched this file.
const exampleChecksV1Reduced = `package example

import "gitlab.com/sioakeim/attestward/internal/model"

func computeStatus(ok bool) model.Status {
	return model.StatusVerifiedPass
}
`

// exampleChecksV2 is the #202 shape: a new case producing a status the
// rubric (still at V1 in the "no rubric update" tests below) never
// mentions.
const exampleChecksV2 = `package example

import "gitlab.com/sioakeim/attestward/internal/model"

func computeStatus(ok, checkable bool) model.Status {
	if !checkable {
		return model.StatusNotCheckable
	}
	if ok {
		return model.StatusVerifiedPass
	}
	return model.StatusVerifiedFail
}
`

// exampleChecksV1LineMoved is exampleChecksV1's identical status logic,
// restructured (a named var + fall-through return) so
// model.StatusVerifiedFail's line moves — mirroring #261's own false
// positive. Same outcome for every input: ok=true -> Pass, ok=false -> Fail.
const exampleChecksV1LineMoved = `package example

import "gitlab.com/sioakeim/attestward/internal/model"

func computeStatus(ok bool) model.Status {
	status := model.StatusVerifiedFail
	if ok {
		status = model.StatusVerifiedPass
	}
	return status
}
`

const exampleChecksTestV1 = `package example

import (
	"testing"

	"gitlab.com/sioakeim/attestward/internal/model"
)

func TestComputeStatus(t *testing.T) {
	if got := computeStatus(true); got != model.StatusVerifiedPass {
		t.Errorf("got %v", got)
	}
}
`

// exampleChecksTestV2 adds a new assertion referencing
// model.StatusVerifiedFail — a change to a _test.go file only, which
// must never be mistaken for a production status-assignment change.
const exampleChecksTestV2 = `package example

import (
	"testing"

	"gitlab.com/sioakeim/attestward/internal/model"
)

func TestComputeStatus(t *testing.T) {
	if got := computeStatus(true); got != model.StatusVerifiedPass {
		t.Errorf("got %v", got)
	}
	if got := computeStatus(false); got != model.StatusVerifiedFail {
		t.Errorf("got %v", got)
	}
}
`

// exampleChecksV1CommentOnly is exampleChecksV1 with an added comment
// above computeStatus — no code line changes at all.
const exampleChecksV1CommentOnly = `package example

import "gitlab.com/sioakeim/attestward/internal/model"

// computeStatus decides pass or fail. Nothing about model.Status
// assignment changed here — only this comment was added.
func computeStatus(ok bool) model.Status {
	if ok {
		return model.StatusVerifiedPass
	}
	return model.StatusVerifiedFail
}
`

const runhistoryHelper = `package runhistory

import "gitlab.com/sioakeim/attestward/internal/model"

// classify has no local checkRubrics — the rubric for whatever consumes
// this lives in the calling collector package, not here.
func classify(matched bool) model.Status {
	if matched {
		return model.StatusVerifiedPass
	}
	return model.StatusNotCheckable
}
`

const runhistoryHelperV2 = `package runhistory

import "gitlab.com/sioakeim/attestward/internal/model"

// classify has no local checkRubrics — the rubric for whatever consumes
// this lives in the calling collector package, not here.
func classify(matched, ambiguous bool) model.Status {
	if ambiguous {
		return model.StatusPartial
	}
	if matched {
		return model.StatusVerifiedPass
	}
	return model.StatusNotCheckable
}
`

// mainBranch is newRepo's initial branch name, pinned explicitly rather
// than relying on git's own init.defaultBranch config (which varies by
// git version/system config) — TestRun_IgnoresUnrelatedMainDrift needs a
// known name to `git checkout` back to after branching off for the PR
// side.
const mainBranch = "main"

func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", mainBranch)
	gitRun(t, dir, "config", "user.email", "test@test.invalid")
	gitRun(t, dir, "config", "user.name", "rubricguard test")
	return dir
}

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func writeFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commit(t *testing.T, dir, msg string) string {
	t.Helper()
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", msg)
	return strings.TrimSpace(gitRun(t, dir, "rev-parse", "HEAD"))
}

// chdir points the process at dir for the duration of the calling test —
// run()'s git shell-outs use the ambient working directory, same as any
// CLI tool invoked from a repo root in CI. Go tests in one package run
// sequentially unless t.Parallel() is called, which none of these do, so
// this is safe.
func chdir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

// formatFindings renders findings for test failure messages. `%+v` on
// []*packageFinding prints pointer addresses (e.g. "[0x5300fffd6ea0]"),
// not the package/file/line information a failure exists to convey
// (round 3 review, nit 2) — this dereferences instead.
func formatFindings(findings []*packageFinding) string {
	if len(findings) == 0 {
		return "[]"
	}
	var b strings.Builder
	for i, pf := range findings {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s:", pf.Dir)
		for j, f := range pf.Files {
			if j > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, " %s(lines %v)", f.Path, f.StatusLines)
		}
	}
	return b.String()
}

func TestRun_FlagsStatusChangeWithoutRubricUpdate(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "internal/collect/github/example/example.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1)
	base := commit(t, dir, "base")

	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV2)
	head := commit(t, dir, "head: new not-checkable case, rubric untouched")

	chdir(t, dir)
	findings, err := run(base, head)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %s", len(findings), formatFindings(findings))
	}
	if findings[0].Dir != "internal/collect/github/example" {
		t.Errorf("finding dir = %q", findings[0].Dir)
	}
	if len(findings[0].Files) != 1 || findings[0].Files[0].Path != "internal/collect/github/example/checks.go" {
		t.Errorf("finding files = %+v", findings[0].Files)
	}
}

// TestRun_SilentWhenStatusReferenceOnlyMovedWithinFunction is issue
// #262's end-to-end regression case (scan_test.go's
// TestAnalyzeFile_PositionInsensitiveComparison covers it directly): the
// #261 shape, through a real git repo instead of a hand-built hunk.
func TestRun_SilentWhenStatusReferenceOnlyMovedWithinFunction(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "internal/collect/github/example/example.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1)
	base := commit(t, dir, "base")

	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1LineMoved)
	head := commit(t, dir, "head: restructured, identical status set, rubric untouched")

	chdir(t, dir)
	findings, err := run(base, head)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for pure status-reference movement within an unchanged function (issue #262, #261's own false positive), got %s", formatFindings(findings))
	}
}

func TestRun_SilentWhenRubricAlsoUpdated(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "internal/collect/github/example/example.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1)
	base := commit(t, dir, "base")

	writeFile(t, dir, "internal/collect/github/example/example.go", exampleRubricV2)
	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV2)
	head := commit(t, dir, "head: new case, rubric updated in the same commit")

	chdir(t, dir)
	findings, err := run(base, head)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings when the rubric was updated too, got %s", formatFindings(findings))
	}
}

func TestRun_SilentWhenOnlyTestFileChanged(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "internal/collect/github/example/example.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1)
	writeFile(t, dir, "internal/collect/github/example/checks_test.go", exampleChecksTestV1)
	base := commit(t, dir, "base")

	writeFile(t, dir, "internal/collect/github/example/checks_test.go", exampleChecksTestV2)
	head := commit(t, dir, "head: test file only, new assertion referencing model.StatusVerifiedFail")

	chdir(t, dir)
	findings, err := run(base, head)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a _test.go-only change, got %s", formatFindings(findings))
	}
}

// TestRun_SilentForBrandNewCollectorPackage covers a case none of the
// scan.go unit tests exercise end-to-end through run() itself: an
// entirely new package (both example.go and checks.go added in the same
// diff, base has no internal/collect/github/newcollector at all).
// oldSrc is nil for every file here (showFileOrNil's "doesn't exist at
// this ref" path) — checkRubrics is being created, not left stale, so
// this must never be flagged even though status references obviously
// "changed" (from nothing to something) in the same files.
func TestRun_SilentForBrandNewCollectorPackage(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "README.md", "placeholder so the repo has a base commit\n")
	base := commit(t, dir, "base")

	writeFile(t, dir, "internal/collect/github/newcollector/newcollector.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/newcollector/checks.go", exampleChecksV1)
	head := commit(t, dir, "head: introduce a brand-new collector package")

	chdir(t, dir)
	findings, err := run(base, head)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a brand-new collector package, got %s", formatFindings(findings))
	}
}

func TestRun_SilentWhenOnlyCommentChanged(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "internal/collect/github/example/example.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1)
	base := commit(t, dir, "base")

	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1CommentOnly)
	head := commit(t, dir, "head: added a comment, no code line changed")

	chdir(t, dir)
	findings, err := run(base, head)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a comment-only change (no status line itself changed), got %s", formatFindings(findings))
	}
}

func TestRun_SilentForPackageWithNoLocalRubric(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "internal/collect/github/runhistory/runhistory.go", runhistoryHelper)
	base := commit(t, dir, "base")

	writeFile(t, dir, "internal/collect/github/runhistory/runhistory.go", runhistoryHelperV2)
	head := commit(t, dir, "head: new status case in a package with no checkRubrics of its own")

	chdir(t, dir)
	findings, err := run(base, head)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for a package with no local checkRubrics, got %s", formatFindings(findings))
	}
}

// TestRun_IgnoresUnrelatedMainDrift is the merge-base claim: main moves
// forward on its own after a PR branches (routine in this repo's actual
// history — #211 and #176 both needed a rebase mid-review for exactly
// this reason). A second, unrelated collector package gets a real
// rubric-drift defect committed straight to "main" (the base branch)
// *after* the PR branched off — this run() call must not attribute that
// to the PR at all, since the PR's own diff never touches it.
//
// Review round 2 found the first version of this test didn't actually
// exercise any of that: all three commits landed sequentially on one
// branch (linear history, no fork), so merge-base(base, prHead) trivially
// resolved to prHead itself, changedCollectorFiles came back empty, and
// run returned before any merge-base-specific logic ever ran — it would
// have passed against a naive implementation that diffed base..head
// directly, i.e. against the exact bug it exists to prove doesn't exist.
// Fixed by actually branching: the PR's commit lands on its own branch
// off branchPoint, "main" advances independently back on mainBranch.
//
// Review round 3 then found the *fix* for that was itself incomplete:
// the sibling test below proved a naive reimplementation gets this
// fixture wrong, but never called the real run() on it — so it proved
// "a naive implementation would be wrong", not "ours isn't", and
// wouldn't have caught a real regression to naive behavior in run()
// itself. Fixed by adding that exact call at the end of the sibling
// test; see its own doc comment for why that specific gap mattered.
func TestRun_IgnoresUnrelatedMainDrift(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "internal/collect/github/example/example.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1)
	writeFile(t, dir, "internal/collect/github/other/other.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/other/checks.go", exampleChecksV1)
	branchPoint := commit(t, dir, "branch point")

	// The PR's own branch, forked from branchPoint: a clean, unrelated
	// change (a comment only) to "example" — must never be flagged.
	gitRun(t, dir, "checkout", "-q", "-b", "pr")
	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1CommentOnly)
	prHead := commit(t, dir, "PR: comment-only change to example")

	// Meanwhile, back on mainBranch (NOT a descendant of the PR branch —
	// a real fork, not a continuation of it): a genuine rubric-drift
	// defect lands in the unrelated "other" package, after the PR
	// branched off. This must not leak into the PR's own result.
	gitRun(t, dir, "checkout", "-q", mainBranch)
	writeFile(t, dir, "internal/collect/github/other/checks.go", exampleChecksV2)
	base := commit(t, dir, "main: unrelated rubric drift in other, after the PR branched")

	chdir(t, dir)

	mergeBase, err := gitOutput("merge-base", base, prHead)
	if err != nil {
		t.Fatalf("merge-base: %v", err)
	}
	if strings.TrimSpace(mergeBase) != branchPoint {
		t.Fatalf("test fixture isn't actually forked: merge-base(base, prHead) = %s, want branchPoint %s",
			strings.TrimSpace(mergeBase), branchPoint)
	}

	findings, err := run(base, prHead)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings — the only real defect is on base's own post-branch history, not in this PR's diff — got %s", formatFindings(findings))
	}

	// Sanity check on the test fixture itself: diffing branchPoint to
	// base directly (i.e. what actually landed on "main") really is
	// flaggable — proving the fixture is a genuine defect, not one that
	// happens to be invisible to run() for some unrelated reason.
	findings, err = run(branchPoint, base)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the main-only drift to be flagged when diffed on its own terms, got %d findings", len(findings))
	}
}

// TestRun_IgnoresUnrelatedMainDrift_FailsAgainstNaiveDirectDiff proves two
// separate claims against the identical fixture, both required — round 3
// review's finding was that the first version of this test proved only
// the first one, which is not by itself evidence about the code:
//
//  1. A naive reimplementation ("diff straight from base", the bug the
//     real run() no longer has) gets this fixture wrong — via the inline
//     naiveRun below.
//  2. The REAL run() gets it right — a direct call, at the end of this
//     test, on the exact same base/prHead. Without this second call, the
//     test only shows "a naive implementation would be wrong", never
//     "ours isn't", and a real regression to naive behavior inside run()
//     itself (verified live: swapping `mergeBase := base` into run()
//     directly) would leave every test in this file green, including
//     this one and TestRun_IgnoresUnrelatedMainDrift above.
//
// The fixture differs from the test above on purpose: analyzeFile only
// ever inspects the *new*-side file for status references (matching
// #202's own shape — new code producing an undescribed status), so a
// naive base..head diff only visibly misattributes something to the PR
// when head's own (PR-untouched) content has *more* status references
// than base's does — i.e. when main's independent drift *removed* a
// status reference "other" always had, making head's still-original
// content look like it "added" that reference back when compared
// directly against base instead of against the real merge-base.
func TestRun_IgnoresUnrelatedMainDrift_FailsAgainstNaiveDirectDiff(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "internal/collect/github/example/example.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1)
	writeFile(t, dir, "internal/collect/github/other/other.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/other/checks.go", exampleChecksV1)
	commit(t, dir, "branch point")

	gitRun(t, dir, "checkout", "-q", "-b", "pr")
	writeFile(t, dir, "internal/collect/github/example/checks.go", exampleChecksV1CommentOnly)
	prHead := commit(t, dir, "PR: comment-only change to example")

	gitRun(t, dir, "checkout", "-q", mainBranch)
	writeFile(t, dir, "internal/collect/github/other/checks.go", exampleChecksV1Reduced)
	base := commit(t, dir, "main: unrelated simplification of other, after the PR branched")

	chdir(t, dir)

	// naiveRun mirrors run() exactly, except it diffs base..head directly
	// instead of computing the merge-base first — the exact defect class
	// this test is supposed to catch.
	naiveRun := func(base, head string) ([]*packageFinding, error) {
		changed, err := changedCollectorFiles(base, head)
		if err != nil {
			return nil, err
		}
		fset := token.NewFileSet()
		byDir := map[string][]fileFinding{}
		var dirOrder []string
		for _, path := range changed {
			hunks, err := diffHunks(base, head, path)
			if err != nil {
				return nil, err
			}
			newSrc, err := showFile(head, path)
			if err != nil {
				return nil, err
			}
			oldSrc, err := showFileOrNil(base, path)
			if err != nil {
				return nil, err
			}
			ff, err := analyzeFile(fset, path, oldSrc, newSrc, hunks)
			if err != nil {
				continue
			}
			dir := filepath.Dir(path)
			if _, seen := byDir[dir]; !seen {
				dirOrder = append(dirOrder, dir)
			}
			byDir[dir] = append(byDir[dir], ff)
		}
		var findings []*packageFinding
		for _, dir := range dirOrder {
			hasRubric, err := packageHasRubric(fset, head, dir)
			if err != nil {
				return nil, err
			}
			if pf := aggregate(dir, byDir[dir], hasRubric); pf != nil {
				findings = append(findings, pf)
			}
		}
		return findings, nil
	}

	findings, err := naiveRun(base, prHead)
	if err != nil {
		t.Fatalf("naiveRun: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("naiveRun(base, prHead) found nothing — this fixture is supposed to demonstrate a " +
			"direct-diff implementation wrongly attributing main's own post-branch drift to the PR; " +
			"if it finds nothing, the fixture itself isn't proving what this test claims")
	}
	// It must specifically be "other" — the package the PR never
	// touched — not "example", or this would just be a (correct) finding
	// about the PR's own change, proving nothing about the merge-base
	// bug this test exists to demonstrate.
	found := false
	for _, pf := range findings {
		if pf.Dir == "internal/collect/github/other" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected naiveRun to misattribute drift to internal/collect/github/other specifically, got %s", formatFindings(findings))
	}

	// The assertion that actually guards the code: the REAL run() — not
	// the inline naiveRun reimplementation above — must return nothing
	// for this identical fixture. Round 3 review's finding: without this
	// call, the test only proves "a naive implementation would be
	// wrong", never "ours isn't" — those are different claims, and a
	// naive mergeBase := base swapped into run() itself made every
	// TestRun_* test in this file pass anyway, because none of them
	// actually invoked run() on a fixture where the naive and
	// merge-base answers diverge. This is that fixture, and this is
	// run() itself.
	realFindings, err := run(base, prHead)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(realFindings) != 0 {
		t.Fatalf("run() misattributed main's own post-branch drift to the PR: %s", formatFindings(realFindings))
	}
}

// TestRun_NoCommonAncestorSkipsCleanly is F4: base and head sharing no
// history at all (git merge-base's "no common ancestor" case, exit 1) is
// treated the same way ci.yaml's own range-determination step already
// treats every other "nothing sane to diff" case — a clean skip, not a
// tool error that reddens the job over something that isn't a code
// problem.
func TestRun_NoCommonAncestorSkipsCleanly(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "README.md", "a\n")
	a := commit(t, dir, "a1")

	gitRun(t, dir, "checkout", "-q", "--orphan", "unrelated")
	// An orphan checkout leaves the previous branch's files staged;
	// clear them so this commit truly starts from nothing.
	gitRun(t, dir, "rm", "-rf", "-q", "--cached", ".")
	writeFile(t, dir, "README.md", "b\n")
	b := commit(t, dir, "b1")

	chdir(t, dir)
	findings, err := run(a, b)
	if err != nil {
		t.Fatalf("run: expected a clean skip, got an error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for unrelated histories, got %s", formatFindings(findings))
	}
}

// TestRun_InvalidRefStillErrors is the other half of F4's distinction: a
// genuinely broken ref (not "no common ancestor", but "no such object at
// all" — the shape a real bug in how the caller computed a SHA would
// take) must still surface as a real error, not be swallowed by the same
// skip path.
func TestRun_InvalidRefStillErrors(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "README.md", "a\n")
	a := commit(t, dir, "a1")

	chdir(t, dir)
	if _, err := run(a, "not-a-real-ref-0000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected an error for a nonexistent ref, got none")
	}
}

// TestPackageHasRubric_NonASCIIFilename is F6 (round 3 review). `git
// ls-tree` (without -z) applies core.quotePath and C-quotes any
// "unusual" byte in a path — confirmed directly: a file named
// "héllo.go" comes back from `git ls-tree --name-only` as the literal
// string `"h\303\251llo.go"`, a quoted, escaped representation, not a
// real path.
//
// Verified precisely what that does in this tool's actual code, rather
// than assuming: the quoted string's *own* trailing `"` means it no
// longer ends in literal ".go", so packageHasRubric's existing
// .go/_test.go suffix filter (there for an unrelated reason — excluding
// non-Go and test files) incidentally excludes it too, silently — a
// false negative (a real checkRubrics goes undetected), not the hard
// `git show` failure a naive trace through the code suggests. Confirmed
// by reverting to the non -z form and running this exact test: it
// returns `has=false, err=nil`, not an error. Still a real defect either
// way — this test's fixture puts checkRubrics itself in the non-ASCII
// file specifically, with no other candidate in the package, so a
// silent miss is directly observable as `has == false` rather than
// masked by an unrelated file's early return. -z avoids the quoting
// entirely (raw, NUL-separated paths), fixing it either way.
func TestPackageHasRubric_NonASCIIFilename(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "internal/collect/github/example/héllo.go", exampleRubricV1)
	head := commit(t, dir, "the package's only .go file, and its only checkRubrics, has a non-ASCII name")

	chdir(t, dir)
	fset := token.NewFileSet()
	has, err := packageHasRubric(fset, head, "internal/collect/github/example")
	if err != nil {
		t.Fatalf("packageHasRubric errored on a package containing a non-ASCII filename: %v", err)
	}
	if !has {
		t.Error("expected the package's real checkRubrics (in the non-ASCII-named file) to be found")
	}
}

// TestRun_FlagsStatusChangeInNonASCIIFilename is changedCollectorFiles'
// twin of the test above: `git diff --name-only` (without -z) has the
// identical core.quotePath vulnerability (confirmed directly, same
// shape) — a *changed* status-assignment line in a non-ASCII-named file
// would silently drop out of the changed-files list entirely, end to
// end, never reaching analyzeFile at all. Found while fixing F6, not
// itself named in review — same underlying cause, same fix.
func TestRun_FlagsStatusChangeInNonASCIIFilename(t *testing.T) {
	dir := newRepo(t)
	writeFile(t, dir, "internal/collect/github/example/example.go", exampleRubricV1)
	writeFile(t, dir, "internal/collect/github/example/checks_ünïcödé.go", exampleChecksV1)
	base := commit(t, dir, "base")

	writeFile(t, dir, "internal/collect/github/example/checks_ünïcödé.go", exampleChecksV2)
	head := commit(t, dir, "head: new not-checkable case in a non-ASCII-named file, rubric untouched")

	chdir(t, dir)
	findings, err := run(base, head)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the status change in the non-ASCII-named file to be flagged, got %d findings: %s", len(findings), formatFindings(findings))
	}
}

// TestRun_ShallowCloneErrorsInsteadOfSilentSkip is F4's nit (round 3
// review): a shallow clone also makes `git merge-base` exit 1 — the
// identical signature as a genuine "no common ancestor" — because the
// two commits' real shared ancestor lies beyond the fetch depth, not
// because their histories are actually unrelated. Confirmed directly
// with a real shallow clone before writing this: two commits where one
// is genuinely the other's grandparent, each fetched with its own
// `--depth 1` so the connecting history is never present locally, gives
// merge-base exit 1 with no stderr — indistinguishable from
// TestRun_NoCommonAncestorSkipsCleanly's fixture by exit code alone.
// run() must error here, not silently return zero findings the way it
// correctly does for a real unrelated-history case — silently skipping
// would hide a range that a full clone (ci.yaml's actual fetch-depth: 0)
// would have resolved and possibly flagged.
func TestRun_ShallowCloneErrorsInsteadOfSilentSkip(t *testing.T) {
	src := newRepo(t)
	writeFile(t, src, "f.txt", "1\n")
	commit(t, src, "c1")
	writeFile(t, src, "f.txt", "2\n")
	base := commit(t, src, "c2")
	gitRun(t, src, "checkout", "-q", "-b", "feature")
	writeFile(t, src, "f.txt", "3\n")
	head := commit(t, src, "c3")
	gitRun(t, src, "checkout", "-q", mainBranch)

	// A fresh directory, shallow-fetching each ref independently (depth
	// 1 from its own tip) — mirrors how a real CI checkout could end up
	// shallow despite fetching more than one ref, without needing
	// fetch-depth: 0 to be missing entirely.
	shallowDir := t.TempDir()
	gitRun(t, shallowDir, "init", "-q", "-b", "placeholder")
	gitRun(t, shallowDir, "remote", "add", "origin", "file://"+src)
	gitRun(t, shallowDir, "fetch", "--depth", "1", "origin", mainBranch+":refs/heads/"+mainBranch)
	gitRun(t, shallowDir, "fetch", "--depth", "1", "origin", "feature:refs/heads/feature")

	isShallow := strings.TrimSpace(gitRun(t, shallowDir, "rev-parse", "--is-shallow-repository"))
	if isShallow != "true" {
		t.Fatalf("test fixture isn't actually shallow: rev-parse --is-shallow-repository = %q", isShallow)
	}

	chdir(t, shallowDir)
	if _, err := run(base, head); err == nil {
		t.Fatal("expected an error for a shallow clone's ambiguous merge-base result, got none (silent skip)")
	}
}
