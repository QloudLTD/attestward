// rubricguard is a CI guard for issue #209. Usage:
//
//	go run ./tools/rubricguard <base-ref> <head-ref>
//
// Compares every internal/collect/**/*.go file (excluding _test.go) that
// differs between base-ref and head-ref. For each package (directory)
// where a status-assignment change lands without a matching checkRubrics
// change in the same diff, prints the offending file(s)/line(s) and
// exits 1. Exits 0 (silently) when there's nothing to flag.
//
// A green run means "no function's multiset of referenced status
// constants changed outside checkRubrics" (issue #262 — occurrence-count-
// sensitive but position-insensitive per function, see scan.go's
// funcStatusRefs) — it does NOT mean "status behavior is unchanged". Two
// known false-negative classes exist and are permanent, not bugs (round 2
// review, F1/F2 — see scan.go's aggregate doc comment for the second one
// in detail):
//
//   - Branch-swap invisibility, now covering BOTH spellings (issue #262's
//     re-review, confirmed by injecting into real production code —
//     github/secretshygiene/checks.go:130-133): exchanging which status a
//     check produces between two branches leaves a function's multiset
//     unchanged whichever way it's spelled. Flipping `if enabled {` to
//     `if !enabled {` around an unchanged pair of `model.Status*`
//     branches was already invisible before #262 (no status-constant
//     line changes at all — no line/hunk-diff tool, old or new, can
//     distinguish "this branch's meaning flipped" from "this branch is
//     untouched" without real dataflow analysis). What #262 gave up:
//     exchanging which constant sits in which branch (condition
//     untouched, e.g. swapping which of two existing StatusVerifiedPass/
//     StatusVerifiedFail lines returns which) DID change a status-
//     constant line, and the old hunk-overlap algorithm caught that
//     spelling — but it's the identical set of names occurring the
//     identical number of times, so the multiset comparison can't see it
//     either. Accepted deliberately: the old algorithm only ever covered
//     one of these two spellings by accident of which text happened to
//     move, and giving up that accidental half is the direct cost of
//     eliminating #261's own false positive, which fires on the exact
//     Facts-population shape this repo is actively producing (see the
//     #250/#252/#254/#256/#261 sequence) — the corpus replay backs this
//     as a net-positive trade (CHANGELOG's #262 entry has the numbers),
//     not a free one.
//   - A package-wide OR on whether checkRubrics was touched (see
//     aggregate in scan.go). A genuine new status case in one check, with
//     no rubric update, next to an unrelated one-character rubric-string
//     edit for a *different* check in the same package's checkRubrics
//     map, reads as "checkRubrics was touched" for the whole package —
//     exactly the partial-#202 shape this guard is blindest to.
//
// Deliberately coarse otherwise too — see scan.go's package doc comment
// for the false-positive tradeoffs this accepts and why. It exists so a
// reviewer is *pointed at* the question "does the rubric still describe
// what this code does", not so the answer is computed for them; a
// flagged PR may turn out to need no rubric change at all (e.g. a
// function renamed with its status logic otherwise untouched), and
// that's an acceptable false positive per issue #209's own bar ("a lint
// rule with false positives a reviewer can wave off is fine") — silence
// is what isn't. #261's own shape (a status reference purely relocated
// within its function) used to be exactly that kind of waveable false
// positive; issue #262 removed it as a false positive entirely.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: rubricguard <base-ref> <head-ref>")
		os.Exit(2)
	}
	findings, err := run(os.Args[1], os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "rubricguard: "+err.Error())
		os.Exit(2)
	}
	if len(findings) > 0 {
		reportFindings(findings)
		os.Exit(1)
	}
}

// run does the actual scan and returns what it found — it never calls
// os.Exit itself, so it's directly testable (see main_test.go's
// real-git-repo integration tests) without needing to exec a subprocess.
func run(base, head string) ([]*packageFinding, error) {
	// F4 nit (round 3 review): a shallow clone also makes `git
	// merge-base` exit 1 — truncated history looks exactly like "no
	// common ancestor" to that command, and the two must not be treated
	// the same way below: a shallow clone's exit 1 skipping silently
	// would hide a real, resolvable range that a full clone would have
	// found. Checked explicitly up front rather than left as an implicit
	// dependency on ci.yaml's fetch-depth: 0 elsewhere in this repo.
	shallow, err := isShallowRepo()
	if err != nil {
		return nil, fmt.Errorf("checking repository depth: %w", err)
	}

	// The merge-base, not base itself: base may have moved forward on
	// its own (main advances independently of an open PR's branch,
	// routinely in this repo's history) since the PR branched. Diffing
	// straight from base would pull in every change main picked up in
	// the meantime — a different PR's rubric edit or status change,
	// wrongly attributed to this one. The merge-base is what GitHub's
	// own PR "Files changed" view diffs against too.
	mergeBase, err := gitOutput("merge-base", base, head)
	if err != nil {
		if noMergeBase(err) && !shallow {
			// git merge-base's own convention: exit 1 with no stderr
			// means "no common ancestor" (base and head share no
			// history at all — e.g. an orphan branch, or refs from
			// unrelated repos), not a usage error. There's no sane
			// range to diff, the same "nothing to check" conclusion the
			// range-determination step in ci.yaml already reaches for
			// other unresolvable cases (a brand-new branch's push
			// event, a non-pull_request/push trigger) — this should
			// skip the same way, not redden the job over something
			// that isn't a code problem. A genuinely broken ref (a typo
			// in how the workflow computed a SHA) exits 128 with a
			// clear "fatal: not a valid object name" instead, and that
			// still surfaces as a real error below.
			fmt.Fprintf(os.Stderr, "rubricguard: no common ancestor between %s and %s — nothing to diff, skipping\n", base, head)
			return nil, nil
		}
		if noMergeBase(err) && shallow {
			return nil, fmt.Errorf("merge-base reported no common ancestor between %s and %s, but this is a shallow clone — cannot tell a genuine unrelated-history case apart from history truncated by the clone depth; fetch full history (fetch-depth: 0) and retry", base, head)
		}
		return nil, fmt.Errorf("merge-base %s %s: %w", base, head, err)
	}
	mergeBase = strings.TrimSpace(mergeBase)

	changed, err := changedCollectorFiles(mergeBase, head)
	if err != nil {
		return nil, err
	}
	if len(changed) == 0 {
		return nil, nil
	}

	fset := token.NewFileSet()
	byDir := map[string][]fileFinding{}
	dirOrder := []string{}

	for _, path := range changed {
		hunks, err := diffHunks(mergeBase, head, path)
		if err != nil {
			return nil, fmt.Errorf("diff %s: %w", path, err)
		}
		newSrc, err := showFile(head, path)
		if err != nil {
			return nil, fmt.Errorf("read %s at %s: %w", path, head, err)
		}
		oldSrc, err := showFileOrNil(mergeBase, path)
		if err != nil {
			return nil, fmt.Errorf("read %s at %s: %w", path, mergeBase, err)
		}

		ff, err := analyzeFile(fset, path, oldSrc, newSrc, hunks)
		if err != nil {
			// A file that fails to parse (e.g. mid-refactor syntax error
			// on a branch, or a non-Go file matched by accident) isn't
			// this guard's problem to adjudicate — go build/go vet/lint
			// already gate that. Skip it rather than failing the whole
			// check on an unrelated build error.
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
			return nil, fmt.Errorf("scan package %s: %w", dir, err)
		}
		if pf := aggregate(dir, byDir[dir], hasRubric); pf != nil {
			findings = append(findings, pf)
		}
	}

	return findings, nil
}

// changedCollectorFiles lists non-test .go files under internal/collect/
// that differ between base and head. Test files are excluded entirely —
// they're full of legitimate model.Status references as expected-value
// assertions, which have nothing to do with the collector's own
// production status-assignment logic and would otherwise be this guard's
// single largest false-positive source.
//
// -z, same reason as packageHasRubric's identical fix (F6, round 3
// review): `git diff --name-only` applies the identical core.quotePath
// C-quoting to a non-ASCII path (confirmed directly, same shape as
// ls-tree's) — without -z, a changed file with such a name would fail
// the .go/_test.go suffix check below (its quoted form no longer ends in
// literal ".go") and silently drop out of `changed` entirely, never
// analyzed at all.
func changedCollectorFiles(base, head string) ([]string, error) {
	out, err := gitOutput("diff", "-z", "--name-only", "--diff-filter=ACMR", base+".."+head, "--", "internal/collect")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(strings.TrimRight(out, "\x00"), "\x00") {
		if line == "" {
			continue
		}
		if !strings.HasSuffix(line, ".go") || strings.HasSuffix(line, "_test.go") {
			continue
		}
		files = append(files, line)
	}
	sort.Strings(files)
	return files, nil
}

func diffHunks(base, head, path string) ([]hunk, error) {
	out, err := gitOutput("diff", "-U0", base+".."+head, "--", path)
	if err != nil {
		return nil, err
	}
	return parseHunks(out), nil
}

func showFile(ref, path string) ([]byte, error) {
	out, err := gitOutputBytes("show", ref+":"+path)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// showFileOrNil is showFile but returns (nil, nil) instead of an error
// when the file doesn't exist at ref — the normal case for a file added
// in this diff, not a failure.
func showFileOrNil(ref, path string) ([]byte, error) {
	out, err := exec.Command("git", "show", ref+":"+path).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr := string(exitErr.Stderr)
			if strings.Contains(stderr, "does not exist") || strings.Contains(stderr, "exists on disk, but not in") {
				return nil, nil
			}
		}
		return nil, err
	}
	return out, nil
}

// packageHasRubric reports whether any non-test .go file in dir at head
// declares checkRubrics. Reads via git (ls-tree to list, show to read),
// not the checked-out working tree — on a pull_request event, GitHub's
// default checkout gives the *merge commit* (base merged with head), not
// literally head, so a working-tree read here could reflect a state that
// is neither (round 2 review's F6: harmless for every other read in this
// tool, which already goes through `git show <ref>:<path>` for actual
// file *content*, but this function used to be the one exception).
//
// -z, not the newline-separated default: round 3 review found that
// ls-tree applies core.quotePath, C-quoting any path with a non-ASCII or
// otherwise "unusual" byte into an escaped string like
// "pkg/h\303\251llo.go" — confirmed directly. Traced what that actually
// does here rather than assuming: the quoted string's own trailing `"`
// means it no longer ends in literal ".go", so the suffix filter below
// (there for an unrelated reason) silently excludes it — a checkRubrics
// that exists goes undetected, not a `git show` failure or a red PR.
// Confirmed by reverting to the non -z form: has=false, err=nil, no
// error at all. -z outputs raw, NUL-separated paths with no quoting,
// closing the gap either way — see TestPackageHasRubric_NonASCIIFilename
// and changedCollectorFiles' identical fix/comment above for the sibling
// case this same root cause produces.
func packageHasRubric(fset *token.FileSet, head, dir string) (bool, error) {
	out, err := gitOutput("ls-tree", "-z", "--name-only", head, "--", dir+"/")
	if err != nil {
		return false, err
	}
	for _, path := range strings.Split(strings.TrimRight(out, "\x00"), "\x00") {
		if path == "" || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := showFile(head, path)
		if err != nil {
			return false, err
		}
		has, err := declaresRubric(fset, src)
		if err != nil {
			// Same reasoning as the skip in run(): a file this guard
			// can't parse isn't grounds to fail the whole check.
			continue
		}
		if has {
			return true, nil
		}
	}
	return false, nil
}

func reportFindings(findings []*packageFinding) {
	fmt.Fprintln(os.Stderr, "rubricguard: possible rubric drift (issue #209)")
	fmt.Fprintln(os.Stderr, "")
	for _, pf := range findings {
		fmt.Fprintf(os.Stderr, "  package %s:\n", pf.Dir)
		for _, f := range pf.Files {
			lines := make([]string, len(f.StatusLines))
			for i, l := range f.StatusLines {
				lines[i] = fmt.Sprintf("%d", l)
			}
			fmt.Fprintf(os.Stderr, "    %s: changed model.Status reference(s) at line(s) %s\n",
				f.Path, strings.Join(lines, ", "))
		}
		fmt.Fprintf(os.Stderr, "    checkRubrics in this package was not touched in the same diff.\n\n")
	}
	fmt.Fprintln(os.Stderr, "This may be a genuine rubric gap (a check can now produce a status its "+
		"rubric doesn't describe — see issue #209's own #202 example) or a false positive (e.g. a "+
		"function renamed with its status logic otherwise untouched). Check docs/checks-reference.md's "+
		"entry for the check(s) involved against what the changed code now does; update checkRubrics if "+
		"it no longer matches.")
}

func gitOutput(args ...string) (string, error) {
	b, err := gitOutputBytes(args...)
	return string(b), err
}

func gitOutputBytes(args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// noMergeBase reports whether err came from `git merge-base` exiting 1 —
// git's own convention for "ran fine, found no common ancestor", distinct
// from a genuine usage/fatal error (an invalid ref, a corrupt repo, ...),
// which exits 128 instead. Confirmed directly: git merge-base between two
// orphan branches with no shared history exits 1 with empty stderr; git
// merge-base against a nonexistent ref exits 128 with a "fatal: Not a
// valid object name" message.
func noMergeBase(err error) bool {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return false
	}
	return exitErr.ExitCode() == 1
}

// isShallowRepo reports whether the current git checkout has truncated
// history (a shallow clone) — see run()'s own comment for why this
// matters to the no-common-ancestor skip.
func isShallowRepo() (bool, error) {
	out, err := gitOutput("rev-parse", "--is-shallow-repository")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == "true", nil
}
