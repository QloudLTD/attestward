// This file extends threatmodelguard for issue #274 (option 2 of that
// issue's four): docs/threat-model.md's "ten ADO collector packages"
// list is a hand-maintained enumeration of code facts, the same shape
// scan.go's runner-state guard closes for issue #260. It enumerates every
// directory directly under internal/collect/azuredevops exposing a
// Collect(ctx context.Context, ...) method — the real collect.Collector
// shape (internal/collect/collector.go) — and flags any not named in the
// doc's list. Membership is determined by that method's presence, not by
// directory name: the two shared-helper packages this repo has today,
// adofixture and pipelinehistory, have no Collect method and stay
// excluded on that basis rather than by a hard-coded exception list.
//
// Scoped narrower than a naive "guard the collector list" reading: only
// the ADO side names its collectors by package in the doc at all.
// GitHub's collectors are covered by the endpoint table instead — #274's
// harder option 1, left for its own cost/benefit call — so there's no
// GitHub-side list for this guard to check.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// adoCollectorListRe matches the brace-expansion package list in
// docs/threat-model.md's "ten ADO collector packages" sentence, e.g.
// "internal/collect/azuredevops/{orgsecurity,\nrepoprotection, ...}/".
// Anchoring on this exact path prefix — not a bare `{...}` — is what
// keeps this guard from being satisfiable by a package name mentioned
// anywhere else in the document (the substring-matching weakness #286
// found in a different guard): only this one construct counts as "the
// list that makes the claim".
var adoCollectorListRe = regexp.MustCompile(`internal/collect/azuredevops/\{([^}]*)\}/`)

// runADOCollectors returns which packages directly under collectDir with
// a Collect(ctx context.Context, ...) method aren't named in
// threatModelPath's "ten ADO collector packages" list.
func runADOCollectors(collectDir, threatModelPath string) ([]string, error) {
	packages, err := adoCollectorPackages(collectDir)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", collectDir, err)
	}
	doc, err := os.ReadFile(threatModelPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", threatModelPath, err)
	}
	listed, err := adoCollectorListFromDoc(doc)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", threatModelPath, err)
	}
	return missingADOCollectors(packages, listed), nil
}

// adoCollectorPackages returns the sorted set of directory names directly
// under dir whose non-test .go files declare a Collect(ctx
// context.Context, ...) method on some receiver.
func adoCollectorPackages(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		has, err := hasCollectMethod(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("package %s: %w", e.Name(), err)
		}
		if has {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// hasCollectMethod reports whether any non-test .go file directly in
// pkgDir declares a method named Collect whose first parameter's type is
// context.Context — the part of collect.Collector's own
// Collect(ctx context.Context, scope Scope) ([]model.CheckResult, error)
// signature that actually distinguishes a collector from a shared-helper
// package, without this standalone tool importing internal/collect.
func hasCollectMethod(pkgDir string) (bool, error) {
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return false, err
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, name)
		src, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return false, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv != nil && fn.Name.Name == "Collect" && firstParamIsContextContext(fn.Type) {
				return true, nil
			}
		}
	}
	return false, nil
}

// firstParamIsContextContext reports whether ft's first parameter's type
// is the qualified identifier context.Context — matched by type, not by
// the parameter's own name, so it doesn't depend on every collector
// spelling it "ctx".
func firstParamIsContextContext(ft *ast.FuncType) bool {
	if ft.Params == nil || len(ft.Params.List) == 0 {
		return false
	}
	sel, ok := ft.Params.List[0].Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	return ok && pkgIdent.Name == "context" && sel.Sel.Name == "Context"
}

// adoCollectorListFromDoc extracts the package names named in doc's "ten
// ADO collector packages" brace-expansion list. Errors if the list can't
// be found — a restructured threat model needs a human to re-anchor the
// guard, not a silent pass.
func adoCollectorListFromDoc(doc []byte) (map[string]bool, error) {
	m := adoCollectorListRe.FindSubmatch(doc)
	if m == nil {
		return nil, fmt.Errorf("no %q brace-list found in the \"ten ADO collector packages\" sentence",
			"internal/collect/azuredevops/{...}/")
	}
	listed := map[string]bool{}
	for _, part := range strings.Split(string(m[1]), ",") {
		if name := strings.TrimSpace(part); name != "" {
			listed[name] = true
		}
	}
	return listed, nil
}

// missingADOCollectors returns which of packages (the real, code-derived
// set) aren't in listed (the doc's own claimed set).
func missingADOCollectors(packages []string, listed map[string]bool) []string {
	var missing []string
	for _, p := range packages {
		if !listed[p] {
			missing = append(missing, p)
		}
	}
	return missing
}
