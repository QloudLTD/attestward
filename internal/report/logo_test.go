package report

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	logoPathRE    = regexp.MustCompile(`<path d="([^"]+)"`)
	logoViewBoxRE = regexp.MustCompile(`viewBox="([^"]+)"`)
)

// TestInlineLogoMatchesAsset guards the hand-inlined logo in
// report.html.tmpl against drifting from the canonical asset. The inline
// copy is maintained manually (see the template's own comment), and its
// very first derivation silently dropped one of the asset's two <path>
// elements — caught only in review. This makes that class of mistake a
// test failure instead.
func TestInlineLogoMatchesAsset(t *testing.T) {
	tmpl, err := templatesFS.ReadFile("templates/report.html.tmpl")
	if err != nil {
		t.Fatalf("read embedded template: %v", err)
	}
	asset, err := os.ReadFile(filepath.Join("..", "..", "docs", "assets", "logo.svg"))
	if err != nil {
		t.Fatalf("read logo asset: %v", err)
	}

	got, want := svgPathData(tmpl), svgPathData(asset)
	if len(got) != len(want) {
		t.Fatalf("inline logo has %d <path> elements, docs/assets/logo.svg has %d — re-derive the inline copy from the asset", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("inline logo path %d differs from docs/assets/logo.svg (whitespace-normalized) — re-derive the inline copy from the asset", i)
		}
	}

	gotVB := logoViewBoxRE.FindSubmatch(tmpl)
	wantVB := logoViewBoxRE.FindSubmatch(asset)
	if gotVB == nil || wantVB == nil || string(gotVB[1]) != string(wantVB[1]) {
		t.Errorf("inline logo viewBox %q differs from asset viewBox %q", gotVB, wantVB)
	}
}

// svgPathData extracts every <path d="..."> value with runs of whitespace
// collapsed, so the one-line inline copy compares equal to the wrapped
// asset file.
func svgPathData(b []byte) []string {
	var ds []string
	for _, m := range logoPathRE.FindAllSubmatch(b, -1) {
		ds = append(ds, strings.Join(strings.Fields(string(m[1])), " "))
	}
	return ds
}
