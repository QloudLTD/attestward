package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/model"
)

// writePack writes a minimal evidence.json at reports/<platform>/<version>/
// under root. statuses is the status string of each result in the pack.
func writePack(t *testing.T, root, platform, version, startedAt string, statuses ...string) {
	t.Helper()
	dir := filepath.Join(root, "reports", platform, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// scope.platform is a fixed literal, not the directory name: the
	// generator reads the platform from the path, and a test that wants an
	// awkward directory name shouldn't have to hand-escape it into JSON.
	var results []string
	for i, s := range statuses {
		results = append(results, `{"check_id":"C0`+string(rune('1'+i%9))+`.x","title":"t","status":"`+s+`","reason":"r","scope":{"platform":"gitlab"}}`)
	}
	pack := `{"schema_version":1,"tool_version":"test","scan_started_at":"` + startedAt +
		`","scan_ended_at":"` + startedAt + `","results":[` + strings.Join(results, ",") + `]}`
	if err := os.WriteFile(filepath.Join(dir, "evidence.json"), []byte(pack), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRunIsIdempotent is the property the publish job depends on: the index
// is derived from the tree, never appended to, so publishing the same tag
// twice must leave exactly one row for it and produce a byte-identical file.
func TestRunIsIdempotent(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "gitlab", "v1.2.1", "2026-08-15T10:00:00Z", "verified-pass", "verified-fail")

	if err := run(root); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal(err)
	}

	// Second publish of the same tag: the job overwrites the same directory,
	// then regenerates. Nothing about the tree changed.
	if err := run(root); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(first, second) {
		t.Errorf("index.html changed on a re-run of the same tree:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if got := rowsFor(second, "v1.2.1"); got != 1 {
		t.Errorf("v1.2.1 has %d rows in the index, want exactly 1 (a duplicated row)", got)
	}
}

// rowsFor counts the version cells for version — one per table row. Counting
// bare occurrences of the version string would double-count, since each row
// also names it inside the report href.
func rowsFor(index []byte, version string) int {
	return bytes.Count(index, []byte("<code>"+version+"</code>"))
}

// TestRunRescanOfSameTagReplacesRatherThanAdds covers the case the re-run
// above cannot: a second scan of the same tag writes a DIFFERENT pack into
// the same directory. The row must be updated, not joined by a second one.
func TestRunRescanOfSameTagReplacesRatherThanAdds(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "gitlab", "v1.2.1", "2026-08-15T10:00:00Z", "verified-pass")
	if err := run(root); err != nil {
		t.Fatal(err)
	}

	writePack(t, root, "gitlab", "v1.2.1", "2026-08-16T11:00:00Z", "verified-pass", "verified-pass")
	if err := run(root); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if n := rowsFor(got, "v1.2.1"); n != 1 {
		t.Errorf("v1.2.1 has %d rows after a re-scan, want exactly 1", n)
	}
	if !bytes.Contains(got, []byte("2026-08-16")) {
		t.Errorf("index did not pick up the newer scan date, got:\n%s", got)
	}
	if bytes.Contains(got, []byte("2026-08-15")) {
		t.Errorf("index still shows the superseded scan date, got:\n%s", got)
	}
}

func TestCollectSortsNewestFirstAcrossPlatforms(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "gitlab", "v1.0.0", "2026-08-10T10:00:00Z", "verified-pass")
	writePack(t, root, "github", "v1.2.1", "2026-08-15T10:00:00Z", "verified-pass")
	writePack(t, root, "gogs", "v1.1.0", "2026-08-12T10:00:00Z", "verified-pass")

	entries, err := collect(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"github", "gogs", "gitlab"}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d", len(entries), len(want))
	}
	for i, w := range want {
		if entries[i].Platform != w {
			t.Errorf("entry %d is %q, want %q (newest-first ordering)", i, entries[i].Platform, w)
		}
	}
}

// Two packs sharing a timestamp must still order deterministically, or the
// idempotency property above holds only by luck of the clock.
func TestCollectTieBreaksDeterministically(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "gogs", "v1.0.0", "2026-08-10T10:00:00Z", "verified-pass")
	writePack(t, root, "github", "v1.0.0", "2026-08-10T10:00:00Z", "verified-pass")

	for i := 0; i < 5; i++ {
		entries, err := collect(root)
		if err != nil {
			t.Fatal(err)
		}
		if entries[0].Platform != "github" || entries[1].Platform != "gogs" {
			t.Fatalf("run %d ordered %q,%q — want github,gogs", i, entries[0].Platform, entries[1].Platform)
		}
	}
}

func TestCollectCountsEveryStatus(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "gitlab", "v1.2.1", "2026-08-15T10:00:00Z",
		"verified-pass", "verified-pass", "verified-fail", "partial", "self-attested", "not-checkable")

	entries, err := collect(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Total != 6 {
		t.Errorf("Total = %d, want 6", e.Total)
	}
	for status, want := range map[string]int{
		"verified-pass": 2, "verified-fail": 1, "partial": 1,
		"self-attested": 1, "not-checkable": 1,
	} {
		if got := e.Counts[model.Status(status)]; got != want {
			t.Errorf("count[%s] = %d, want %d", status, got, want)
		}
	}

	// The rendered table must account for every result, or a reader is
	// silently shown a subset.
	out := string(render(entries))
	for _, s := range reportedStatuses {
		if !strings.Contains(out, label(s)) {
			t.Errorf("rendered index omits the %q column", label(s))
		}
	}
}

// TestCollectSkipsIncompleteDirectories: a directory with no evidence.json
// (a half-copied publish) is skipped, not fatal.
func TestCollectSkipsIncompleteDirectories(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "gitlab", "v1.2.1", "2026-08-15T10:00:00Z", "verified-pass")
	if err := os.MkdirAll(filepath.Join(root, "reports", "github", "v1.2.1"), 0o755); err != nil {
		t.Fatal(err)
	}

	entries, err := collect(root)
	if err != nil {
		t.Fatalf("an evidence-less directory should be skipped, got error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
}

func TestRunOnEmptyTree(t *testing.T) {
	root := t.TempDir()
	if err := run(root); err != nil {
		t.Fatalf("an empty tree should still render a placeholder index: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("No scans published yet")) {
		t.Errorf("empty index missing its placeholder, got:\n%s", got)
	}
}

// Directory names become both table cells and href components. They are
// attacker-controlled only via someone who can already push to the branch,
// but the escaping is what makes that irrelevant.
func TestRenderEscapesPathComponents(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, `ev"il<script>`, "v1.0.0", "2026-08-15T10:00:00Z", "verified-pass")

	entries, err := collect(root)
	if err != nil {
		t.Fatal(err)
	}
	out := string(render(entries))
	if strings.Contains(out, "<script>") {
		t.Errorf("unescaped markup survived into the index:\n%s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Errorf("expected the platform name to be HTML-escaped, got:\n%s", out)
	}
}
