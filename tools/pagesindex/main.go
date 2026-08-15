// Command pagesindex renders index.html for the self-scan report site that
// the `publish` stage of .gitlab-ci.yml keeps on the pages-history branch.
//
// It is a pure function of the directory tree it is pointed at: it walks
// every reports/<platform>/<version>/evidence.json under root, and rewrites
// root/index.html from scratch each time. Nothing is appended and no
// previous index.html is read, so re-running the pipeline for a tag that was
// already published re-derives the same table instead of adding a duplicate
// row — the idempotency the publish job depends on lives here, not in the
// job's shell.
//
// Written in Go rather than as a hack/*.sh sibling so it needs nothing the
// pipeline's golang image doesn't already have (hack/check-examples-drift.sh
// has to apt-get jq for exactly this reason), and so `go test` covers the
// idempotency claim above. Invoked as `go run ./tools/pagesindex <dir>`, the
// same way CI already invokes tools/rubricguard and tools/threatmodelguard.
package main

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gitlab.com/sioakeim/attestward/internal/model"
)

// reportedStatuses is every status the evidence schema defines, in the order
// the table shows them. Listing all five rather than the four "headline"
// ones is deliberate: a row whose columns don't sum to its own check count
// invites the reader to assume a rendering bug, and self-attested checks are
// exactly the ones a compliance reader must not overlook.
var reportedStatuses = []model.Status{
	model.StatusVerifiedPass,
	model.StatusVerifiedFail,
	model.StatusPartial,
	model.StatusSelfAttested,
	model.StatusNotCheckable,
}

// entry is one published scan: one platform at one tag.
type entry struct {
	Platform string
	Version  string
	Started  time.Time
	Counts   map[model.Status]int
	Total    int
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	if err := run(root); err != nil {
		fmt.Fprintf(os.Stderr, "pagesindex: %v\n", err)
		os.Exit(1)
	}
}

func run(root string) error {
	entries, err := collect(root)
	if err != nil {
		return err
	}
	out := filepath.Join(root, "index.html")
	if err := os.WriteFile(out, render(entries), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Printf("wrote %s (%d scan(s))\n", out, len(entries))
	return nil
}

// collect walks root/reports/<platform>/<version>/evidence.json. A directory
// without an evidence.json is skipped rather than failing the run: the
// publish job copies five files per scan and a partially-copied tree should
// not be able to wedge every future publish.
//
// Packs are unmarshaled into model.EvidencePack but deliberately NOT put
// through ValidateAgainstSchema. This tree accumulates packs across tags, so
// it will eventually hold packs written by older builds; the index is a
// directory, not a compliance artifact, and refusing to render the whole
// site because a two-releases-old pack no longer validates would be the
// wrong trade. `attestward verify` in the same job is what gates the pack
// actually being published.
func collect(root string) ([]entry, error) {
	reportsDir := filepath.Join(root, "reports")
	platforms, err := os.ReadDir(reportsDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", reportsDir, err)
	}

	var entries []entry
	for _, p := range platforms {
		if !p.IsDir() {
			continue
		}
		versions, err := os.ReadDir(filepath.Join(reportsDir, p.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filepath.Join(reportsDir, p.Name()), err)
		}
		for _, v := range versions {
			if !v.IsDir() {
				continue
			}
			packPath := filepath.Join(reportsDir, p.Name(), v.Name(), "evidence.json")
			data, err := os.ReadFile(packPath)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", packPath, err)
			}
			var pack model.EvidencePack
			if err := json.Unmarshal(data, &pack); err != nil {
				return nil, fmt.Errorf("parse %s: %w", packPath, err)
			}
			e := entry{
				Platform: p.Name(),
				Version:  v.Name(),
				Started:  pack.ScanStartedAt,
				Counts:   map[model.Status]int{},
				Total:    len(pack.Results),
			}
			for _, r := range pack.Results {
				e.Counts[r.Status]++
			}
			entries = append(entries, e)
		}
	}

	// Newest first. Platform then version break ties so the output is a
	// function of the tree alone — os.ReadDir is already sorted, but two
	// packs can share a scan timestamp and an unstable order there would
	// make the "running it twice produces the same file" property depend on
	// sub-second timing.
	sort.SliceStable(entries, func(i, j int) bool {
		if !entries[i].Started.Equal(entries[j].Started) {
			return entries[i].Started.After(entries[j].Started)
		}
		if entries[i].Platform != entries[j].Platform {
			return entries[i].Platform < entries[j].Platform
		}
		return entries[i].Version < entries[j].Version
	})
	return entries, nil
}

func render(entries []entry) []byte {
	var b strings.Builder
	b.WriteString(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>attestward self-scan reports</title>
<style>
:root { color-scheme: light dark; }
body { font: 16px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
       margin: 0 auto; max-width: 60rem; padding: 2rem 1rem; }
h1 { font-size: 1.5rem; margin-bottom: .25rem; }
p.lede { margin-top: 0; opacity: .8; }
.wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: .5rem .75rem; border-bottom: 1px solid rgba(128,128,128,.35); }
th { font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; opacity: .7; }
td.n { text-align: right; }
.pass { color: #197a3d; } .fail { color: #b3261e; }
@media (prefers-color-scheme: dark) { .pass { color: #6ee7a0; } .fail { color: #ff8a80; } }
footer { margin-top: 2rem; font-size: .85rem; opacity: .7; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body>
<h1>attestward self-scan reports</h1>
<p class="lede">attestward scanning its own repository on every published tag, on each
forge that hosts it. Generated by the <code>publish</code> stage of
<code>.gitlab-ci.yml</code>; each row links to the full rendered report.</p>
`)

	if len(entries) == 0 {
		b.WriteString("<p>No scans published yet.</p>\n")
	} else {
		b.WriteString(`<div class="wrap">
<table>
<thead><tr><th>Platform</th><th>Version</th><th>Scanned</th>`)
		for _, s := range reportedStatuses {
			b.WriteString("<th>" + html.EscapeString(label(s)) + "</th>")
		}
		b.WriteString("<th>Total</th><th>Report</th></tr></thead>\n<tbody>\n")

		for _, e := range entries {
			b.WriteString("<tr>")
			b.WriteString("<td>" + html.EscapeString(e.Platform) + "</td>")
			b.WriteString("<td><code>" + html.EscapeString(e.Version) + "</code></td>")
			b.WriteString("<td>" + html.EscapeString(e.Started.UTC().Format("2006-01-02 15:04 MST")) + "</td>")
			for _, s := range reportedStatuses {
				b.WriteString(`<td class="n` + cls(s) + `">` + fmt.Sprint(e.Counts[s]) + "</td>")
			}
			b.WriteString(`<td class="n">` + fmt.Sprint(e.Total) + "</td>")
			// Path components come from directory names this job created, but
			// they are escaped anyway — an index that is safe only because of
			// what a sibling job happens to write is one refactor from not
			// being safe.
			href := "reports/" + e.Platform + "/" + e.Version + "/report.html"
			b.WriteString(`<td><a href="` + html.EscapeString(href) + `">report</a></td>`)
			b.WriteString("</tr>\n")
		}
		b.WriteString("</tbody>\n</table>\n</div>\n")
	}

	// No "generated at" timestamp: it would make every run produce a
	// different file, which is exactly the idempotency this command exists
	// to provide. The scan timestamps in the table already carry the
	// freshness information a reader needs.
	b.WriteString(`<footer>Each row also has <code>report.md</code>, <code>poam.md</code>,
<code>evidence.json</code> and <code>evidence.json.sha256</code> alongside its
<code>report.html</code>. Verify a pack with
<code>attestward verify &lt;dir&gt;</code>.</footer>
</body>
</html>
`)
	return []byte(b.String())
}

func label(s model.Status) string {
	return strings.ReplaceAll(string(s), "-", " ")
}

func cls(s model.Status) string {
	switch s {
	case model.StatusVerifiedPass:
		return " pass"
	case model.StatusVerifiedFail:
		return " fail"
	default:
		return ""
	}
}
