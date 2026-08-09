package packdiff

import (
	"fmt"
	"strings"

	"gitlab.com/sioakeim/attestward/internal/mdescape"
)

// RenderText renders a Delta as the human-readable default output of
// `attestward diff` — a summary line plus one line per change, most
// urgent class first.
func RenderText(d Delta) string {
	var b strings.Builder
	if d.Empty() {
		b.WriteString("No semantic differences: every check has the same status in both packs.\n")
		writeContext(&b, d.Context, "", func(x string) string { return x })
		return b.String()
	}

	fmt.Fprintf(&b, "%d regression(s), %d improvement(s), %d coverage change(s), %d other change(s), %d added, %d removed\n",
		len(d.Regressions), len(d.Improvements), len(d.CoverageLoss)+len(d.CoverageGain), len(d.Other), len(d.Added), len(d.Removed))

	section := func(title string, changes []Change) {
		if len(changes) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", title)
		for _, c := range changes {
			fmt.Fprintf(&b, "  %s: %s -> %s — %s\n", c.Ref, c.From, c.To, c.Reason)
		}
	}
	section("REGRESSIONS", d.Regressions)
	section("Improvements", d.Improvements)
	section("Coverage lost (verification capability, not posture)", d.CoverageLoss)
	section("Coverage gained", d.CoverageGain)
	section("Other status changes", d.Other)

	entries := func(title string, es []Entry) {
		if len(es) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", title)
		for _, e := range es {
			fmt.Fprintf(&b, "  %s: %s — %s\n", e.Ref, e.Status, e.Reason)
		}
	}
	entries("Only in current pack", d.Added)
	entries("Only in baseline pack", d.Removed)

	writeContext(&b, d.Context, "", func(x string) string { return x })
	return b.String()
}

// RenderMarkdown renders a Delta as a Markdown fragment suitable for a
// drift-issue body (issue #36's scheduled mode) — same content as
// RenderText, table-formed.
func RenderMarkdown(d Delta) string {
	var b strings.Builder
	if d.Empty() {
		b.WriteString("No semantic differences: every check has the same status in both packs.\n")
		writeContext(&b, d.Context, "> ", mdescape.Escape)
		return b.String()
	}

	fmt.Fprintf(&b, "**%d regression(s)**, %d improvement(s), %d coverage change(s), %d other change(s), %d added, %d removed\n",
		len(d.Regressions), len(d.Improvements), len(d.CoverageLoss)+len(d.CoverageGain), len(d.Other), len(d.Added), len(d.Removed))

	// Every cell goes through mdescape.Escape — not just reasons. Check
	// IDs, org/repo names, and even statuses come from the input packs,
	// and a pack is only trusted as far as its (optional) sidecar: this
	// output's destination is a posted drift-issue body (#36), where a
	// crafted cell could otherwise smuggle live markdown.
	section := func(title string, changes []Change) {
		if len(changes) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n### %s\n\n| Check | Scope | Was | Now | Reason |\n|---|---|---|---|---|\n", title)
		for _, c := range changes {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				mdescape.Escape(c.CheckID), mdescape.Escape(mdScope(c.Ref)),
				mdescape.Escape(string(c.From)), mdescape.Escape(string(c.To)), mdescape.Escape(c.Reason))
		}
	}
	section("Regressions", d.Regressions)
	section("Improvements", d.Improvements)
	section("Coverage lost (verification capability, not posture)", d.CoverageLoss)
	section("Coverage gained", d.CoverageGain)
	section("Other status changes", d.Other)

	entries := func(title string, es []Entry) {
		if len(es) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n### %s\n\n| Check | Scope | Status | Reason |\n|---|---|---|---|\n", title)
		for _, e := range es {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n",
				mdescape.Escape(e.CheckID), mdescape.Escape(mdScope(e.Ref)),
				mdescape.Escape(string(e.Status)), mdescape.Escape(e.Reason))
		}
	}
	entries("Only in current pack", d.Added)
	entries("Only in baseline pack", d.Removed)

	writeContext(&b, d.Context, "> ", mdescape.Escape)
	return b.String()
}

// writeContext appends the checker-change caveats, if any apply. prefix
// is prepended to each line ("> " turns them into a Markdown blockquote);
// esc escapes interpolated pack data for the target format (identity for
// plain text, mdescape.Escape for Markdown — tool versions come from the
// input packs like every other rendered string).
func writeContext(b *strings.Builder, ctx Context, prefix string, esc func(string) string) {
	var notes []string
	if ctx.ToolVersionChanged {
		notes = append(notes, fmt.Sprintf("tool version changed (%s -> %s)", esc(ctx.BaselineToolVersion), esc(ctx.CurrentToolVersion)))
	}
	if ctx.MappingVersionsChanged {
		notes = append(notes, "mapping versions changed")
	}
	if ctx.ReposChanged {
		notes = append(notes, "the set of scanned repos changed")
	}
	if len(notes) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%sContext: %s. Status changes above may reflect checker changes, not posture changes.\n", prefix, strings.Join(notes, "; "))
}

func mdScope(r Ref) string {
	if r.Repo == "" {
		return r.Org + " (org)"
	}
	return r.Org + "/" + r.Repo
}
