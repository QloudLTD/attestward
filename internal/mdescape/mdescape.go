// Package mdescape neutralizes markdown/HTML syntax inside API-derived
// text before it is interpolated into Markdown output — text/template has
// no auto-escaping (unlike html/template), so every Markdown renderer in
// this codebase escapes by hand, and they all share this one escaper
// (originally internal/report's, moved here when internal/packdiff needed
// the same guarantees for drift-issue bodies).
package mdescape

import "strings"

// escaper implements Escape. Backslash is escaped
// first so escaping the other characters doesn't get double-escaped by a
// later pass. Covers exactly the two threat classes issue #25's own
// acceptance criteria names: `<script>` (neutralized by escaping < and >,
// so it can never become live HTML if this markdown is later rendered to
// HTML by GitHub or any other renderer) and a markdown link bomb like
// `[click here](javascript:...)` (neutralized by escaping [ and ], which
// breaks link syntax formation). Backtick and pipe are also escaped since
// they'd otherwise break code spans and markdown tables.
//
// Newlines are collapsed to a space (and carriage returns dropped) rather
// than escaped: CommonMark is line-oriented, and inline escapes don't stop
// a line starting with e.g. "# " from being parsed as a fresh ATX heading —
// an escaped-but-still-real newline in attacker-influenceable content (a
// Facts value pulled from scanned repo content, a collector-built Reason)
// would let it forge a fake heading/section or corrupt a markdown table
// row. Flattening to one line is the only escape that actually closes
// this off.
var escaper = strings.NewReplacer(
	`\`, `\\`,
	"`", "\\`",
	`*`, `\*`,
	`_`, `\_`,
	`[`, `\[`,
	`]`, `\]`,
	`<`, `\<`,
	`>`, `\>`,
	`|`, `\|`,
	"\n", " ",
	"\r", "",
)

// Escape neutralizes markdown/HTML syntax in s — see escaper above for
// the exact character set and the newline-flattening rationale.
func Escape(s string) string {
	return escaper.Replace(s)
}
