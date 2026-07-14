package report

import "strings"

// escapeMD neutralizes markdown/HTML syntax inside API-derived text before
// it's interpolated into report.md — text/template has no auto-escaping
// (unlike html/template, used for report.html), so this package must do
// it by hand. Backslash is escaped first so escaping the other characters
// doesn't get double-escaped by a later pass. Covers exactly the two
// threat classes issue #25's own acceptance criteria names: `<script>`
// (neutralized by escaping < and >, so it can never become live HTML if
// this markdown is later rendered to HTML by GitHub or any other
// renderer) and a markdown link bomb like `[click here](javascript:...)`
// (neutralized by escaping [ and ], which breaks link syntax formation).
// Backtick and pipe are also escaped since they'd otherwise break code
// spans and this report's own Facts tables.
//
// Newlines are collapsed to a space (and carriage returns dropped) rather
// than escaped: CommonMark is line-oriented, and inline escapes don't stop
// a line starting with e.g. "# " from being parsed as a fresh ATX heading —
// an escaped-but-still-real newline in attacker-influenceable content (a
// Facts value pulled from scanned repo content, a collector-built Reason)
// would let it forge a fake heading/section or corrupt a markdown table
// row. Flattening to one line is the only escape that actually closes
// this off.
var mdEscaper = strings.NewReplacer(
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

func escapeMD(s string) string {
	return mdEscaper.Replace(s)
}
