package github

import "fmt"

// UserAccountNotCheckableReason is the shared not-checkable Reason text
// C01.org-security, C04.org.security-defaults, and C09.audit.org-log-available
// each return when collect.Scope.AccountType is collect.AccountTypeUser: org
// (org string) is a personal GitHub user account, not an organization, so
// the org-scoped endpoint this check depends on has no equivalent for it —
// issue #102. A shared helper keeps the wording (and any future refinement
// of it) identical across the three collectors that need it, rather than
// three independent paraphrases drifting apart over time.
func UserAccountNotCheckableReason(org string) string {
	return fmt.Sprintf("%s is a personal GitHub user account, not an organization — this check depends on an org-scoped API that has no equivalent for a personal account", org)
}
