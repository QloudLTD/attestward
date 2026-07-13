package github

import (
	"net/http"
	"strings"
	"sync"
)

// knownReadOnlyScopes are classic-PAT OAuth scopes that are read-only on
// their face; anything else (or an unrecognized scope) is treated as
// possibly-write for the purposes of HasWriteScope's least-privilege
// warning — a false positive (warning on a scope that's actually read-only)
// is far cheaper than a false negative (staying silent on a write scope).
// Notably absent on purpose: "public_repo" (grants write despite the name),
// "repo"/"repo:status"/"repo_deployment"/"workflow" (all write-capable), and
// "security_events" (read+write on code scanning alerts).
var knownReadOnlyScopes = map[string]bool{
	"read:org":        true,
	"read:user":       true,
	"read:project":    true,
	"read:packages":   true,
	"read:discussion": true,
	"read:audit_log":  true,
	"read:enterprise": true,
	"user:email":      true,
}

// scopeTracker records the OAuth scopes GitHub reports for the token in
// use, captured best-effort from the X-OAuth-Scopes response header classic
// personal access tokens (and OAuth apps) receive on every authenticated
// response. Fine-grained PATs do not send this header — GitHub has no
// equivalent response-header introspection for them — so Scopes() returns
// empty for a fine-grained token and callers must not treat that as "no
// scopes granted"; it means "not introspectable this way."
type scopeTracker struct {
	mu     sync.Mutex
	scopes []string
	seen   bool
}

func (s *scopeTracker) observe(resp *http.Response) {
	header := resp.Header.Get("X-OAuth-Scopes")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen {
		return // first observation wins; scopes don't change mid-run
	}
	s.seen = true
	if header == "" {
		return
	}
	for _, raw := range strings.Split(header, ",") {
		if scope := strings.TrimSpace(raw); scope != "" {
			s.scopes = append(s.scopes, scope)
		}
	}
}

// Scopes returns the OAuth scopes observed on the token in use, or nil if
// none have been observed yet (no authenticated request has completed) or
// the token is a fine-grained PAT (no X-OAuth-Scopes header to read).
func (s *scopeTracker) Scopes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.scopes...)
}

// HasWriteScope reports whether any observed scope is not a recognized
// read-only scope — a best-effort least-privilege signal for the CLI to
// warn on (docs/architecture.md, README token-permissions guidance), never
// a hard block. Returns false when no scopes have been observed (including
// the fine-grained-PAT case) since there is nothing to warn about yet.
func (s *scopeTracker) HasWriteScope() bool {
	for _, scope := range s.Scopes() {
		if !knownReadOnlyScopes[scope] {
			return true
		}
	}
	return false
}
