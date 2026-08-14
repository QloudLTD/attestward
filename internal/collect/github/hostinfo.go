package github

import (
	"net/http"
	"sync"
)

// hostVersionTracker records the X-GitHub-Enterprise-Version response
// header a GitHub Enterprise Server (GHES) install sends on every API
// response — github.com never sends this header at all, so its presence
// is itself the authoritative "is this GHES" signal (issue #12's GHES
// epic), independent of whether --github-url was actually set. Captured
// best-effort from the first observed response, the same
// first-observation-wins convention scopeTracker already uses for
// X-OAuth-Scopes — the version doesn't change mid-scan.
type hostVersionTracker struct {
	mu      sync.Mutex
	version string
	seen    bool
}

func (h *hostVersionTracker) observe(resp *http.Response) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen {
		return
	}
	// Latch only on a response that actually carried the header. Latching
	// on the first response regardless meant a headerless one — an
	// LB-generated 502 arriving first, a redirect hop, a reverse proxy
	// stripping unknown X-* headers, which is the default posture in the
	// networks GHES lives in — pinned the version to "" for the whole
	// scan, even though every subsequent response announced it. That is
	// this codebase's named defect class wearing a new costume: a value
	// that silently defaults on a NON-observation and is then read as a
	// confirmed observation.
	version := resp.Header.Get("X-GitHub-Enterprise-Version")
	if version == "" {
		return
	}
	h.seen = true
	h.version = version
}

// Version returns the GHES version observed so far, or "" if either no
// authenticated response has completed yet, or the target is github.com
// (which never sends this header).
func (h *hostVersionTracker) Version() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.version
}
