package collect

import (
	"context"

	"github.com/sioakim/ssdf/internal/model"
)

// Scope is what one Collector.Collect call covers: platform-neutral so the
// same interface serves GitHub, Azure DevOps, and GitLab collectors
// (ADR-0005). LookbackReleases/LookbackMonths both being zero means the
// caller (the #10 orchestrator) is responsible for defaulting them (per the
// product brief: last 5 releases or 12 months) before Collect ever sees a
// Scope — collectors should treat both-zero as "use the values given",
// not re-derive defaults themselves.
type Scope struct {
	Org               string
	Repos             []string
	ReleaseTagPattern string
	LookbackReleases  int
	LookbackMonths    int
}

// Collector is the seam every platform-specific implementation satisfies
// (ADR-0005): platform API access stays behind this interface so onboarding
// Azure DevOps or GitLab later never touches internal/model, internal/mapping,
// or internal/report.
//
// Collect must never let one failure abort the whole scan: a returned error
// is caught by the caller (see Run) and turned into a single not-checkable
// CheckResult with the error recorded in its Reason, so every other
// collector still runs to completion — partial evidence is still evidence.
// Results themselves are pure data; no rendering or mapping logic belongs
// in a Collector or anything it calls.
type Collector interface {
	ID() string
	Collect(ctx context.Context, scope Scope) ([]model.CheckResult, error)
}
