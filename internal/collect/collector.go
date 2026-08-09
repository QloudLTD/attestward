package collect

import (
	"context"

	"gitlab.com/sioakeim/attestward/internal/model"
)

// AccountType is what kind of GitHub account Scope.Org names — an
// Organization or a personal User account. The orchestrator (issue #10,
// extended by issue #102) resolves this once during preflight, via a call
// that works for either kind (GET /users/{account}), and every Scope it
// builds afterward carries the answer — a collector never needs to guess it
// from a failed org-scoped call.
type AccountType string

const (
	// AccountTypeUnknown is the zero value: the orchestrator hasn't
	// resolved an account type (e.g. a test building Scope by hand without
	// going through real preflight). Collectors that branch on AccountType
	// must treat this the same as AccountTypeOrganization — attempt the
	// org-scoped call and let it fail honestly — never as a reason to
	// assume AccountTypeUser and skip the call outright.
	AccountTypeUnknown AccountType = ""
	// AccountTypeOrganization means Scope.Org names a GitHub Organization
	// — the case every org-scoped collector call was originally written
	// for, before issue #102 gave it a named counterpart.
	AccountTypeOrganization AccountType = "organization"
	// AccountTypeUser means Scope.Org actually names a personal GitHub
	// user account. Org-scoped endpoints (GET /orgs/{org}, GET
	// /orgs/{org}/audit-log, etc.) have no equivalent for a personal
	// account and always 404 — a collector that knows AccountTypeUser
	// should skip attempting them and report a specific, honest
	// not-checkable reason instead of a generic API-error message (issue
	// #102).
	AccountTypeUser AccountType = "user"
)

// Scope is what one Collector.Collect call covers: platform-neutral so the
// same interface serves GitHub, Azure DevOps, and GitLab collectors
// (ADR-0005). LookbackReleases/LookbackMonths both being zero means the
// caller (the #10 orchestrator) is responsible for defaulting them (per the
// product brief: last 5 releases or 12 months) before Collect ever sees a
// Scope — collectors should treat both-zero as "use the values given",
// not re-derive defaults themselves.
type Scope struct {
	// Org is the target GitHub account name — despite the field name, it
	// may name either an Organization or a personal User account; see
	// AccountType.
	Org         string
	AccountType AccountType
	Repos       []string
	// Project is the Azure DevOps project name a scan is scoped to. GitHub
	// collectors ignore this field entirely — Org+Repos already fully
	// scopes a GitHub collector, and GitHub has no equivalent concept at
	// this level. Azure DevOps collectors require it: every ADO REST path
	// is org+project scoped, never org-only (issue #34's v0.2 epic).
	Project           string
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
