package github

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-github/v75/github"
	"github.com/shurcooL/githubv4"

	"github.com/sioakim/attestward/internal/collect"
	"github.com/sioakim/attestward/internal/collect/github/ghfixture"
	"github.com/sioakim/attestward/internal/model"
)

// demoCollector is a minimal collect.Collector implementation used only by
// this test, to prove the full stack fits together end to end: the
// Collector interface, Client (auth + provenance + rate-limit transport),
// ForEachRepo's per-repo pool, and a fixture-backed http.RoundTripper — the
// exact combination issue #9's acceptance criteria asks for ("a demo no-op
// collector runs through the pool against fixtures and produces
// CheckResults with complete provenance"). It is not a real product
// collector; the real ones start with issue #11.
type demoCollector struct {
	client *Client
}

func (d *demoCollector) ID() string { return "DEMO.noop" }

func (d *demoCollector) Collect(ctx context.Context, scope collect.Scope) ([]model.CheckResult, error) {
	repoResults := ForEachRepo(ctx, scope.Repos, 2, func(ctx context.Context, repo string) (model.CheckResult, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+scope.Org+"/"+repo, nil)
		if err != nil {
			return model.CheckResult{}, err
		}
		resp, err := d.client.REST.Client().Do(req)
		if err != nil {
			return model.CheckResult{}, err
		}
		defer func() { _ = resp.Body.Close() }()

		// Demonstrates the pattern real collectors (issue #11+) follow: a
		// plan-gated response is an honest "unknown", not a failure — never
		// verified-fail — per this issue's acceptance criteria.
		if IsPlanGated(resp.StatusCode) {
			return model.CheckResult{
				CheckID: d.ID(),
				Title:   "Demo no-op check",
				Status:  model.StatusNotCheckable,
				Reason:  "feature not available on this org's plan",
				Scope:   model.ScopeRef{Org: scope.Org, Repo: repo},
			}, nil
		}

		return model.CheckResult{
			CheckID: d.ID(),
			Title:   "Demo no-op check",
			Status:  model.StatusVerifiedPass,
			Reason:  "demo collector always passes",
			Scope:   model.ScopeRef{Org: scope.Org, Repo: repo},
		}, nil
	})

	results := make([]model.CheckResult, 0, len(repoResults))
	for _, r := range repoResults {
		if r.Err != nil {
			return nil, r.Err
		}
		results = append(results, r.Value)
	}
	return results, nil
}

func TestDemoCollector_EndToEndThroughPoolAndFixtures(t *testing.T) {
	fx := ghfixture.New().
		Set("GET", "/repos/attestor-demo/good-repo", ghfixture.Response{Status: 200, Body: map[string]any{"name": "good-repo"}}).
		Set("GET", "/repos/attestor-demo/other-repo", ghfixture.Response{Status: 200, Body: map[string]any{"name": "other-repo"}})

	client := newTestClient(t, "ghp_demo-token", fx)
	d := &demoCollector{client: client}

	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"good-repo", "other-repo"}}
	results, err := d.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	for _, r := range results {
		if r.Status != model.StatusVerifiedPass {
			t.Errorf("result %s status = %q, want verified-pass", r.Scope.Repo, r.Status)
		}
	}

	prov := client.Provenance()
	if len(prov) != 2 {
		t.Fatalf("len(Provenance()) = %d, want 2 (one call per repo)", len(prov))
	}
	for _, p := range prov {
		if p.Method != "GET" {
			t.Errorf("provenance Method = %q, want GET", p.Method)
		}
		if p.HTTPStatus != 200 {
			t.Errorf("provenance HTTPStatus = %d, want 200", p.HTTPStatus)
		}
		if p.ResponseSHA256 == "" {
			t.Error("provenance ResponseSHA256 is empty")
		}
		if p.Timestamp.IsZero() {
			t.Error("provenance Timestamp is zero")
		}
	}
}

func TestDemoCollector_PlanGatedResponseProducesNotCheckableNeverFail(t *testing.T) {
	fx := ghfixture.New().Set("GET", "/repos/attestor-demo/free-plan-repo", ghfixture.Response{
		Status: http.StatusNotFound,
		Body:   map[string]any{"message": "Not Found"},
	})
	client := newTestClient(t, "ghp_demo-token", fx)
	d := &demoCollector{client: client}

	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"free-plan-repo"}}
	results, err := d.Collect(context.Background(), scope)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if got := results[0].Status; got != model.StatusNotCheckable {
		t.Errorf("status = %q, want not-checkable (never verified-fail for a plan-gated response)", got)
	}
}

func TestDemoCollector_CollectorFailureDoesNotPanicCaller(t *testing.T) {
	// No fixture registered for this repo at all: proves an unmatched
	// request surfaces as a clean error (via ghfixture.ErrNoFixture), not a
	// panic — the caller (the future #10 orchestrator) is documented to
	// turn that error into a single not-checkable CheckResult and keep
	// going, but that aggregation is #10's job, not this package's.
	fx := ghfixture.New()
	client := newTestClient(t, "ghp_demo-token", fx)
	d := &demoCollector{client: client}

	scope := collect.Scope{Org: "attestor-demo", Repos: []string{"unregistered-repo"}}
	_, err := d.Collect(context.Background(), scope)
	if err == nil {
		t.Fatal("Collect() = nil error, want an error for a repo with no matching fixture")
	}
}

// newTestClient builds a Client whose transport chain terminates in fx
// instead of a real network round-tripper, reusing the package's actual
// auth+provenance+rate-limit layers unmodified.
func newTestClient(t *testing.T, token string, fx *ghfixture.Transport) *Client {
	t.Helper()
	prov := newProvenanceTransport(token, fx)
	rl := newRateLimitTransport(prov)
	httpClient := &http.Client{Transport: rl}

	rest := github.NewClient(httpClient)
	rest.DisableRateLimitCheck = true // rateLimitTransport already handles this uniformly for REST and GraphQL

	return &Client{
		REST:    rest,
		GraphQL: githubv4.NewClient(httpClient),
		prov:    prov,
	}
}
