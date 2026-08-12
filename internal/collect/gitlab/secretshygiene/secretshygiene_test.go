package secretshygiene

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/sioakeim/attestward/internal/collect"
	"gitlab.com/sioakeim/attestward/internal/collect/collecttest"
	gitlabcollect "gitlab.com/sioakeim/attestward/internal/collect/gitlab"
	"gitlab.com/sioakeim/attestward/internal/model"
)

func newTestCollector(t *testing.T, handler http.Handler) *Collector {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewForTest(server.URL, "token", func() (*gitlabcollect.Client, error) {
		return gitlabcollect.NewClientForTest(server.URL, "token", http.DefaultTransport)
	})
}

func collectWith(t *testing.T, handler http.Handler, org string, repos ...string) []model.CheckResult {
	t.Helper()
	c := newTestCollector(t, handler)
	results, err := c.Collect(context.Background(), collect.Scope{Org: org, Repos: repos})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return results
}

func varJSON(key, value string, masked bool) string {
	return fmt.Sprintf(`{"key":%q,"value":%q,"masked":%v}`, key, value, masked)
}

// varsMux serves GET /projects/:id/variables — verified live 2026-08-13
// against gitlab.com/sioakeim/attestward-scratch (see the package doc
// comment).
func varsMux(vars []string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/g%2Fp/variables", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := "[" + strings.Join(vars, ",") + "]"
		_, _ = fmt.Fprint(w, body)
	})
	return mux
}

func TestNoVariablesIsAPass(t *testing.T) {
	got := collectWith(t, varsMux(nil), "g", "p")
	if len(got) != 1 || got[0].Status != model.StatusVerifiedPass {
		t.Fatalf("got = %+v, want one verified-pass result", got)
	}
}

func TestNonSensitiveVariableIsIgnoredRegardlessOfMasking(t *testing.T) {
	vars := []string{varJSON("BUILD_ENV", "production", false), varJSON("REGION", "eu-west", false)}
	got := collectWith(t, varsMux(vars), "g", "p")
	if got[0].Status != model.StatusVerifiedPass {
		t.Errorf("status = %q, want verified-pass; reason=%q", got[0].Status, got[0].Reason)
	}
}

func TestSensitiveMaskedVariablePasses(t *testing.T) {
	vars := []string{varJSON("DB_PASSWORD", "hunter2plaintext", true)}
	got := collectWith(t, varsMux(vars), "g", "p")
	if got[0].Status != model.StatusVerifiedPass {
		t.Errorf("status = %q, want verified-pass; reason=%q", got[0].Status, got[0].Reason)
	}
}

func TestSensitiveEmptyValueIsIgnored(t *testing.T) {
	vars := []string{varJSON("API_TOKEN", "", false)}
	got := collectWith(t, varsMux(vars), "g", "p")
	if got[0].Status != model.StatusVerifiedPass {
		t.Errorf("status = %q, want verified-pass — an empty value has nothing to leak; reason=%q", got[0].Status, got[0].Reason)
	}
}

func TestSensitiveUnmaskedVariableFails(t *testing.T) {
	vars := []string{varJSON("DB_PASSWORD", "hunter2plaintext", false)}
	got := collectWith(t, varsMux(vars), "g", "p")
	if got[0].Status != model.StatusVerifiedFail {
		t.Fatalf("status = %q, want verified-fail; reason=%q", got[0].Status, got[0].Reason)
	}
	offending, _ := got[0].Facts["offending_variables"].([]string)
	if len(offending) != 1 || offending[0] != "DB_PASSWORD" {
		t.Errorf("Facts.offending_variables = %v, want [DB_PASSWORD]", offending)
	}
}

func TestMixOfOffendingAndCleanVariablesFailsAndListsOnlyOffenders(t *testing.T) {
	vars := []string{
		varJSON("DB_PASSWORD", "hunter2plaintext", false),
		varJSON("API_TOKEN", "SuperSecretMaskedValue123", true),
		varJSON("BUILD_ENV", "production", false),
	}
	got := collectWith(t, varsMux(vars), "g", "p")
	if got[0].Status != model.StatusVerifiedFail {
		t.Fatalf("status = %q, want verified-fail", got[0].Status)
	}
	offending, _ := got[0].Facts["offending_variables"].([]string)
	if len(offending) != 1 || offending[0] != "DB_PASSWORD" {
		t.Errorf("Facts.offending_variables = %v, want exactly [DB_PASSWORD]", offending)
	}
}

// TestNeverLeaksVariableValues is this check's sentinel test — proving a
// distinctive real value never appears anywhere in the marshaled result,
// not just that checkSecretMasking's own code doesn't reference it. Same
// discipline Azure DevOps's own secretshygiene package established
// (TestCollect_SecretHygiene_NeverLeaksVariableValues).
func TestNeverLeaksVariableValues(t *testing.T) {
	const distinctiveValue = "hunter2plaintext-distinctive-marker"
	vars := []string{varJSON("DB_PASSWORD", distinctiveValue, false)}
	got := collectWith(t, varsMux(vars), "g", "p")

	marshaled := fmt.Sprintf("%+v", got)
	if strings.Contains(marshaled, distinctiveValue) {
		t.Fatalf("result contains the raw variable value — Facts must record only variable names: %s", marshaled)
	}
}

func TestSensitivePatternsMatchTheDocumentedConventions(t *testing.T) {
	for _, name := range []string{"DB_PASSWORD", "db_passwd", "PWD", "MY_SECRET", "API_CREDENTIALS", "ACCESS_TOKEN", "API_KEY", "API-KEY", "DB_CONNSTR", "CONNECTION_STRING"} {
		if !sensitiveVariableNameRE.MatchString(name) {
			t.Errorf("%q did not match the sensitive-name pattern", name)
		}
	}
	for _, name := range []string{"BUILD_ENV", "REGION", "NODE_VERSION"} {
		if sensitiveVariableNameRE.MatchString(name) {
			t.Errorf("%q unexpectedly matched the sensitive-name pattern", name)
		}
	}
}

func TestVariablesReadFailureIsNotCheckable(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/g%2Fp/variables", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		_, _ = fmt.Fprint(w, `{"message":"403 Forbidden"}`)
	})
	got := collectWith(t, mux, "g", "p")
	if len(got) != 1 || got[0].Status != model.StatusNotCheckable {
		t.Fatalf("got = %+v, want one not-checkable result", got)
	}
}

func TestClientBuildFailureIsNotCheckable(t *testing.T) {
	c := NewForTest("https://example.invalid", "token", func() (*gitlabcollect.Client, error) {
		return nil, fmt.Errorf("boom")
	})
	results, err := c.Collect(context.Background(), collect.Scope{Org: "g", Repos: []string{"p"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != 1 || results[0].Status != model.StatusNotCheckable {
		t.Fatalf("results = %+v, want one not-checkable result", results)
	}
}

func TestID(t *testing.T) {
	if got := New("https://gitlab.example", "t").ID(); got != collectorID {
		t.Errorf("ID() = %q, want %q", got, collectorID)
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue
// #10).
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	states := []struct {
		name string
		h    http.Handler
		want model.Status
	}{
		{"no offending variables", varsMux([]string{varJSON("BUILD_ENV", "production", false)}), model.StatusVerifiedPass},
		{"one offending variable", varsMux([]string{varJSON("DB_PASSWORD", "hunter2plaintext", false)}), model.StatusVerifiedFail},
		{"variables unreadable", (func() http.Handler {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v4/projects/g%2Fp/variables", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(403)
				_, _ = fmt.Fprint(w, `{"message":"nope"}`)
			})
			return mux
		})(), model.StatusNotCheckable},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			res := collectWith(t, st.h, "g", "p")
			if len(res) != 1 || res[0].Status != st.want {
				t.Fatalf("got %+v, want a single %q result", res, st.want)
			}
			all = append(all, res...)
		})
	}

	collecttest.AssertRubricsMatchObservedBehaviour(t, platform, collectorID, all)
}
