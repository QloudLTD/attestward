package actionssecurity

import (
	"context"
	"encoding/json"
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

// fixture describes one project's worth of API responses. Every field is a
// raw JSON body except the *Status fields, which serve that status with an
// error body instead — the two failure shapes this collector distinguishes
// (a readable field that is absent, and an endpoint that refuses) both need
// to be expressible.
//
// The bodies below are shaped from responses captured live on 2026-08-13
// against gitlab.com/sioakeim/attestward-scratch and .../attestward — see
// the package doc comment for the full list of what was confirmed.
type fixture struct {
	project       string
	projectStatus int

	lint       string
	lintStatus int

	jobTokenScope       string
	jobTokenScopeStatus int

	allowlist       string
	groupsAllowlist string

	runners       string
	runnersStatus int

	variables       string
	variablesStatus int
}

func (f fixture) handler() http.Handler {
	mux := http.NewServeMux()
	const base = "/api/v4/projects/g%2Fp"

	serve := func(path, body string, status int, fallback string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if status != 0 {
				w.WriteHeader(status)
				_, _ = fmt.Fprintf(w, `{"message":"%d test failure"}`, status)
				return
			}
			if body == "" {
				body = fallback
			}
			_, _ = fmt.Fprint(w, body)
		})
	}

	serve(base, f.project, f.projectStatus, `{"visibility":"public","ci_allow_fork_pipelines_to_run_in_parent_project":false}`)
	serve(base+"/ci/lint", f.lint, f.lintStatus, `{"valid":true,"errors":[],"merged_yaml":"job1:\n  script:\n  - echo hi\n","includes":[]}`)
	serve(base+"/job_token_scope", f.jobTokenScope, f.jobTokenScopeStatus, `{"inbound_enabled":true,"outbound_enabled":false}`)
	serve(base+"/job_token_scope/allowlist", f.allowlist, 0, `[{"id":1}]`)
	serve(base+"/job_token_scope/groups_allowlist", f.groupsAllowlist, 0, `[]`)
	serve(base+"/variables", f.variables, f.variablesStatus, `[]`)

	// The runner listing is requested twice, once per self-managed runner
	// type; the fixture body is served for project_type and an empty list
	// for group_type, so a test naming one runner gets one runner rather
	// than two.
	mux.HandleFunc(base+"/runners", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.runnersStatus != 0 {
			w.WriteHeader(f.runnersStatus)
			_, _ = fmt.Fprintf(w, `{"message":"%d test failure"}`, f.runnersStatus)
			return
		}
		if r.URL.Query().Get("type") != "project_type" {
			_, _ = fmt.Fprint(w, `[]`)
			return
		}
		body := f.runners
		if body == "" {
			body = `[]`
		}
		_, _ = fmt.Fprint(w, body)
	})

	return mux
}

func collectWith(t *testing.T, f fixture) map[string]model.CheckResult {
	t.Helper()
	results := collectAll(t, f)
	byID := map[string]model.CheckResult{}
	for _, r := range results {
		byID[r.CheckID] = r
	}
	if len(byID) != len(checkIDs) {
		t.Fatalf("got %d distinct check IDs, want %d: %v", len(byID), len(checkIDs), results)
	}
	return byID
}

func collectAll(t *testing.T, f fixture) []model.CheckResult {
	t.Helper()
	server := httptest.NewServer(f.handler())
	t.Cleanup(server.Close)
	c := NewForTest(server.URL, "token", func() (*gitlabcollect.Client, error) {
		return gitlabcollect.NewClientForTest(server.URL, "token", http.DefaultTransport)
	})
	results, err := c.Collect(context.Background(), collect.Scope{Org: "g", Repos: []string{"p"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return results
}

func assertStatus(t *testing.T, got map[string]model.CheckResult, id string, want model.Status) {
	t.Helper()
	r, ok := got[id]
	if !ok {
		t.Fatalf("no result for %s", id)
	}
	if r.Status != want {
		t.Errorf("%s status = %q, want %q; reason=%q", id, r.Status, want, r.Reason)
	}
}

// -----------------------------------------------------------------------
// the five named states, reused by the rubric guard below
// -----------------------------------------------------------------------

const shaRef = "abe6b8554a161ec776e8034c51cbb5b56e695509"

func includeJSON(entries ...string) string {
	return `{"valid":true,"errors":[],"merged_yaml":"job1:\n  script:\n  - echo hi\n","includes":[` + strings.Join(entries, ",") + `]}`
}

func fileInclude(ref string) string {
	return fmt.Sprintf(`{"type":"file","location":".gitlab-ci.yml","extra":{"project":"other/proj","ref":%q},"context_project":"g/p"}`, ref)
}

// lintWithIDTokens serves a merged_yaml declaring GitLab's OIDC keyword on
// one job, alongside whatever includes the caller wants.
func lintWithIDTokens(entries ...string) string {
	const merged = "deploy:\\n  id_tokens:\\n    AWS_TOKEN:\\n      aud: https://sts.amazonaws.com\\n  script:\\n  - echo deploy\\n"
	return `{"valid":true,"errors":[],"merged_yaml":"` + merged + `","includes":[` + strings.Join(entries, ",") + `]}`
}

func varJSON(key, value string) string {
	return fmt.Sprintf(`{"key":%q,"value":%q}`, key, value)
}

// varJSONHidden serves a masked-and-hidden variable the way GitLab actually
// returns one: value null (decodes to ""), hidden true. GitLab enforces the
// masking minimum length at creation, so a hidden variable always holds
// something — that's the whole reason hidden must not be read the same as
// genuinely empty.
func varJSONHidden(key string) string {
	return fmt.Sprintf(`{"key":%q,"value":null,"hidden":true}`, key)
}

// cleanProject is a project doing everything this collector asks for.
var cleanProject = fixture{
	project:       `{"visibility":"public","ci_allow_fork_pipelines_to_run_in_parent_project":false}`,
	lint:          lintWithIDTokens(fileInclude(shaRef)),
	jobTokenScope: `{"inbound_enabled":true}`,
	runners:       `[{"id":1,"description":"mac-studio","runner_type":"project_type"}]`,
	variables:     `[` + varJSON("BUILD_ENV", "production") + `]`,
}

// exposedProject fails or is capped on every check at once.
var exposedProject = fixture{
	project:       `{"visibility":"public","ci_allow_fork_pipelines_to_run_in_parent_project":true}`,
	lint:          includeJSON(fileInclude("main")),
	jobTokenScope: `{"inbound_enabled":false}`,
	runners:       `[{"id":1,"description":"mac-studio","runner_type":"project_type"}]`,
	variables:     `[` + varJSON("AWS_SECRET_ACCESS_KEY", "AKIAsomethinglong") + `]`,
}

// mixedProject reaches the two partial states the other fixtures do not:
// an include type this build does not classify, and OIDC configured while a
// static credential is still stored. It has no self-managed runner, so
// self-hosted passes even though fork pipelines are permitted.
var mixedProject = fixture{
	project:       `{"visibility":"public","ci_allow_fork_pipelines_to_run_in_parent_project":true}`,
	lint:          lintWithIDTokens(fileInclude(shaRef), `{"type":"some-future-type","location":"whatever","extra":{},"context_project":"g/p"}`),
	jobTokenScope: `{"inbound_enabled":true}`,
	runners:       `[]`,
	variables:     `[` + varJSON("AWS_SECRET_ACCESS_KEY", "AKIAsomethinglong") + `]`,
}

// unreadableProject is every endpoint refusing.
var unreadableProject = fixture{
	projectStatus:       403,
	lintStatus:          403,
	jobTokenScopeStatus: 403,
	runnersStatus:       403,
	variablesStatus:     403,
}

// noCloudProject has a resolvable CI configuration with neither OIDC nor a
// stored cloud credential — the ordinary shape of a project that does no
// cloud deployment, which is not-checkable for OIDC rather than a pass.
var noCloudProject = fixture{
	project:       `{"visibility":"private","ci_allow_fork_pipelines_to_run_in_parent_project":true}`,
	lint:          includeJSON(),
	jobTokenScope: `{"inbound_enabled":true}`,
	runners:       `[{"id":1,"description":"mac-studio","runner_type":"project_type"}]`,
	variables:     `[]`,
}

func TestCleanProjectPassesEveryCheck(t *testing.T) {
	got := collectWith(t, cleanProject)
	for _, id := range checkIDs {
		assertStatus(t, got, id, model.StatusVerifiedPass)
	}
}

func TestExposedProjectFailsOrCapsEveryCheck(t *testing.T) {
	got := collectWith(t, exposedProject)
	assertStatus(t, got, idPinned, model.StatusVerifiedFail)
	assertStatus(t, got, idTokenPermissions, model.StatusVerifiedFail)
	assertStatus(t, got, idOIDC, model.StatusVerifiedFail)
	assertStatus(t, got, idPRTarget, model.StatusPartial)
	assertStatus(t, got, idSelfHosted, model.StatusPartial)
}

func TestMixedProjectReachesBothRemainingPartials(t *testing.T) {
	got := collectWith(t, mixedProject)
	assertStatus(t, got, idPinned, model.StatusPartial)
	assertStatus(t, got, idOIDC, model.StatusPartial)
	assertStatus(t, got, idSelfHosted, model.StatusVerifiedPass)
}

func TestUnreadableProjectIsNotCheckableEverywhere(t *testing.T) {
	got := collectWith(t, unreadableProject)
	for _, id := range checkIDs {
		assertStatus(t, got, id, model.StatusNotCheckable)
	}
}

func TestNoCloudAuthenticationIsNotCheckableNotAPass(t *testing.T) {
	got := collectWith(t, noCloudProject)
	assertStatus(t, got, idOIDC, model.StatusNotCheckable)
	if !strings.Contains(got[idOIDC].Reason, "no cloud authentication of either kind") {
		t.Errorf("oidc reason = %q, want it to name the absent-evidence case", got[idOIDC].Reason)
	}
	// A private project with fork pipelines permitted still passes both
	// fork-exposure checks, and for the private-specific reason.
	assertStatus(t, got, idPRTarget, model.StatusVerifiedPass)
	assertStatus(t, got, idSelfHosted, model.StatusVerifiedPass)
	if !strings.Contains(got[idPRTarget].Reason, "private") {
		t.Errorf("pull-request-target reason = %q, want it to name the project's visibility", got[idPRTarget].Reason)
	}
}

// -----------------------------------------------------------------------
// the absent-field trap
// -----------------------------------------------------------------------

// TestAbsentForkSettingIsNotCheckableNotAPass is the test this collector
// exists to not fail. GitLab omits ci_allow_fork_pipelines_to_run_in_parent_
// project entirely below the Maintainer role (confirmed live). Decoded into
// a plain bool, that absence is indistinguishable from false — which is the
// SAFE value for both fork checks, so a token without the role would have
// produced two confident verified-passes backed by a field nobody read.
func TestAbsentForkSettingIsNotCheckableNotAPass(t *testing.T) {
	f := cleanProject
	f.project = `{"visibility":"public"}`
	got := collectWith(t, f)
	assertStatus(t, got, idPRTarget, model.StatusNotCheckable)
	// self-hosted only needs the setting once a runner is actually found;
	// cleanProject has one, so it must reach the same conclusion.
	assertStatus(t, got, idSelfHosted, model.StatusNotCheckable)
}

// TestAbsentForkSettingWithNoRunnersStillPassesSelfHosted pins the
// asymmetry the previous test's comment implies: with no self-managed
// runner attached there is nothing to expose, so self-hosted does not need
// the Maintainer-gated field at all and must not go not-checkable for want
// of it.
func TestAbsentForkSettingWithNoRunnersStillPassesSelfHosted(t *testing.T) {
	f := cleanProject
	f.project = `{"visibility":"public"}`
	f.runners = `[]`
	got := collectWith(t, f)
	assertStatus(t, got, idSelfHosted, model.StatusVerifiedPass)
	assertStatus(t, got, idPRTarget, model.StatusNotCheckable)
}

// -----------------------------------------------------------------------
// pinning
// -----------------------------------------------------------------------

func TestPinnedClassification(t *testing.T) {
	cases := []struct {
		name       string
		inc        ciInclude
		wantClass  includeClass
		wantPinned bool
	}{
		{"project include on a full SHA", ciInclude{Type: "file", Extra: ciIncludeExtra{Project: "o/p", Ref: shaRef}}, classPinnable, true},
		{"project include on a branch", ciInclude{Type: "file", Extra: ciIncludeExtra{Project: "o/p", Ref: "main"}}, classPinnable, false},
		{"project include with ref omitted reports HEAD", ciInclude{Type: "file", Extra: ciIncludeExtra{Project: "o/p", Ref: "HEAD"}}, classPinnable, false},
		{"component on a SHA", ciInclude{Type: "component", Location: "gitlab.com/g/p/comp@" + shaRef}, classPinnable, true},
		{"component on a catalog version", ciInclude{Type: "component", Location: "gitlab.com/g/p/comp@1.2.0"}, classPinnable, false},
		{"component on a branch", ciInclude{Type: "component", Location: "gitlab.com/g/p/comp@main"}, classPinnable, false},
		{"remote at a commit", ciInclude{Type: "remote", Location: "https://gitlab.com/g/p/-/raw/" + shaRef + "/ci.yml"}, classPinnable, true},
		{"remote at a branch", ciInclude{Type: "remote", Location: "https://gitlab.com/g/p/-/raw/main/ci.yml"}, classPinnable, false},
		{"local include", ciInclude{Type: "local", Location: "ci/jobs.yml"}, classNotPinnable, false},
		{"instance template", ciInclude{Type: "template", Location: "Security/SAST.gitlab-ci.yml"}, classNotPinnable, false},
		{"an include type this build has never seen", ciInclude{Type: "some-future-type"}, classUnknown, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyInclude(tc.inc)
			if got.Class != tc.wantClass {
				t.Errorf("class = %q, want %q", got.Class, tc.wantClass)
			}
			if got.Pinned != tc.wantPinned {
				t.Errorf("pinned = %v, want %v (ref=%q)", got.Pinned, tc.wantPinned, got.Ref)
			}
		})
	}
}

// TestRemoteSHAMustBeAWholePathSegment guards the shape of the one
// heuristic in this package: a hex run that merely CONTAINS 40 characters,
// or a SHA that only appears in the query string, does not make a remote
// URL's response immutable.
func TestRemoteSHAMustBeAWholePathSegment(t *testing.T) {
	if remoteURLHasCommitSHA("https://example.com/x/" + shaRef + "beef/ci.yml") {
		t.Error("a 44-character hex path segment was accepted as a commit SHA")
	}
	if remoteURLHasCommitSHA("https://example.com/ci.yml?ref=" + shaRef) {
		t.Error("a SHA in the query string was accepted; only the path pins the response")
	}
	if !remoteURLHasCommitSHA("https://example.com/raw/" + shaRef + "/ci.yml") {
		t.Error("a SHA as its own path segment was rejected")
	}
	// A SHA that's a slash-delimited segment of the QUERY VALUE, not the
	// path, would satisfy a naive "contains /SHA/" check on the raw URL
	// string — this is the case that actually discriminates "only u.Path is
	// examined" from "the whole URL is examined": both readings agree on
	// the three cases above.
	if remoteURLHasCommitSHA("https://example.com/ci.yml?file=/" + shaRef + "/ci.yml") {
		t.Error("a SHA as a path-shaped segment of the QUERY VALUE was accepted; only the URL's own path pins the response")
	}
}

// TestUnpinnedIncludeIsNamedInFacts proves the fail path records which
// include is at fault rather than only a count.
func TestUnpinnedIncludeIsNamedInFacts(t *testing.T) {
	got := collectWith(t, exposedProject)
	raw, _ := got[idPinned].Facts["unpinned_includes"].([]map[string]any)
	if len(raw) != 1 {
		t.Fatalf("Facts.unpinned_includes = %v, want exactly one entry", raw)
	}
	if ref, _ := raw[0]["ref"].(string); ref != "main" {
		t.Errorf("Facts.unpinned_includes[0].ref = %q, want \"main\"", ref)
	}
}

// TestLocalAndTemplateIncludesAreNotFailures pins the exclusion: neither
// can be pinned by anything the producer could do, so flagging them would
// report a finding with no possible remediation.
func TestLocalAndTemplateIncludesAreNotFailures(t *testing.T) {
	f := cleanProject
	f.lint = includeJSON(
		`{"type":"local","location":"ci/jobs.yml","extra":{},"context_project":"g/p"}`,
		`{"type":"template","location":"Security/SAST.gitlab-ci.yml","extra":{},"context_project":"g/p"}`,
	)
	got := collectWith(t, f)
	assertStatus(t, got, idPinned, model.StatusVerifiedPass)
	if count, _ := got[idPinned].Facts["evaluated_count"].(int); count != 0 {
		t.Errorf("Facts.evaluated_count = %v, want 0 — neither include should have been judged", count)
	}
}

// TestNullIncludesIsNotCheckable covers the response GitLab returns for a
// project with no CI configuration at all, and for one whose include failed
// to resolve — [] and null are different answers and only [] is evidence.
func TestNullIncludesIsNotCheckable(t *testing.T) {
	f := cleanProject
	f.lint = `{"valid":false,"errors":["Please provide content of .gitlab-ci.yml"],"merged_yaml":null,"includes":null}`
	got := collectWith(t, f)
	assertStatus(t, got, idPinned, model.StatusNotCheckable)
	assertStatus(t, got, idOIDC, model.StatusNotCheckable)
	if !strings.Contains(got[idPinned].Reason, "Please provide content of .gitlab-ci.yml") {
		t.Errorf("reason = %q, want GitLab's own error quoted rather than paraphrased", got[idPinned].Reason)
	}
}

// TestJobLevelLintErrorStillYieldsEvidence: a config that is invalid for a
// reason unrelated to its includes still comes back with a populated
// includes array and merged_yaml (confirmed live), so a stage typo must not
// cost this collector its evidence.
func TestJobLevelLintErrorStillYieldsEvidence(t *testing.T) {
	f := cleanProject
	f.lint = `{"valid":false,"errors":["job1 job: chosen stage nonexistent does not exist"],` +
		`"merged_yaml":"job1:\n  id_tokens:\n    T:\n      aud: https://x\n  script:\n  - echo hi\n",` +
		`"includes":[` + fileInclude(shaRef) + `]}`
	got := collectWith(t, f)
	assertStatus(t, got, idPinned, model.StatusVerifiedPass)
	assertStatus(t, got, idOIDC, model.StatusVerifiedPass)
}

// -----------------------------------------------------------------------
// OIDC vs. stored credentials
// -----------------------------------------------------------------------

func TestIDTokenJobsFindsBothDefaultAndJobDeclarations(t *testing.T) {
	merged := "default:\n  id_tokens:\n    D:\n      aud: https://d\nstages:\n- build\njob1:\n  script:\n  - echo hi\ndeploy:\n  id_tokens:\n    A:\n      aud: https://a\n  script:\n  - echo go\n"
	names, ok := idTokenJobs(merged)
	if !ok {
		t.Fatal("idTokenJobs reported the merged config unparseable")
	}
	if len(names) != 2 || names[0] != "default" || names[1] != "deploy" {
		t.Errorf("names = %v, want sorted [default deploy]", names)
	}
}

func TestIDTokenJobsReportsUnparseableRatherThanEmpty(t *testing.T) {
	if _, ok := idTokenJobs("\tnot: [valid\n  yaml"); ok {
		t.Error("unparseable YAML reported ok — a parse failure must not read as \"no OIDC configured\"")
	}
	if _, ok := idTokenJobs("   "); ok {
		t.Error("empty merged config reported ok")
	}
}

func TestStaticCloudCredentialsAreMatchedExactlyAndCaseSensitively(t *testing.T) {
	vars := []variableRaw{
		{Key: "AWS_SECRET_ACCESS_KEY", Value: "real"},
		{Key: "aws_secret_access_key", Value: "lowercase-is-not-read-by-the-sdk"},
		{Key: "MY_AWS_SECRET_ACCESS_KEY_BACKUP", Value: "substring-only"},
		{Key: "AZURE_CLIENT_SECRET", Value: ""},
		{Key: "SOME_API_TOKEN", Value: "a secret, but not a cloud credential"},
	}
	got := findStaticCloudCredentials(vars)
	if len(got) != 1 || got[0].Key != "AWS_SECRET_ACCESS_KEY" || got[0].Cloud != "aws" {
		t.Fatalf("findStaticCloudCredentials = %+v, want exactly the exact-name, non-empty AWS key", got)
	}
}

// TestEveryStaticCloudCredentialNameIsDetected exercises every entry in
// staticCloudCredentialVariables individually, table-driven — the table IS
// the entire detection surface of this check, and the sibling test above
// only ever supplies AWS_SECRET_ACCESS_KEY, leaving the other four names
// (and their cloud labels) completely unexercised.
func TestEveryStaticCloudCredentialNameIsDetected(t *testing.T) {
	for name, wantCloud := range staticCloudCredentialVariables {
		t.Run(name, func(t *testing.T) {
			got := findStaticCloudCredentials([]variableRaw{{Key: name, Value: "real"}})
			if len(got) != 1 || got[0].Key != name || got[0].Cloud != wantCloud {
				t.Fatalf("findStaticCloudCredentials(%s) = %+v, want [{%s %s}]", name, got, name, wantCloud)
			}
		})
	}
}

// TestHiddenCredentialVariableCountsAsStored is the regression test for a
// real bug caught in review: GitLab always returns "value": null (decodes
// to "") for a masked-and-hidden variable, and the pre-fix code read an
// empty Value as "nothing stored" — so a hidden AWS_SECRET_ACCESS_KEY, the
// most security-conscious configuration a team could choose, produced a
// confident verified-pass whose reason text ("this project stores no
// long-lived cloud credential variable") was false. Hidden must be treated
// as holding a value regardless of what Value decodes to.
func TestHiddenCredentialVariableCountsAsStored(t *testing.T) {
	got := findStaticCloudCredentials([]variableRaw{{Key: "AWS_SECRET_ACCESS_KEY", Hidden: true}})
	if len(got) != 1 || got[0].Key != "AWS_SECRET_ACCESS_KEY" || got[0].Cloud != "aws" {
		t.Fatalf("findStaticCloudCredentials(hidden) = %+v, want the hidden AWS key detected despite empty Value", got)
	}
}

// TestHiddenCredentialWithNoOIDCFailsNotPasses reproduces the false-pass
// end to end through Collect, not just the extraction function: a project
// with no id_tokens: block and a hidden, unmasked-name cloud credential
// must fail, never read as clean because Value came back empty.
func TestHiddenCredentialWithNoOIDCFailsNotPasses(t *testing.T) {
	f := noCloudProject
	f.variables = `[` + varJSONHidden("AWS_SECRET_ACCESS_KEY") + `]`
	got := collectWith(t, f)
	assertStatus(t, got, idOIDC, model.StatusVerifiedFail)
}

// TestHiddenCredentialWithOIDCIsPartialNotPass reproduces the more severe
// of the two false results found in review: a project WITH id_tokens:
// declared AND a hidden AWS_SECRET_ACCESS_KEY must read as partial (OIDC in
// use for something, but a static credential remains available too), never
// as verified-pass — the pre-fix code read the hidden variable's empty
// Value as "no credential stored" and shipped a pack asserting the project
// stored no long-lived cloud credential, which was false.
func TestHiddenCredentialWithOIDCIsPartialNotPass(t *testing.T) {
	f := cleanProject
	f.variables = `[` + varJSONHidden("AWS_SECRET_ACCESS_KEY") + `]`
	got := collectWith(t, f)
	assertStatus(t, got, idOIDC, model.StatusPartial)
}

// TestOIDCNeverLeaksCredentialValues is this check's sentinel: it reads
// variable VALUES (to tell "stored" from "empty") and must never carry one
// into the pack. Marshalling is the format the pack actually ships, not a
// debug dump, and the key marker assertion proves the test exercised the
// offending path rather than passing vacuously on empty Facts.
func TestOIDCNeverLeaksCredentialValues(t *testing.T) {
	const sentinel = "ZzZ-do-not-leak-this-exact-sentinel-value-ZzZ"
	f := exposedProject
	f.variables = `[` + varJSON("AWS_SECRET_ACCESS_KEY", sentinel) + `]`
	got := collectWith(t, f)
	if got[idOIDC].Status != model.StatusVerifiedFail {
		t.Fatalf("status = %q, want verified-fail (fixture setup sanity check)", got[idOIDC].Status)
	}
	marshaled, err := json.Marshal(got[idOIDC])
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(marshaled), sentinel) {
		t.Fatalf("marshaled CheckResult contains the credential value verbatim: %s", marshaled)
	}
	if !strings.Contains(string(marshaled), "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("marshaled CheckResult never named the offending variable, so this test proved nothing: %s", marshaled)
	}
}

// TestUnreadableVariablesIsNotCheckableEvenWithOIDCPresent: a project can
// declare id_tokens for one cloud and still keep a static key for another,
// so an unreadable variable list cannot be waved through as a pass.
func TestUnreadableVariablesIsNotCheckableEvenWithOIDCPresent(t *testing.T) {
	f := cleanProject
	f.variablesStatus = 403
	got := collectWith(t, f)
	assertStatus(t, got, idOIDC, model.StatusNotCheckable)
	assertStatus(t, got, idPinned, model.StatusVerifiedPass)
}

// -----------------------------------------------------------------------
// job token scope
// -----------------------------------------------------------------------

// TestAllowlistCountsAreContextNotStatus: the two allowlist endpoints are
// read only for Facts, so their failure must leave the check's own status
// alone rather than dragging it to not-checkable.
func TestAllowlistCountsAreContextNotStatus(t *testing.T) {
	f := cleanProject
	f.allowlist = `{"message":"nope"}` // not an array: decoding fails
	got := collectWith(t, f)
	assertStatus(t, got, idTokenPermissions, model.StatusVerifiedPass)
	if _, present := got[idTokenPermissions].Facts["allowlist_project_count"]; present {
		t.Error("allowlist_project_count is present despite the allowlist being unreadable")
	}
	if enabled, _ := got[idTokenPermissions].Facts["inbound_enabled"].(bool); !enabled {
		t.Error("inbound_enabled fact missing or false")
	}
}

func TestAllowlistCountsAppearWhenReadable(t *testing.T) {
	f := cleanProject
	f.allowlist = `[{"id":1},{"id":2}]`
	f.groupsAllowlist = `[{"id":9}]`
	facts := collectWith(t, f)[idTokenPermissions].Facts
	if facts["allowlist_project_count"] != 2 || facts["allowlist_group_count"] != 1 {
		t.Errorf("allowlist facts = %v, want 2 projects and 1 group", facts)
	}
}

// -----------------------------------------------------------------------
// provenance
// -----------------------------------------------------------------------

// TestProvenanceIsSegmentedPerCheck: each check must carry the calls its own
// Status depends on and no others, so a reader auditing one result is not
// shown five unrelated endpoints as its basis.
func TestProvenanceIsSegmentedPerCheck(t *testing.T) {
	got := collectWith(t, cleanProject)
	contains := func(r model.CheckResult, fragment string) bool {
		for _, p := range r.Provenance {
			if strings.Contains(p.Endpoint, fragment) {
				return true
			}
		}
		return false
	}
	if !contains(got[idPinned], "/ci/lint") {
		t.Errorf("pinned provenance does not include the lint call: %+v", got[idPinned].Provenance)
	}
	if contains(got[idPinned], "/variables") || contains(got[idPinned], "/runners") {
		t.Errorf("pinned provenance includes calls its status does not depend on: %+v", got[idPinned].Provenance)
	}
	if !contains(got[idTokenPermissions], "/job_token_scope") {
		t.Errorf("token-permissions provenance does not include the job token scope call: %+v", got[idTokenPermissions].Provenance)
	}
	if contains(got[idTokenPermissions], "/ci/lint") {
		t.Errorf("token-permissions provenance includes the lint call: %+v", got[idTokenPermissions].Provenance)
	}
	if !contains(got[idOIDC], "/ci/lint") || !contains(got[idOIDC], "/variables") {
		t.Errorf("oidc provenance is missing one of its two evidence calls: %+v", got[idOIDC].Provenance)
	}
}

// -----------------------------------------------------------------------
// collector plumbing
// -----------------------------------------------------------------------

func TestClientBuildFailureIsNotCheckable(t *testing.T) {
	c := NewForTest("https://example.invalid", "token", func() (*gitlabcollect.Client, error) {
		return nil, fmt.Errorf("boom")
	})
	results, err := c.Collect(context.Background(), collect.Scope{Org: "g", Repos: []string{"p"}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(results) != len(checkIDs) {
		t.Fatalf("got %d results, want %d", len(results), len(checkIDs))
	}
	for _, r := range results {
		if r.Status != model.StatusNotCheckable {
			t.Errorf("%s status = %q, want not-checkable", r.CheckID, r.Status)
		}
	}
}

func TestID(t *testing.T) {
	if got := New("https://gitlab.example", "t").ID(); got != collectorID {
		t.Errorf("ID() = %q, want %q", got, collectorID)
	}
}

func TestEveryResultIsPlatformStamped(t *testing.T) {
	for _, r := range collectAll(t, cleanProject) {
		if r.Scope.Platform != platform {
			t.Errorf("%s Scope.Platform = %q, want %q", r.CheckID, r.Scope.Platform, platform)
		}
		if r.Title != checkTitles[r.CheckID] {
			t.Errorf("%s Title = %q, want %q", r.CheckID, r.Title, checkTitles[r.CheckID])
		}
	}
}

// TestNoTitleNamesAGitHubMechanism is the check the C07 and C10 reviews
// both had to make by eye: a title inherited from a GitHub twin names a
// mechanism GitLab does not have, and is wrong regardless of what the check
// reports.
func TestNoTitleNamesAGitHubMechanism(t *testing.T) {
	for id, title := range checkTitles {
		for _, banned := range []string{"GITHUB_TOKEN", "pull_request_target", "GitHub", "workflow", "self-hosted runner"} {
			if strings.Contains(title, banned) {
				t.Errorf("%s title %q names %q, a GitHub mechanism", id, title, banned)
			}
		}
	}
}

// TestRubricsMatchObservedBehaviour wires the shared rubric guard (issue
// #10). The matrix is the five named fixtures above plus the absent-field
// state, which together reach every status all five checks can emit.
func TestRubricsMatchObservedBehaviour(t *testing.T) {
	absentForkSetting := cleanProject
	absentForkSetting.project = `{"visibility":"public"}`

	states := []struct {
		name string
		f    fixture
	}{
		{"clean", cleanProject},
		{"exposed", exposedProject},
		{"mixed", mixedProject},
		{"unreadable", unreadableProject},
		{"no cloud auth", noCloudProject},
		{"fork setting not visible to this token", absentForkSetting},
	}

	var all []model.CheckResult
	for _, st := range states {
		t.Run(st.name, func(t *testing.T) {
			all = append(all, collectAll(t, st.f)...)
		})
	}
	collecttest.AssertRubricsMatchObservedBehaviour(t, platform, collectorID, all)
}
