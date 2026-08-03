package provenance

import (
	"fmt"
	"net/http"
	"sort"

	ghgithub "github.com/google/go-github/v75/github"

	"gitlab.com/sioakeim/attestward/internal/collect"
	ghcollect "gitlab.com/sioakeim/attestward/internal/collect/github"
	"gitlab.com/sioakeim/attestward/internal/collect/github/runhistory"
	"gitlab.com/sioakeim/attestward/internal/mapping"
	"gitlab.com/sioakeim/attestward/internal/model"
)

func notCheckableReason(resp *ghgithub.Response, err error, org, repo string, scope collect.Scope) string {
	if resp != nil {
		switch {
		case resp.StatusCode == http.StatusForbidden:
			return fmt.Sprintf("token lacks permission to read %s/%s", org, repo)
		case ghcollect.IsPlanGated(resp.StatusCode):
			return ghcollect.GatedRepoReason(scope.IsGHES, scope.GHESVersion, "feature", org, repo)
		}
	}
	return fmt.Sprintf("could not query %s/%s: %v", org, repo, err)
}

// resolvedRelease is one release's tag-signature resolution, computed once
// in collectRepo and shared by checkTagsSigned and checkCommitLinkage
// (which both need CommitSHA, only one of which needs the signature
// itself).
type resolvedRelease struct {
	Release    runhistory.ReleaseInfo
	Signature  tagSignature
	ResolveErr error
}

// linkageResult is one release's commit-linkage evidence.
type linkageResult struct {
	TagName  string
	RunCount int
	Err      error
}

// signatureEvidence is one release's evidence for checkSignatures —
// gathered with I/O (asset listing, attestation lookups) in collectRepo
// so the check function itself stays pure given already-fetched data.
type signatureEvidence struct {
	TagName           string
	MatchedAssetNames []string
	AttestedDigest    string
	AttestationErr    error
	// LookupCapped is true when this release had more digest-bearing
	// assets than hasAnyAttestation's maxAttestationLookupsPerRelease
	// cap — surfaced in Facts so a "no attestation found" verdict on a
	// large release discloses it checked only the first few assets, not
	// an exhaustive search.
	LookupCapped bool
}

// releaseVerdict is one release's outcome for any of the four per-release
// checks — three-way, not boolean, so an unresolvable tag (an API call
// failed for reasons unrelated to the release's actual state) can be
// distinguished from a release that was fully evaluated and genuinely
// failed. Conflating the two would either overstate confidence (treating
// "unknown" as passing) or overstate a gap (treating "unknown" as a
// confirmed failure) — C05/C06 established this same distinction for
// their own dropped/unresolvable-tag cases (capping at partial rather
// than fail), and C07 follows it for consistency.
type releaseVerdict int

const (
	releasePassed releaseVerdict = iota
	releaseFailed
	releaseUnresolved
)

// releaseCheckResult is one release's verdict for any of the four
// per-release checks, in the shape rollupReleaseResults consumes.
type releaseCheckResult struct {
	TagName string
	Verdict releaseVerdict
	Reason  string
	Facts   map[string]any
}

// rollupReleaseResults implements the issue's stated semantics: "overall
// status = worst recent release, with per-release table in facts." A
// confirmed failure anywhere always wins (verified-fail) — an unresolvable
// release elsewhere doesn't soften a genuine gap. Absent any confirmed
// failure, an unresolvable release caps the result at partial rather than
// letting it read as a clean verified-pass. Only when every release both
// resolved AND passed does the check reach verified-pass.
func rollupReleaseResults(results []releaseCheckResult) (model.Status, []map[string]any) {
	table := make([]map[string]any, 0, len(results))
	anyFailed, anyUnresolved := false, false
	for _, r := range results {
		row := map[string]any{"tag": r.TagName, "passed": r.Verdict == releasePassed, "reason": r.Reason}
		for k, v := range r.Facts {
			row[k] = v
		}
		table = append(table, row)
		switch r.Verdict {
		case releaseFailed:
			anyFailed = true
		case releaseUnresolved:
			anyUnresolved = true
		}
	}
	switch {
	case anyFailed:
		return model.StatusVerifiedFail, table
	case anyUnresolved:
		return model.StatusPartial, table
	default:
		return model.StatusVerifiedPass, table
	}
}

// checkTagsSigned implements the issue's tags-signed semantics exactly:
// "signed AND GitHub reports the signature verified." A tag whose
// resolution failed (a Git.GetRef/Git.GetTag call error, e.g. a deleted
// tag) is neither confirmed signed nor confirmed unsigned — it's
// releaseUnresolved, capping the overall result at partial rather than
// being treated as a confirmed fail (see rollupReleaseResults). A
// lightweight tag, by contrast, IS a confirmed fail: git's own object
// model makes "lightweight and signed" impossible, so there's nothing
// unresolved about it.
func checkTagsSigned(org, repo string, resolved []resolvedRelease, prov []model.Provenance) model.CheckResult {
	const id = "C07.release.tags-signed"

	if len(resolved) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "no releases match the configured release tag pattern within the lookback window",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	results := make([]releaseCheckResult, 0, len(resolved))
	for _, r := range resolved {
		if r.ResolveErr != nil {
			results = append(results, releaseCheckResult{
				TagName: r.Release.TagName, Verdict: releaseUnresolved,
				Reason: fmt.Sprintf("tag could not be resolved: %v", r.ResolveErr),
			})
			continue
		}
		verdict := releaseFailed
		if r.Signature.Signed && r.Signature.Verified {
			verdict = releasePassed
		}
		results = append(results, releaseCheckResult{
			TagName: r.Release.TagName,
			Verdict: verdict,
			Reason:  r.Signature.Reason,
			Facts: map[string]any{
				"signed":    r.Signature.Signed,
				"verified":  r.Signature.Verified,
				"annotated": r.Signature.Annotated,
			},
		})
	}

	status, table := rollupReleaseResults(results)
	reason := "every release tag in the lookback window is signed and its signature is verified"
	switch status {
	case model.StatusVerifiedFail:
		reason = "at least one release tag in the lookback window is unsigned or its signature is not verified"
	case model.StatusPartial:
		reason = "every resolvable release tag in the lookback window is signed and verified, but at least one tag could not be resolved"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"per_release": table},
	}
}

// checkChecksums looks only at each release's already-fetched Assets list
// (ListReleases returns the full asset array, including per-asset
// digests, in one call — no per-release GetRelease needed) against
// checksumAssetPatterns. Pure given rawByTag; no I/O of its own.
func checkChecksums(org, repo string, filteredReleases []runhistory.ReleaseInfo, rawByTag map[string]*ghgithub.RepositoryRelease, prov []model.Provenance) model.CheckResult {
	const id = "C07.release.checksums"

	if len(filteredReleases) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "no releases match the configured release tag pattern within the lookback window",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	results := make([]releaseCheckResult, 0, len(filteredReleases))
	for _, rel := range filteredReleases {
		raw := rawByTag[rel.TagName]
		var names []string
		if raw != nil {
			for _, a := range raw.Assets {
				names = append(names, a.GetName())
			}
		}
		matched := matchingAssetNames(names, checksumAssetPatterns)
		verdict := releaseFailed
		reason := "no checksum asset found among this release's assets"
		if len(matched) > 0 {
			verdict = releasePassed
			reason = fmt.Sprintf("checksum asset(s) found: %v", matched)
		}
		results = append(results, releaseCheckResult{
			TagName: rel.TagName, Verdict: verdict, Reason: reason,
			Facts: map[string]any{"matched_assets": matched},
		})
	}

	status, table := rollupReleaseResults(results)
	reason := "every release in the lookback window ships a checksum asset"
	if status == model.StatusVerifiedFail {
		reason = "at least one release in the lookback window has no checksum asset"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"per_release": table},
	}
}

// checkSignatures accepts two independent kinds of evidence per release,
// either of which is sufficient: a signature/attestation-shaped asset by
// naming convention, or a GitHub Artifact Attestation found for one of
// the release's asset digests (collectRepo only bothers with the latter,
// I/O-costing lookup when the former already came up empty — see
// collectRepo's ordering).
func checkSignatures(org, repo string, filteredReleases []runhistory.ReleaseInfo, evidence map[string]signatureEvidence, prov []model.Provenance) model.CheckResult {
	const id = "C07.release.signatures"

	if len(filteredReleases) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "no releases match the configured release tag pattern within the lookback window",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	results := make([]releaseCheckResult, 0, len(filteredReleases))
	for _, rel := range filteredReleases {
		ev := evidence[rel.TagName]
		verdict := releaseFailed
		reason := "no signature/attestation asset and no GitHub Artifact Attestation found"
		if ev.LookupCapped {
			reason += fmt.Sprintf(" (checked only the first %d digest-bearing asset(s); not an exhaustive search)", maxAttestationLookupsPerRelease)
		}
		if len(ev.MatchedAssetNames) > 0 {
			verdict = releasePassed
			reason = fmt.Sprintf("signature asset(s) found: %v", ev.MatchedAssetNames)
		} else if ev.AttestedDigest != "" {
			verdict = releasePassed
			reason = fmt.Sprintf("a GitHub Artifact Attestation was found for asset digest %s", ev.AttestedDigest)
		} else if ev.AttestationErr != nil {
			// No naming-convention match, and the attestation lookup that
			// would have confirmed or ruled out the other kind of evidence
			// itself failed — the digest that errored might well have an
			// attestation, so this is unresolved, not a confirmed absence
			// (see checkTagsSigned/checkCommitLinkage's identical
			// releaseUnresolved use for the same reasoning).
			verdict = releaseUnresolved
			reason = fmt.Sprintf("no signature asset found by naming convention, and the attestation lookup itself failed: %v", ev.AttestationErr)
		}
		results = append(results, releaseCheckResult{
			TagName: rel.TagName, Verdict: verdict, Reason: reason,
			Facts: map[string]any{
				"matched_assets":            ev.MatchedAssetNames,
				"attested_digest":           ev.AttestedDigest,
				"attestation_lookup_capped": ev.LookupCapped,
			},
		})
	}

	status, table := rollupReleaseResults(results)
	reason := "every release in the lookback window ships a signature/attestation asset or has a GitHub Artifact Attestation"
	switch status {
	case model.StatusVerifiedFail:
		reason = "at least one release in the lookback window has neither a signature/attestation asset nor a GitHub Artifact Attestation"
	case model.StatusPartial:
		reason = "every release with confirmed evidence in the lookback window ships a signature/attestation asset or has a GitHub Artifact Attestation, but at least one release's attestation lookup failed and couldn't be resolved"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"per_release": table},
	}
}

// checkProvenanceWorkflow is release-independent — like C05/C06's
// tool-configured, it asks "is a provenance-generating tool configured at
// all," not "did it run for this release" (that's commit-linkage's job,
// via a different, more precise mechanism: direct HeadSHA matching rather
// than category-matched-workflow run history). Applies the same
// confidence-capping rule as C05/C06: a low-confidence-only match (a
// workflow merely named "SLSA" with no matched action) can never alone
// justify verified-pass.
//
// skipped is this repo's runhistory.MatchWorkflows skip list (issue #207 —
// the last of this codebase's tool-configured-shaped checks to consume it;
// C05/C06 on both platforms and this package's own ADO twin already do):
// surfaced in Facts unconditionally (path + reason per entry), and — only
// when every other signal here would otherwise produce verified-fail —
// capping that at not-checkable instead, since a workflow this collector
// couldn't fully inspect means "no provenance tool configured" rests on
// incomplete evidence, not a confirmed absence. Unlike C05, there is no
// enablement-style OR condition here at all (no GitHub-native attestation
// default-setup feature exists), so this guard has no precedence question
// to resolve — contrast azuredevops/scahistory's checkRanPerRelease, whose
// injectionOnly guard has to win over an identical skip guard for exactly
// that reason.
func checkProvenanceWorkflow(org, repo string, matched []runhistory.MatchedWorkflow, skipped []runhistory.SkippedWorkflow, prov []model.Provenance) model.CheckResult {
	const id = "C07.provenance.workflow"

	hasAny, hasHighOrMedium := false, false
	names := map[string]bool{}
	for _, mw := range matched {
		for _, m := range mw.Matches {
			hasAny = true
			names[m.Name] = true
			if m.Confidence != mapping.ConfidenceLow {
				hasHighOrMedium = true
			}
		}
	}

	skipDetails := make([]map[string]any, 0, len(skipped))
	for _, sw := range skipped {
		skipDetails = append(skipDetails, map[string]any{"path": sw.Path, "reason": sw.Reason})
	}
	hasSkips := len(skipped) > 0

	status, reason := model.StatusVerifiedFail, "no provenance-generating tool (Sigstore/cosign, SLSA generator, or GitHub Attestations) detected in any workflow"
	switch {
	case hasHighOrMedium:
		status = model.StatusVerifiedPass
		reason = "a provenance-generating tool is configured"
	case hasAny:
		status = model.StatusPartial
		reason = "only a low-confidence (workflow-name-only) match was found — not enough signal alone to confirm a provenance tool is genuinely configured"
	case hasSkips:
		status = model.StatusNotCheckable
		reason = fmt.Sprintf("no matched provenance-tool workflow evidence, but %d workflow(s) in this repo could not be fully inspected — a confirmed absence can't be asserted over incomplete evidence", len(skipped))
	}

	toolNames := make([]string, 0, len(names))
	for n := range names {
		toolNames = append(toolNames, n)
	}
	sort.Strings(toolNames)

	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{
			"tool_names":                toolNames,
			"low_confidence_match_only": hasAny && !hasHighOrMedium,
			"skipped_workflows":         skipDetails,
		},
	}
}

// checkCommitLinkage passes a release when at least one workflow run (any
// workflow, any conclusion) ran directly on that release's resolved
// commit SHA — deliberately not requiring the run to have succeeded: by
// the time a release exists with real assets, some process produced them,
// and this check's job is to verify that production is traceable to an
// identifiable CI run, not to re-judge whether that run was clean (that's
// what C07.release.checksums/signatures and the SAST/SCA history checks
// are for). A release whose commit couldn't even be resolved (r.Err set —
// propagated from checkTagsSigned's same resolvedRelease data, or the run
// listing call itself failing) is releaseUnresolved, not a confirmed
// fail — see rollupReleaseResults.
func checkCommitLinkage(org, repo string, results []linkageResult, prov []model.Provenance) model.CheckResult {
	const id = "C07.provenance.commit-linkage"

	if len(results) == 0 {
		return model.CheckResult{
			CheckID: id, Title: checkTitles[id], Status: model.StatusNotCheckable,
			Reason: "no releases match the configured release tag pattern within the lookback window",
			Scope:  model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		}
	}

	perRelease := make([]releaseCheckResult, 0, len(results))
	for _, r := range results {
		if r.Err != nil {
			perRelease = append(perRelease, releaseCheckResult{
				TagName: r.TagName, Verdict: releaseUnresolved,
				Reason: fmt.Sprintf("could not determine workflow runs for this release's commit: %v", r.Err),
			})
			continue
		}
		verdict := releaseFailed
		reason := "no workflow run found on this release's commit"
		if r.RunCount > 0 {
			verdict = releasePassed
			reason = fmt.Sprintf("%d workflow run(s) found on this release's commit", r.RunCount)
		}
		perRelease = append(perRelease, releaseCheckResult{
			TagName: r.TagName, Verdict: verdict, Reason: reason,
			Facts: map[string]any{"run_count": r.RunCount},
		})
	}

	status, table := rollupReleaseResults(perRelease)
	reason := "every release in the lookback window is traceable to a workflow run on its commit"
	switch status {
	case model.StatusVerifiedFail:
		reason = "at least one release in the lookback window has no workflow run traceable to its commit"
	case model.StatusPartial:
		reason = "every resolvable release in the lookback window is traceable to a workflow run on its commit, but at least one release's commit could not be resolved"
	}
	return model.CheckResult{
		CheckID: id, Title: checkTitles[id], Status: status, Reason: reason,
		Scope: model.ScopeRef{Org: org, Repo: repo}, Provenance: prov,
		Facts: map[string]any{"per_release": table},
	}
}
