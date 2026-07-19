package provenance

import (
	"context"

	ghcollect "github.com/sioakim/attestward/internal/collect/github"
)

// maxAttestationLookupsPerRelease bounds how many of a release's assets
// get an attestation lookup — a goreleaser-style release can ship dozens
// of per-platform binaries, and this check only needs "is at least one
// asset attested," not a full inventory; capping keeps the worst case
// (no attestations exist anywhere) from costing one API call per asset.
const maxAttestationLookupsPerRelease = 5

// hasAnyAttestation checks GitHub Artifact Attestations
// (GET /repos/{owner}/{repo}/attestations/{subject_digest}) for up to the
// first maxAttestationLookupsPerRelease of assetDigests, stopping at the
// first one actually found. Returns the digest that matched (empty if
// none did within the capped set); capped — true when there were more
// digest-bearing assets than the cap allowed checking, so a "not found"
// result can honestly disclose it wasn't an exhaustive search rather than
// reading as a confident negative; and the first real lookup error
// encountered, if any — one asset's attestation lookup failing doesn't
// invalidate the others (a later digest can still short-circuit to a
// match), but the caller treats a lookup error with no match found as
// unresolved rather than a confirmed absence, since the errored digest
// might well have an attestation.
func hasAnyAttestation(ctx context.Context, client *ghcollect.Client, org, repo string, assetDigests []string) (matchedDigest string, capped bool, firstErr error) {
	checked := 0
	for _, digest := range assetDigests {
		if digest == "" {
			continue
		}
		if checked >= maxAttestationLookupsPerRelease {
			capped = true
			break
		}
		checked++

		resp, _, err := client.REST.Repositories.ListAttestations(ctx, org, repo, digest, nil)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if len(resp.Attestations) > 0 {
			return digest, false, nil
		}
	}
	return "", capped, firstErr
}
