package provenance

import "regexp"

// checksumAssetPatterns matches the release-asset naming conventions the
// issue explicitly calls out: checksums.txt, SHA256SUMS (with or without a
// .txt suffix — goreleaser and manual release processes both appear), and
// a per-file *.sha256 sidecar.
var checksumAssetPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^checksums\.txt$`),
	regexp.MustCompile(`(?i)^sha256sums(\.txt)?$`),
	regexp.MustCompile(`(?i)\.sha256(sum)?$`),
}

// signatureAssetPatterns matches release-asset naming conventions for a
// detached signature or attestation file: the issue's own explicit list
// (.sig, .pem, .intoto.jsonl, .sigstore) plus .bundle — cosign v3's actual
// output format (`cosign sign-blob --bundle=...`), the version this
// project's own release pipeline uses (see .goreleaser.yaml's signs:
// block) and the convention the demo release fixture for this collector
// uses.
var signatureAssetPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.sig$`),
	regexp.MustCompile(`(?i)\.pem$`),
	regexp.MustCompile(`(?i)\.intoto\.jsonl$`),
	regexp.MustCompile(`(?i)\.sigstore(\.json)?$`),
	regexp.MustCompile(`(?i)\.bundle$`),
}

// matchesAnyPattern reports whether name matches any of patterns — a
// small pure helper shared by the checksum/signature asset checks so
// their "does any asset look like X" logic isn't duplicated.
func matchesAnyPattern(name string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(name) {
			return true
		}
	}
	return false
}

// matchingAssetNames returns the subset of assetNames matching any of
// patterns, for Facts — a reader auditing the pack should see exactly
// which asset(s) satisfied the check, not just a bare pass/fail.
func matchingAssetNames(assetNames []string, patterns []*regexp.Regexp) []string {
	var out []string
	for _, name := range assetNames {
		if matchesAnyPattern(name, patterns) {
			out = append(out, name)
		}
	}
	return out
}
