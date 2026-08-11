package provenance

import "regexp"

// checksumAssetPatterns and signatureAssetPatterns are reproduced verbatim
// from internal/collect/github/provenance/assets.go — the naming
// conventions themselves are platform-neutral (a checksums.txt file means
// the same thing regardless of which forge hosts it), so this duplicates
// the regexes rather than inventing a second set that could quietly drift
// from the GitHub twin's. Duplicated per ADR-0005, same as heuristics.go
// in the vdp packages.
var checksumAssetPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^checksums\.txt$`),
	regexp.MustCompile(`(?i)^sha256sums(\.txt)?$`),
	regexp.MustCompile(`(?i)\.sha256(sum)?$`),
}

// signatureAssetPatterns deliberately does NOT include GitHub Artifact
// Attestation's digest-lookup path — that is a GitHub-specific mechanism
// (a separate API querying attestations by asset digest) with no GitLab
// equivalent, the same class of platform gap C10.vdp.private-reporting
// already documents. Naming-convention evidence is the whole of what this
// check can evaluate on GitLab.
var signatureAssetPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\.sig$`),
	regexp.MustCompile(`(?i)\.pem$`),
	regexp.MustCompile(`(?i)\.intoto\.jsonl$`),
	regexp.MustCompile(`(?i)\.sigstore(\.json)?$`),
	regexp.MustCompile(`(?i)\.bundle$`),
}

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
