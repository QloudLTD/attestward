package report

import (
	"reflect"
	"testing"

	"github.com/sioakim/attestward/internal/mapping"
	"github.com/sioakim/attestward/internal/model"
)

// matchingMappingVersions builds a model.MappingVersions whose every field
// equals the corresponding loaded mapping's own Version — derived from the
// mappings themselves, never a hardcoded literal, so this stays correct
// regardless of what mappings/*.yaml's own version: fields currently say
// (found in review of #265: an earlier version of this file hardcoded
// "1.13.0"/"1.0.0"/"1.5.0" — the last of those wasn't even the registry's
// real current version at review time, since the bump was still on the
// then-unmerged #253).
func matchingMappingVersions(t *testing.T) (model.MappingVersions, *mapping.SSDFMapping, *mapping.CISAMapping, *mapping.SelfAttestationQuestions, *mapping.ScannerSignatureRegistry) {
	t.Helper()
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)
	pack := model.MappingVersions{
		SSDF:              ssdf.Version,
		CISAForm:          cisa.Version,
		SelfAttestation:   saQuestions.Version,
		ScannerSignatures: scannerSignatures.Version,
	}
	return pack, ssdf, cisa, saQuestions, scannerSignatures
}

// TestMappingVersionMismatch_AllFourMatch_False is the negative baseline
// every other test in this file drifts away from: a pack whose four
// recorded versions all equal what's actually loaded must never trigger
// the mismatch banner.
func TestMappingVersionMismatch_AllFourMatch_False(t *testing.T) {
	pack, ssdf, cisa, saQuestions, scannerSignatures := matchingMappingVersions(t)
	if got := mappingVersionMismatch(pack, ssdf, cisa, saQuestions, scannerSignatures); got {
		t.Errorf("mappingVersionMismatch(pack=%+v) = true, want false — every field matches what's loaded", pack)
	}
}

// TestMappingVersionMismatch_EveryFieldDriftsIndependently is issue #264
// (and #265's own review, which found the first version of this test
// still didn't deliver what #264 asked for): MappingVersionMismatch used
// to compare only two of the four mapping files (ssdf, cisa_form) in both
// buildContext and buildPOAMContext, identically — self_attestation and
// scanner_signatures were silently never checked. A hand-listed table
// test (the shape this test replaces) proves today's four fields are each
// wired up, but a fifth field added to model.MappingVersions later with
// no matching comparison in mappingVersionMismatch would leave that table
// green forever — the exact class of gap a hand-maintained list always
// carries (docs/threat-model.md's own persistent-runner-state paragraph
// hit this identically, per #257's review).
//
// Reflecting over model.MappingVersions itself — one struct, one uniform
// "does drifting this field alone flip the result" predicate, the same
// shape as #263's own guard — closes that gap structurally: a fifth
// field is discovered and drifted automatically, with no test-file change
// required, and fails with a message naming exactly which field has no
// comparison wired up for it.
func TestMappingVersionMismatch_EveryFieldDriftsIndependently(t *testing.T) {
	baseline, ssdf, cisa, saQuestions, scannerSignatures := matchingMappingVersions(t)

	v := reflect.ValueOf(baseline)
	tp := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := tp.Field(i)
		t.Run(field.Name, func(t *testing.T) {
			if v.Field(i).Kind() != reflect.String {
				t.Fatalf("MappingVersions.%s is not a string field — this test assumes every field is a version string; update it if that's no longer true", field.Name)
			}

			drifted := baseline
			dv := reflect.ValueOf(&drifted).Elem()
			dv.Field(i).SetString(dv.Field(i).String() + "-drifted")

			if !mappingVersionMismatch(drifted, ssdf, cisa, saQuestions, scannerSignatures) {
				t.Errorf("field %s (%s) drifted but mappingVersionMismatch returned false — add a comparison for it", field.Name, field.Tag.Get("json"))
			}
		})
	}
}

// TestMappingVersionMismatch_OlderPackMissingScannerSignaturesVersion_NoFalsePositive
// confirms, rather than assumes, the claim that makes it safe to ship the
// scanner_signatures comparison when not every pack carries the field.
// #255's fix (PR #263) started populating it, so packs scanned from that
// point on have it — but packs captured earlier, including
// examples/demo-org-pack's own frozen fixture, still lack it entirely.
// The existing pack.X != "" guard degrades an absent field to "skip this
// one comparison" rather than "confirmed mismatch": the real, currently
// loaded scannerSignatures registry (loadRealMappings, not a hand-typed
// version string — #265's review caught the earlier version of this file
// claiming "real, current" while actually using a struct literal) paired
// with a pack whose own ScannerSignatures is empty must not trigger the
// banner on that field alone.
func TestMappingVersionMismatch_OlderPackMissingScannerSignaturesVersion_NoFalsePositive(t *testing.T) {
	ssdf, cisa, saQuestions, scannerSignatures := loadRealMappings(t)
	pack := model.MappingVersions{SSDF: ssdf.Version, CISAForm: cisa.Version, SelfAttestation: saQuestions.Version} // ScannerSignatures deliberately absent

	if got := mappingVersionMismatch(pack, ssdf, cisa, saQuestions, scannerSignatures); got {
		t.Errorf("mappingVersionMismatch(pack=%+v) = true, want false — an older pack missing scanner_signatures entirely must not spuriously trigger the mismatch banner on that field", pack)
	}
}
