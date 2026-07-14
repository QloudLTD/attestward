# mappings

SSDF/CISA-form compliance mappings as versioned YAML — data, not code
([ADR-0003](../docs/adr/0003-mappings-as-data.md)).

| File | Purpose | Lands with |
|---|---|---|
| `ssdf-800-218.yaml` | SSDF SP 800-218 task matrix | issue #6 |
| `cisa-ssda-form.yaml` | CISA SSDA form's four practice clusters → SSDF tasks | issue #7 |
| `scanner-signatures.yaml` | SAST/SCA/container/secrets/SBOM tool detection signatures | issue #16 |
| `self-attestation-questions.yaml` | Questionnaire for non-API-verifiable controls | issue #23 (not yet authored) |

`ssdf-800-218.yaml` and `cisa-ssda-form.yaml` transcribe regulatory sources — every ID in
those two files must trace to a primary source; see CLAUDE.md's accuracy-discipline rule.
`scanner-signatures.yaml` isn't a citation of any regulatory text (it's original data
about how tools present in GitHub Actions workflows), so that rule doesn't apply to it —
see its own header comment for the accuracy standard that does (matched against a real
fixture workflow instead).
