# mappings

SSDF/CISA-form compliance mappings as versioned YAML — data, not code
([ADR-0003](../docs/adr/0003-mappings-as-data.md)).

| File | Purpose | Lands with |
|---|---|---|
| `ssdf-800-218.yaml` | SSDF SP 800-218 task matrix | issue #6 |
| `cisa-ssda-form.yaml` | CISA SSDA form's four practice clusters → SSDF tasks | issue #7 |
| `scanner-signatures.yaml` | SAST/SCA tool detection signatures | issue #16 |
| `self-attestation-questions.yaml` | Questionnaire for non-API-verifiable controls | issue #23 |

Not yet authored — placeholder until those issues land. IDs in every file here must trace
to a primary source; see CLAUDE.md's accuracy-discipline rule.
