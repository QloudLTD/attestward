<!-- Propose a new verification check: a control the tool should verify via a read-only API call. Suggested label: enhancement -->

### Control to verify

<!-- One sentence — what real-world security control does this check prove? -->
<!-- e.g. "Deploy workflows use OIDC federation instead of long-lived cloud keys" -->

### API evidence

<!-- Which API endpoint(s)/fields prove or disprove it? Link API docs. Read-only endpoints only — see ADR-0004. -->

### SSDF mapping

<!-- Which NIST SP 800-218 task ID(s) does this provide evidence for? Cite the exact IDs
     from the publication — do not invent IDs. -->

### Pass/fail semantics

<!-- What is verified-pass? verified-fail? partial? When is it not-checkable (e.g.
     plan-gated features, insufficient token scope)? -->

### Token permissions required

<!-- Minimum fine-grained PAT permission(s) this check needs. -->
