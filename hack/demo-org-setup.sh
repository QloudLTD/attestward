#!/usr/bin/env bash
# hack/demo-org-setup.sh — creates/configures the public demo fixture repos
# attestor's integration test scans (issue #15). Idempotent: safe to re-run.
#
# Scope: this pass only configures what C01–C04 need. CodeQL run history,
# release signing, SLSA provenance, and deliberately-insecure workflow
# patterns (unpinned actions, pull_request_target) are deferred to the
# issues that add the checks needing them (C05–C10, actions-security) —
# fixtures.yaml documents this explicitly, matching issue #15's own
# "grows as C05–C10 land" framing.
#
# Requires: gh CLI authenticated as an admin of the target org.
#
# Usage: hack/demo-org-setup.sh [org]   (default org: Qloud-LTD)

set -euo pipefail

ORG="${1:-Qloud-LTD}"
GOOD_REPO="demo-good"
BAD_REPO="demo-bad"

log() { printf '==> %s\n' "$1"; }

# put_file creates or updates $2 in $1's default branch with content $3,
# handling the Contents API's create-vs-update distinction (an update
# requires the existing blob's sha; a create must omit it). Skips the write
# entirely when the file already has the target content — required for
# idempotency once branch protection is active on demo-good's main: ANY
# direct push there needs a PR regardless of whether content would actually
# change, so a no-op write attempt still 409s.
put_file() {
	local repo="$1" path="$2" content="$3" message="$4"
	local encoded
	encoded=$(printf '%s' "$content" | base64 | tr -d '\n')
	local existing_json existing_content existing_sha
	existing_json=$(gh api "repos/$ORG/$repo/contents/$path" 2>/dev/null || true)
	existing_content=$(printf '%s' "$existing_json" | jq -r '.content // empty' | tr -d '\n')
	if [ "$existing_content" = "$encoded" ]; then
		return 0
	fi
	existing_sha=$(printf '%s' "$existing_json" | jq -r '.sha // empty')
	if [ -n "$existing_sha" ]; then
		gh api "repos/$ORG/$repo/contents/$path" -X PUT \
			-f message="$message" -f content="$encoded" -f sha="$existing_sha" >/dev/null
	else
		gh api "repos/$ORG/$repo/contents/$path" -X PUT \
			-f message="$message" -f content="$encoded" >/dev/null
	fi
}

ensure_repo() {
	local repo="$1" description="$2"
	if gh repo view "$ORG/$repo" >/dev/null 2>&1; then
		log "$ORG/$repo already exists"
	else
		log "creating $ORG/$repo"
		gh repo create "$ORG/$repo" --public --description "$description"
	fi
}

log "configuring org-level defaults on $ORG"
# members_can_create_public_repositories=false ("private-only repo creation")
# is deliberately NOT set here: GitHub rejects it on Free-plan orgs
# ("Private-only repository creation policy is not allowed for this
# organization"). C01.org.members-can-create-public will accurately show
# verified-fail against this org as a result — a real Free-plan constraint,
# not a config mistake — see fixtures.yaml's note on this check.
# advanced_security_enabled_for_new_repositories=true is sent below but,
# on this Free-plan org, GitHub silently accepts the request without
# actually flipping the value (verified: it stays false) — same "silent
# 200" class as the two_factor_requirement_enabled quirk further down,
# just without an easy way to detect and warn about it inline here since
# this single PATCH call sets several fields at once. Left in rather than
# removed: attempting it is harmless, and it'll start working on its own
# if the org's plan or GitHub's policy ever changes — see
# C04.org.security-defaults' note in fixtures.yaml.
gh api "orgs/$ORG" -X PATCH \
	-f default_repository_permission=read \
	-F secret_scanning_enabled_for_new_repositories=true \
	-F secret_scanning_push_protection_enabled_for_new_repositories=true \
	-F dependabot_alerts_enabled_for_new_repositories=true \
	-F advanced_security_enabled_for_new_repositories=true >/dev/null

log "attempting to enable org-wide 2FA requirement"
gh api "orgs/$ORG" -X PATCH -F two_factor_requirement_enabled=true >/dev/null 2>&1 || true
# GitHub has been observed to return 200 here while silently leaving the
# field false (rather than erroring) — a real platform quirk, not
# hypothetical (see fixtures.yaml's note on C01.org.2fa-required). A
# non-2xx from the PATCH itself is deliberately non-fatal to the rest of
# this script either way (`|| true` above), so the only reliable way to
# know whether this actually took effect is to read the value back.
if [ "$(gh api "orgs/$ORG" --jq '.two_factor_requirement_enabled')" != "true" ]; then
	echo "    warning: two_factor_requirement_enabled is still false after attempting to enable it — enable 2FA on the org owner's account (if not already), then re-run this script, or set it manually in org settings" >&2
fi

ensure_repo "$GOOD_REPO" "attestor demo fixture: SSDF/CISA controls configured correctly (C01-C04)"
ensure_repo "$BAD_REPO" "attestor demo fixture: controls deliberately off/misconfigured (C01-C04)"

# The environment reviewer must be an actual org member's user ID — the
# authenticated user running this script (an org admin) is always a valid
# choice. A prior version of this line queried users/$ORG, which resolves
# to the *organization's own* numeric ID tagged type "Organization" — not
# a valid "User"-type reviewer, so GitHub silently accepted the malformed
# request and left the reviewers list empty rather than erroring.
OWNER_ID=$(gh api user --jq '.id')

log "pushing initial content to $GOOD_REPO"
put_file "$GOOD_REPO" "README.md" \
"# demo-good

Fixture repo for [attestor](https://github.com/sioakim/ssdf)'s integration test
harness (issue #15): every C01-C04 control this repo can express is configured
correctly. See \`../fixtures.yaml\` in the attestor repo for the exact expected
status of every check against this repo.
" "docs: add README"

put_file "$GOOD_REPO" ".github/workflows/ci.yaml" \
"name: build
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
" "ci: add trivial build workflow (required status check fixture)"

log "pushing initial content to $BAD_REPO"
put_file "$BAD_REPO" "README.md" \
"# demo-bad

Fixture repo for [attestor](https://github.com/sioakim/ssdf)'s integration test
harness (issue #15): every C01-C04 control this repo can express is
deliberately off or misconfigured. See \`../fixtures.yaml\` in the attestor
repo for the exact expected status of every check against this repo.
" "docs: add README"

log "configuring $GOOD_REPO branch protection on main"
gh api "repos/$ORG/$GOOD_REPO/branches/main/protection" -X PUT --input - >/dev/null <<EOF
{
  "required_status_checks": {"strict": true, "checks": [{"context": "build"}]},
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 1},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF

log "configuring $GOOD_REPO production environment"
gh api "repos/$ORG/$GOOD_REPO/environments/production" -X PUT --input - >/dev/null <<EOF
{
  "reviewers": [{"type": "User", "id": $OWNER_ID}],
  "deployment_branch_policy": {"protected_branches": true, "custom_branch_policies": false}
}
EOF

log "configuring $GOOD_REPO secret scanning + push protection"
gh api "repos/$ORG/$GOOD_REPO" -X PATCH --input - >/dev/null <<'EOF'
{
  "security_and_analysis": {
    "secret_scanning": {"status": "enabled"},
    "secret_scanning_push_protection": {"status": "enabled"}
  }
}
EOF

log "enabling $GOOD_REPO Dependabot alerts"
gh api "repos/$ORG/$GOOD_REPO/vulnerability-alerts" -X PUT >/dev/null

log "configuring $BAD_REPO production environment (deliberately unprotected)"
gh api "repos/$ORG/$BAD_REPO/environments/production" -X PUT --input - >/dev/null <<'EOF'
{}
EOF

log "ensuring $BAD_REPO secret scanning + push protection are off"
gh api "repos/$ORG/$BAD_REPO" -X PATCH --input - >/dev/null <<'EOF'
{
  "security_and_analysis": {
    "secret_scanning": {"status": "disabled"},
    "secret_scanning_push_protection": {"status": "disabled"}
  }
}
EOF

log "ensuring $BAD_REPO Dependabot alerts are off"
# This endpoint is idempotent (204 whether alerts were already off or not),
# so there's no legitimate case for swallowing a failure here — an
# `|| true` would hide a real permission/repo-gone error and let the
# script report "done" while demo-bad still had alerts enabled.
gh api "repos/$ORG/$BAD_REPO/vulnerability-alerts" -X DELETE >/dev/null

log "done — verify with: attestor scan --org $ORG --repo $GOOD_REPO --repo $BAD_REPO --out /tmp/demo-scan"
