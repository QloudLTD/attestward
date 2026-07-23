#!/usr/bin/env bash
# hack/demo-ado-setup.sh — creates/configures the Azure DevOps demo fixture
# project attestward's ADO integration test scans (issue #155, epic #34's
# v0.2 ADO parity work). Idempotent: safe to re-run. Twin of
# hack/demo-org-setup.sh for the GitHub demo org — same check-then-create
# discipline, same per-step logging, same fail-loud-and-name-the-call
# posture — adapted to raw Azure DevOps REST 7.1 calls (there is no `gh`
# equivalent CLI dependency here; this script talks to
# dev.azure.com/{org} directly over HTTPS with curl + jq).
#
# Write-operations carve-out: this script, like its GitHub twin, is hack/
# tooling that provisions a fixture project attestward's own integration
# test then scans read-only — it is not the attestward binary itself.
# ADR-0004 ("read-only, forever") governs the shipped scanner
# (cmd/attestward and everything it imports); it says nothing about how the
# fixtures that scanner is tested against get set up, the same framing
# demo-org-setup.sh's own header comment establishes for the GitHub side.
#
# Structural note specific to Azure DevOps: environments are PROJECT-scoped
# (see internal/collect/azuredevops/envseparation's package doc comment),
# not repo-scoped the way GitHub's environments are. There is exactly one
# "production" environment in this whole project, and it's what backs C03's
# project-level checks regardless of which repo is in scope for a given
# `attestward scan` invocation — there is no ADO equivalent of "demo-bad has
# no environment" the way there is for GitHub's per-repo environments; the
# platform simply has no such per-repo concept to withhold.
#
# Requires: AZURE_DEVOPS_SETUP_PAT with (at minimum) full read/write access
# to the target org — this is a TEMPORARY, short-lived setup credential,
# distinct from the read-only AZURE_DEVOPS_EXT_PAT the shipped binary and
# CI's scheduled integration scan use (see resolveScanToken in
# cmd/attestward/scan.go). curl and jq must be on PATH.
#
# Usage: ADO_ORG=seciq AZURE_DEVOPS_SETUP_PAT=<pat> hack/demo-ado-setup.sh

set -euo pipefail

ORG="${ADO_ORG:-seciq}"
SETUP_PAT="${AZURE_DEVOPS_SETUP_PAT:-}"
PROJECT="attestward-demo"
GOOD_REPO="demo-good"
BAD_REPO="demo-bad"

API_VERSION="7.1"
# Check Configurations (Approvals and Checks) has no non-preview api-version
# as of 7.1 — both its List and Add operations are documented at
# 7.1-preview.1 specifically; every other call in this script uses the
# stable 7.1.
CHECKS_API_VERSION="7.1-preview.1"

ZERO_OBJECT_ID="0000000000000000000000000000000000000000"

# Policy/check type IDs — reused verbatim from this repo's own already-
# verified constants (not re-derived here) rather than re-guessed:
# internal/collect/azuredevops/repoprotection/repoprotection.go's
# minReviewersTypeID/buildValidationTypeID and
# internal/collect/azuredevops/envseparation/envseparation.go's
# approvalCheckTypeID — both verified there against Microsoft's own REST
# reference sample responses, and independently corroborated by the
# Configurations - Create / Check Configurations - Add reference pages'
# own sample requests during this script's research pass.
MIN_REVIEWERS_TYPE_ID="fa4e907d-c16b-4a4c-9dfa-4906e5d171dd"
BUILD_VALIDATION_TYPE_ID="0609b952-1397-4640-95ec-e00a01b2c241"
APPROVAL_CHECK_TYPE_ID="8c6f20a7-a545-4486-9777-f762fafe0d4d"

# log writes to STDERR, deliberately — several functions below (ensure_repo,
# push_good_initial_commit, ensure_pipeline, ensure_environment) both log
# progress AND return a value (an id/SHA) via stdout to a $(...) capture;
# a log line on stdout would silently prepend "==> ..." onto that captured
# value, corrupting every URL/body built from it downstream.
log() { printf '==> %s\n' "$1" >&2; }

require_env() {
	if [ -z "$SETUP_PAT" ]; then
		echo "FAILED: AZURE_DEVOPS_SETUP_PAT is not set" >&2
		exit 1
	fi
}

# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

# ado_request performs one authenticated REST call (Basic auth, empty
# username, the PAT as password — the standard Azure DevOps PAT convention)
# and prints "<body>\n<http status>" so its two callers below can split it.
ado_request() {
	local method="$1" url="$2" body="${3:-}"
	if [ -n "$body" ]; then
		curl -sS -u ":$SETUP_PAT" -X "$method" "$url" \
			-H "Content-Type: application/json" -d "$body" \
			-w $'\n%{http_code}'
	else
		curl -sS -u ":$SETUP_PAT" -X "$method" "$url" \
			-H "Content-Type: application/json" \
			-w $'\n%{http_code}'
	fi
}

# fail_http is ado_api/ado_get's shared "name the call and die" exit path —
# centralizes the message format so both report identically.
fail_http() {
	local method="$1" url="$2" reason="$3" resp="${4:-}"
	echo "FAILED: $method $url -> $reason" >&2
	if [ -n "$resp" ]; then
		echo "$resp" >&2
	fi
	exit 1
}

# check_auth_and_transport is shared by ado_api/ado_get, called before
# either's own status-range handling: fails loudly on a missing HTTP
# status (curl itself failed — network/TLS) or on HTTP 203. 203 (Non-
# Authoritative Information) is Azure DevOps's real, observed response for
# an invalid or expired PAT — a 2xx status carrying an HTML sign-in page
# instead of JSON, not "outside 2xx" the way every other auth failure this
# script anticipated would be, so a bare status-range check alone lets it
# straight through as if the call had succeeded.
check_auth_and_transport() {
	local method="$1" url="$2" status="$3"
	if ! [[ "$status" =~ ^[0-9]+$ ]]; then
		fail_http "$method" "$url" "curl produced no HTTP status (network/TLS failure)"
	fi
	if [ "$status" = "203" ]; then
		fail_http "$method" "$url" "HTTP 203 (Non-Authoritative Information) — Azure DevOps returns this, with an HTML body, for an invalid or expired PAT; AZURE_DEVOPS_SETUP_PAT needs to be regenerated"
	fi
}

# ado_api is this script's default call path: fails loudly — naming the
# method, URL, HTTP status, and response body — on any non-2xx, including
# 404. Almost every call in this script uses this: once a resource is
# expected to exist (the project after ensure_project, a repo after
# ensure_repo, etc.), a 404 reading it back is a genuine error, not a
# normal "doesn't exist yet" outcome.
ado_api() {
	local method="$1" url="$2" body="${3:-}"
	local raw status resp
	raw=$(ado_request "$method" "$url" "$body")
	status="${raw##*$'\n'}"
	resp="${raw%$'\n'*}"
	check_auth_and_transport "$method" "$url" "$status"
	if [ "$status" -lt 200 ] || [ "$status" -ge 300 ]; then
		fail_http "$method" "$url" "HTTP $status" "$resp"
	fi
	printf '%s' "$resp"
}

# ado_get is ado_api's read-side twin, used only where a 404 is the
# expected, non-error "doesn't exist yet" outcome of a check-then-create
# step — in this script, that's exactly one call site: ensure_project's own
# existence probe (Projects - Get 404s on a project that hasn't been
# created yet; every other resource this script probes is looked up via a
# List call, which returns 200 with an empty/filtered array instead of
# 404ing, so ado_api's loud-fail-on-404 is the correct behavior there).
ado_get() {
	local url="$1" raw status resp
	raw=$(ado_request GET "$url" "")
	status="${raw##*$'\n'}"
	resp="${raw%$'\n'*}"
	if [ "$status" = "404" ]; then
		return 1
	fi
	check_auth_and_transport GET "$url" "$status"
	if [ "$status" -lt 200 ] || [ "$status" -ge 300 ]; then
		fail_http GET "$url" "HTTP $status" "$resp"
	fi
	printf '%s' "$resp"
}

# ---------------------------------------------------------------------------
# Project
# ---------------------------------------------------------------------------

# ensure_project creates $PROJECT if it doesn't already exist. Projects -
# Create is asynchronous (202, returns an operation to poll) — verified
# against Microsoft's own reference page, whose sample response is exactly
# this shape. The "Basic" process template is looked up by name via
# Processes - List rather than hardcoding its templateTypeId: safer than
# guessing a GUID that could differ per organization/tenant.
ensure_project() {
	if ado_get "https://dev.azure.com/$ORG/_apis/projects/$PROJECT?api-version=$API_VERSION" >/dev/null; then
		log "project $ORG/$PROJECT already exists"
		return 0
	fi

	log "creating project $ORG/$PROJECT"
	local process_id body op_json op_id op_status
	process_id=$(ado_api GET "https://dev.azure.com/$ORG/_apis/process/processes?api-version=$API_VERSION" "" \
		| jq -r '.value[] | select(.name=="Basic") | .id')
	if [ -z "$process_id" ]; then
		echo "FAILED: no 'Basic' process template found on org $ORG (GET _apis/process/processes)" >&2
		exit 1
	fi

	body=$(jq -n --arg name "$PROJECT" --arg proc "$process_id" '{
		name: $name,
		description: "attestward demo fixture project (issue #155) — see hack/demo-ado-setup.sh in sioakim/attestward",
		visibility: "private",
		capabilities: {
			versioncontrol: {sourceControlType: "Git"},
			processTemplate: {templateTypeId: $proc}
		}
	}')
	op_json=$(ado_api POST "https://dev.azure.com/$ORG/_apis/projects?api-version=$API_VERSION" "$body")
	op_id=$(printf '%s' "$op_json" | jq -r '.id')

	log "waiting for project creation operation $op_id"
	for _ in $(seq 1 30); do
		op_status=$(ado_api GET "https://dev.azure.com/$ORG/_apis/operations/$op_id?api-version=$API_VERSION" "" | jq -r '.status')
		case "$op_status" in
		succeeded)
			log "project $ORG/$PROJECT created"
			return 0
			;;
		failed | cancelled)
			echo "FAILED: project creation operation $op_id ended with status $op_status" >&2
			exit 1
			;;
		esac
		sleep 5
	done
	echo "FAILED: project creation operation $op_id did not reach 'succeeded' within 150s" >&2
	exit 1
}

# project_id resolves $PROJECT's GUID — called only after ensure_project, so
# a non-2xx here (via ado_api, not ado_get) is a genuine error, not a normal
# "doesn't exist yet" case.
project_id() {
	ado_api GET "https://dev.azure.com/$ORG/_apis/projects/$PROJECT?api-version=$API_VERSION" "" | jq -r '.id'
}

# ---------------------------------------------------------------------------
# Repositories
# ---------------------------------------------------------------------------

repo_id_by_name() {
	local name="$1"
	ado_api GET "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories?api-version=$API_VERSION" "" \
		| jq -r --arg n "$name" '.value[] | select(.name==$n) | .id'
}

ensure_repo() {
	local name="$1" id
	id=$(repo_id_by_name "$name")
	if [ -n "$id" ]; then
		log "repo $PROJECT/$name already exists ($id)"
		printf '%s' "$id"
		return 0
	fi

	log "creating repo $PROJECT/$name"
	local proj_id body
	proj_id=$(project_id)
	body=$(jq -n --arg name "$name" --arg pid "$proj_id" '{name: $name, project: {id: $pid}}')
	ado_api POST "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories?api-version=$API_VERSION" "$body" \
		| jq -r '.id'
}

# ensure_default_branch is a defensive belt-and-suspenders step: Azure Repos
# is documented to set defaultBranch automatically from the first branch
# ever pushed to an empty repo, but this script's correctness (branch
# policies, the pipeline definition, the annotated tag) all assume
# refs/heads/main specifically, so this confirms it rather than trusting
# that behavior silently. Idempotent: only PATCHes when the read-back value
# doesn't already match.
ensure_default_branch() {
	local repo_id="$1" current
	current=$(ado_api GET "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories/$repo_id?api-version=$API_VERSION" "" \
		| jq -r '.defaultBranch // empty')
	if [ "$current" = "refs/heads/main" ]; then
		return 0
	fi
	log "setting default branch to refs/heads/main for repo id=$repo_id (was '${current:-<unset>}')"
	local body
	body=$(jq -n '{defaultBranch: "refs/heads/main"}')
	ado_api PATCH "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories/$repo_id?api-version=$API_VERSION" "$body" >/dev/null
}

main_ref_exists() {
	local repo_id="$1" resp
	resp=$(ado_api GET "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories/$repo_id/refs?filter=heads/main&api-version=$API_VERSION" "")
	[ "$(printf '%s' "$resp" | jq -r '(.value // []) | length')" -gt 0 ]
}

head_commit_sha() {
	local repo_id="$1" resp
	resp=$(ado_api GET "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories/$repo_id/refs?filter=heads/main&api-version=$API_VERSION" "")
	printf '%s' "$resp" | jq -r '.value[0].objectId'
}

# ---------------------------------------------------------------------------
# Initial commit content
# ---------------------------------------------------------------------------

# Single-quoted heredocs throughout this section: several of these bodies
# contain literal $(...)-shaped Azure Pipelines macro syntax (e.g.
# $(Build.BuildId) in the pipeline YAML below) that must NOT be evaluated
# by bash as command substitution.

read -r -d '' GOOD_README <<'EOF' || true
# demo-good

Fixture repo for [attestward](https://github.com/sioakim/attestward)'s Azure DevOps
integration test harness (issue #155): every control this repo can express is
configured correctly. See `../fixtures-ado.yaml` in the attestward repo for the
exact expected status of every check against this repo.
EOF

read -r -d '' GOOD_SECURITY_MD <<'EOF' || true
# Security Policy

If you discover a security vulnerability in this repository, please report it to
security@example.com or via https://example.com/security/report — please do not
open a public work item for a security issue.

This is a demo fixture for [attestward](https://github.com/sioakim/attestward)'s
Azure DevOps integration test harness (issue #155).
EOF

# Mirrors internal/mapping/testdata/pipelines/trivy.yaml verbatim (the
# fixture the scanner-signature registry's trivy entry — mappings/
# scanner-signatures.yaml — is itself tested against): a script step whose
# command line matches trivy's registered run_pattern, "trivy (fs|repo|image)".
read -r -d '' GOOD_PIPELINE_YAML <<'EOF' || true
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: |
      curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
      trivy image --exit-code 1 --severity HIGH,CRITICAL myregistry.azurecr.io/myapp:$(Build.BuildId)
    displayName: 'Run Trivy image scan'
EOF

read -r -d '' BAD_README <<'EOF' || true
# demo-bad

Fixture repo for [attestward](https://github.com/sioakim/attestward)'s Azure DevOps
integration test harness (issue #155): every control this repo can express is
deliberately off or misconfigured — starting with the absence of a SECURITY.md.
See `../fixtures-ado.yaml` in the attestward repo for the exact expected status
of every check against this repo.
EOF

# push_good_initial_commit pushes README.md + SECURITY.md + azure-pipelines.yml
# as one commit if refs/heads/main doesn't exist yet, then always echoes the
# HEAD commit's SHA (freshly pushed or pre-existing) — ensure_tag needs this
# on every run, not just the first.
push_good_initial_commit() {
	local repo_id="$1"
	if main_ref_exists "$repo_id"; then
		log "$GOOD_REPO: refs/heads/main already exists — skipping initial commit"
		head_commit_sha "$repo_id"
		return 0
	fi

	log "pushing initial commit to $GOOD_REPO (README.md, SECURITY.md, azure-pipelines.yml)"
	local body
	body=$(jq -n \
		--arg zero "$ZERO_OBJECT_ID" \
		--arg readme "$GOOD_README" \
		--arg security "$GOOD_SECURITY_MD" \
		--arg pipeline "$GOOD_PIPELINE_YAML" \
		'{
			refUpdates: [{name: "refs/heads/main", oldObjectId: $zero}],
			commits: [{
				comment: "chore: initial commit (attestward demo fixture, issue #155)",
				changes: [
					{changeType: "add", item: {path: "/README.md"}, newContent: {content: $readme, contentType: "rawtext"}},
					{changeType: "add", item: {path: "/SECURITY.md"}, newContent: {content: $security, contentType: "rawtext"}},
					{changeType: "add", item: {path: "/azure-pipelines.yml"}, newContent: {content: $pipeline, contentType: "rawtext"}}
				]
			}]
		}')
	ado_api POST "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories/$repo_id/pushes?api-version=$API_VERSION" "$body" \
		| jq -r '.commits[0].commitId'
}

# push_bad_initial_commit pushes only README.md — no SECURITY.md, no
# pipeline, no policies; every C10 vdp check and every scanner-configured
# check should honestly verified-fail/not-checkable against this repo.
push_bad_initial_commit() {
	local repo_id="$1"
	if main_ref_exists "$repo_id"; then
		log "$BAD_REPO: refs/heads/main already exists — skipping initial commit"
		return 0
	fi

	log "pushing initial commit to $BAD_REPO (README.md only — deliberately no SECURITY.md)"
	local body
	body=$(jq -n --arg zero "$ZERO_OBJECT_ID" --arg readme "$BAD_README" '{
		refUpdates: [{name: "refs/heads/main", oldObjectId: $zero}],
		commits: [{
			comment: "chore: initial commit (attestward demo fixture, issue #155)",
			changes: [
				{changeType: "add", item: {path: "/README.md"}, newContent: {content: $readme, contentType: "rawtext"}}
			]
		}]
	}')
	ado_api POST "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories/$repo_id/pushes?api-version=$API_VERSION" "$body" >/dev/null
}

# ---------------------------------------------------------------------------
# Pipeline (demo-good only)
# ---------------------------------------------------------------------------

pipeline_id_by_name() {
	local name="$1"
	ado_api GET "https://dev.azure.com/$ORG/$PROJECT/_apis/pipelines?api-version=$API_VERSION" "" \
		| jq -r --arg n "$name" '.value[] | select(.name==$n) | .id'
}

# ensure_pipeline creates a YAML pipeline definition pointing at
# azure-pipelines.yml in repo_id. [fixture-verify]: Microsoft's own
# Pipelines - Create reference page documents only the bare
# configuration.type field in its request-body table (a known class of gap
# this epic has already flagged elsewhere — see BuildProcess's own
# undocumented yamlFilename field, internal/collect/azuredevops/
# pipelinehistory/pipeline.go's YAMLPathUnknown doc comment) — the
# configuration.path/repository sub-fields used below are corroborated by
# Microsoft's own samples elsewhere and widespread real-world usage, but
# not by this exact reference page's table. If this call's response shape
# surprises you on the first live run, that's exactly where to look first.
ensure_pipeline() {
	local name="$1" repo_id="$2" path="$3" id
	id=$(pipeline_id_by_name "$name")
	if [ -n "$id" ]; then
		log "pipeline $name already exists (id=$id)"
		printf '%s' "$id"
		return 0
	fi

	log "creating pipeline $name ($path)"
	local body
	body=$(jq -n --arg name "$name" --arg path "$path" --arg rid "$repo_id" '{
		name: $name,
		configuration: {
			type: "yaml",
			path: $path,
			repository: {id: $rid, type: "azureReposGit"}
		}
	}')
	ado_api POST "https://dev.azure.com/$ORG/$PROJECT/_apis/pipelines?api-version=$API_VERSION" "$body" | jq -r '.id'
}

# ---------------------------------------------------------------------------
# Branch policies (demo-good only)
# ---------------------------------------------------------------------------

# policy_exists reports whether an enabled, non-deleted policy of type_id
# is already scoped to repo_id's refs/heads/main exactly — mirrors
# internal/collect/azuredevops/repoprotection's own read-side matching
# logic (matchingPolicies/policyScopeMatches) closely enough for this
# script's narrower need (this script only ever creates exact-match,
# single-repo scope entries, never project-wide or prefix ones).
policy_exists() {
	local type_id="$1" repo_id="$2"
	ado_api GET "https://dev.azure.com/$ORG/$PROJECT/_apis/policy/configurations?api-version=$API_VERSION" "" \
		| jq -e --arg t "$type_id" --arg r "$repo_id" '
			any(.value[]?; .isEnabled and (.isDeleted | not) and .type.id == $t
				and ((.settings.scope // []) | any(.repositoryId == $r and .refName == "refs/heads/main")))
		' >/dev/null
}

# ensure_min_reviewers_policy: blocking, minimum 1 approver, scoped to
# repo_id's refs/heads/main specifically (not project-wide) — a
# project-wide scope would apply to demo-bad too, defeating the deliberate
# demo-good/demo-bad contrast this whole script exists to set up.
ensure_min_reviewers_policy() {
	local repo_id="$1"
	if policy_exists "$MIN_REVIEWERS_TYPE_ID" "$repo_id"; then
		log "$GOOD_REPO: minimum-reviewers policy already present"
		return 0
	fi
	log "$GOOD_REPO: creating minimum-reviewers policy (blocking, min 1 approver)"
	local body
	body=$(jq -n --arg t "$MIN_REVIEWERS_TYPE_ID" --arg r "$repo_id" '{
		isEnabled: true,
		isBlocking: true,
		type: {id: $t},
		settings: {
			minimumApproverCount: 1,
			creatorVoteCounts: false,
			scope: [{repositoryId: $r, refName: "refs/heads/main", matchKind: "exact"}]
		}
	}')
	ado_api POST "https://dev.azure.com/$ORG/$PROJECT/_apis/policy/configurations?api-version=$API_VERSION" "$body" >/dev/null
}

ensure_build_validation_policy() {
	local repo_id="$1" definition_id="$2"
	if policy_exists "$BUILD_VALIDATION_TYPE_ID" "$repo_id"; then
		log "$GOOD_REPO: build-validation policy already present"
		return 0
	fi
	log "$GOOD_REPO: creating build-validation policy (blocking, pipeline id=$definition_id)"
	local body
	body=$(jq -n --arg t "$BUILD_VALIDATION_TYPE_ID" --arg r "$repo_id" --argjson defid "$definition_id" '{
		isEnabled: true,
		isBlocking: true,
		type: {id: $t},
		settings: {
			buildDefinitionId: $defid,
			scope: [{repositoryId: $r, refName: "refs/heads/main", matchKind: "exact"}]
		}
	}')
	ado_api POST "https://dev.azure.com/$ORG/$PROJECT/_apis/policy/configurations?api-version=$API_VERSION" "$body" >/dev/null
}

# ---------------------------------------------------------------------------
# Environment + Approval check (project-wide — see the header comment)
# ---------------------------------------------------------------------------

# self_identity_id resolves the authenticated PAT's own VSID via Connection
# Data — the same "use the running admin's own identity as the reviewer"
# trick hack/demo-org-setup.sh's OWNER_ID uses for GitHub, adapted to
# Azure DevOps's identity model (there's no equivalent of GitHub's simple
# `gh api user --jq .id`; connectionData's authenticatedUser.id is the
# established way to get "who am I" as a usable identity reference).
#
# Live finding (2026-07-23, dev.azure.com/seciq): this endpoint rejects the
# stable 7.1 this script uses everywhere else with HTTP 400
# VssInvalidPreviewVersionException ("The -preview flag must be
# supplied") — connectionData is preview-only, so this one call is pinned
# to 7.1-preview.1 directly (a coincidental match with
# CHECKS_API_VERSION's value for an unrelated endpoint — not reused from
# it, to avoid implying a relationship between the two that doesn't exist).
self_identity_id() {
	ado_api GET "https://dev.azure.com/$ORG/_apis/connectiondata?api-version=7.1-preview.1" "" \
		| jq -r '.authenticatedUser.id'
}

environment_id_by_name() {
	local name="$1"
	ado_api GET "https://dev.azure.com/$ORG/$PROJECT/_apis/distributedtask/environments?api-version=$API_VERSION" "" \
		| jq -r --arg n "$name" '.value[] | select(.name==$n) | .id'
}

ensure_environment() {
	local name="$1" id
	id=$(environment_id_by_name "$name")
	if [ -n "$id" ]; then
		log "environment $name already exists (id=$id)"
		printf '%s' "$id"
		return 0
	fi
	log "creating environment $name"
	local body
	body=$(jq -n --arg name "$name" '{name: $name, description: "attestward demo fixture environment (issue #155)"}')
	ado_api POST "https://dev.azure.com/$ORG/$PROJECT/_apis/distributedtask/environments?api-version=$API_VERSION" "$body" \
		| jq -r '.id'
}

# approval_check_exists lists check configurations scoped to env_id (via
# resourceType=environment&resourceId=$env_id — the same narrowing
# envseparation.go's own fetchCheckConfigurations applies) and looks for a
# non-disabled Approval check. The response is Azure DevOps's standard
# {count, value: [...]} list envelope, like every other List call in this
# script — NOT a bare array: an earlier version of this comment mistook
# fetchCheckConfigurations's Go-side []checkConfigurationRaw return type
# for the wire format, when that's actually the GetJSON helper (client.go)
# unwrapping the {count,value} envelope internally before ever handing its
# caller a plain slice. Iterating .[]? instead of .value[]? here would jq
# error on both a populated and an empty envelope, making this probe
# always report "absent" and duplicate the Approval check on every rerun.
approval_check_exists() {
	local env_id="$1"
	ado_api GET "https://dev.azure.com/$ORG/$PROJECT/_apis/pipelines/checks/configurations?resourceType=environment&resourceId=$env_id&api-version=$CHECKS_API_VERSION" "" \
		| jq -e --arg t "$APPROVAL_CHECK_TYPE_ID" '
			any(.value[]?; (.type.id | ascii_downcase) == ($t | ascii_downcase) and (.isDisabled | not))
		' >/dev/null
}

ensure_approval_check() {
	local env_id="$1" approver_id="$2"
	if approval_check_exists "$env_id"; then
		log "environment (id=$env_id): approval check already present"
		return 0
	fi
	log "environment (id=$env_id): creating approval check (approver=$approver_id)"
	local body
	body=$(jq -n --arg tid "$APPROVAL_CHECK_TYPE_ID" --arg envid "$env_id" --arg approver "$approver_id" '{
		settings: {
			approvers: [{id: $approver}],
			executionOrder: "anyOrder",
			minRequiredApprovers: 1,
			instructions: "attestward demo fixture (issue #155)",
			blockedApprovers: []
		},
		timeout: 43200,
		type: {id: $tid, name: "Approval"},
		resource: {type: "environment", id: $envid, name: "production"}
	}')
	ado_api POST "https://dev.azure.com/$ORG/$PROJECT/_apis/pipelines/checks/configurations?api-version=$CHECKS_API_VERSION" "$body" >/dev/null
}

# ---------------------------------------------------------------------------
# Variable groups
# ---------------------------------------------------------------------------

variable_group_exists() {
	local name="$1"
	ado_api GET "https://dev.azure.com/$ORG/$PROJECT/_apis/distributedtask/variablegroups?api-version=$API_VERSION" "" \
		| jq -e --arg n "$name" 'any(.value[]?; .name==$n)' >/dev/null
}

# ensure_variable_group creates name with variables_json (a JSON object
# literal, e.g. '{"API_KEY": {"value": "...", "isSecret": false}}') if it
# doesn't already exist. NOTE the asymmetric URL shape verified against
# Microsoft's own Variablegroups - Add reference: unlike the LIST call
# above (project-scoped URL, matching internal/collect/azuredevops/
# secretshygiene's own read-side path), Add is an ORG-scoped URL —
# variable groups are org-level objects shared into a project via
# variableGroupProjectReferences, not created directly under a project path.
ensure_variable_group() {
	local name="$1" variables_json="$2"
	if variable_group_exists "$name"; then
		log "variable group $name already exists"
		return 0
	fi
	log "creating variable group $name"
	local proj_id body
	proj_id=$(project_id)
	body=$(jq -n \
		--arg name "$name" \
		--argjson vars "$variables_json" \
		--arg pid "$proj_id" \
		--arg pname "$PROJECT" \
		'{
			name: $name,
			description: "attestward demo fixture variable group (issue #155)",
			type: "Vsts",
			variables: $vars,
			variableGroupProjectReferences: [{
				name: $name,
				description: "attestward demo fixture variable group (issue #155)",
				projectReference: {id: $pid, name: $pname}
			}]
		}')
	ado_api POST "https://dev.azure.com/$ORG/_apis/distributedtask/variablegroups?api-version=$API_VERSION" "$body" >/dev/null
}

# ---------------------------------------------------------------------------
# Annotated tag (demo-good only)
# ---------------------------------------------------------------------------

tag_exists() {
	local repo_id="$1" tag_name="$2" resp
	resp=$(ado_api GET "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories/$repo_id/refs?filter=tags/$tag_name&api-version=$API_VERSION" "")
	[ "$(printf '%s' "$resp" | jq -r '(.value // []) | length')" -gt 0 ]
}

# ensure_tag creates an ANNOTATED tag (a real tag object, not a lightweight
# ref): Annotated Tags - Create makes the tag object itself (its response
# .objectId is the TAG OBJECT's own SHA, distinct from commit_sha —
# verified against Microsoft's own sample response, whose .name field even
# comes back pre-prefixed "refs/tags/..."). A separate Refs - Update Refs
# call was originally added here on the assumption that creating the tag
# object doesn't also point refs/tags/$tag_name at it — CONFIRMED WRONG by
# the live run against dev.azure.com/seciq (2026-07-23): Annotated Tags -
# Create creates the ref itself as part of the same operation, so the
# Refs - Update Refs call below is a redundant no-op in practice, not a
# defensive step for a real gap. It's kept anyway as a fallback for the
# unconfirmed case where a future/different Azure DevOps behavior doesn't
# create the ref automatically — the re-probe immediately below already
# skips it whenever the ref already exists (the observed real path), and
# the log line names exactly that:
# "tag v1.0.0 ref already exists after Annotated Tags - Create".
#
# Neither call's HTTP status alone would prove the ref actually ends up
# existing, so this re-probes tag_exists after each rather than trusting a
# 200: if a future response shape ever needed the Refs - Update Refs
# fallback for real, Refs - Update Refs returns HTTP 200 even for a
# REJECTED individual ref update — success/updateStatus live in the
# response BODY, per ref, not the HTTP status, so a bare `>/dev/null` on
# that call could silently no-op.
ensure_tag() {
	local repo_id="$1" tag_name="$2" commit_sha="$3" message="$4"
	if tag_exists "$repo_id" "$tag_name"; then
		log "tag $tag_name already exists on $GOOD_REPO"
		return 0
	fi
	log "creating annotated tag $tag_name on $GOOD_REPO (commit $commit_sha)"
	local tag_body tag_obj_id ref_body
	tag_body=$(jq -n --arg name "$tag_name" --arg sha "$commit_sha" --arg msg "$message" \
		'{name: $name, taggedObject: {objectId: $sha}, message: $msg}')
	tag_obj_id=$(ado_api POST "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories/$repo_id/annotatedtags?api-version=$API_VERSION" "$tag_body" \
		| jq -r '.objectId')

	if tag_exists "$repo_id" "$tag_name"; then
		log "tag $tag_name ref already exists after Annotated Tags - Create — skipping the separate Refs - Update Refs call"
		return 0
	fi

	ref_body=$(jq -n --arg name "refs/tags/$tag_name" --arg newid "$tag_obj_id" --arg zero "$ZERO_OBJECT_ID" \
		'[{name: $name, oldObjectId: $zero, newObjectId: $newid}]')
	ado_api POST "https://dev.azure.com/$ORG/$PROJECT/_apis/git/repositories/$repo_id/refs?api-version=$API_VERSION" "$ref_body" >/dev/null

	if ! tag_exists "$repo_id" "$tag_name"; then
		echo "FAILED: refs/tags/$tag_name still does not exist after Refs - Update Refs reported HTTP 200 — the per-ref update was likely rejected (see success/updateStatus in that call's response body)" >&2
		exit 1
	fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
	local good_id="$1" bad_id="$2" pipeline_id="$3" env_id="$4"
	printf '\n==> summary\n'
	printf '%-38s %s\n' "org" "$ORG"
	printf '%-38s %s\n' "project" "$PROJECT"
	printf '%-38s %s\n' "demo-good repo id" "$good_id"
	printf '%-38s %s\n' "demo-bad repo id" "$bad_id"
	printf '%-38s %s\n' "demo-good pipeline id (demo-good-ci)" "$pipeline_id"
	printf '%-38s %s\n' "production environment id" "$env_id"
	printf '%-38s %s\n' "demo-good branch policies" "minimum-reviewers (blocking, min 1) + build-validation (blocking)"
	printf '%-38s %s\n' "demo-good variable group" "demo-good-vars (DB_PASSWORD, secret)"
	printf '%-38s %s\n' "demo-bad variable group" "demo-bad-vars (API_KEY, plaintext)"
	printf '%-38s %s\n' "demo-good tag" "v1.0.0 (annotated)"
	printf '\nverify with: attestward scan --platform azuredevops --org %s --project %s --repo %s --repo %s --out /tmp/ado-demo-scan\n' \
		"$ORG" "$PROJECT" "$GOOD_REPO" "$BAD_REPO"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
	require_env
	ensure_project

	local good_id bad_id
	good_id=$(ensure_repo "$GOOD_REPO")
	bad_id=$(ensure_repo "$BAD_REPO")

	local good_commit_sha
	good_commit_sha=$(push_good_initial_commit "$good_id")
	push_bad_initial_commit "$bad_id"

	ensure_default_branch "$good_id"
	ensure_default_branch "$bad_id"

	local pipeline_id
	pipeline_id=$(ensure_pipeline "demo-good-ci" "$good_id" "/azure-pipelines.yml")

	ensure_min_reviewers_policy "$good_id"
	ensure_build_validation_policy "$good_id" "$pipeline_id"

	local approver_id env_id
	approver_id=$(self_identity_id)
	env_id=$(ensure_environment "production")
	ensure_approval_check "$env_id" "$approver_id"

	ensure_variable_group "demo-good-vars" '{"DB_PASSWORD": {"value": "demo-not-a-real-secret", "isSecret": true}}'
	ensure_variable_group "demo-bad-vars" '{"API_KEY": {"value": "demo-not-a-real-key", "isSecret": false}}'

	ensure_tag "$good_id" "v1.0.0" "$good_commit_sha" \
		"Demo release fixture for attestward's Azure DevOps C07 provenance collector (issue #155)."

	print_summary "$good_id" "$bad_id" "$pipeline_id" "$env_id"
}

main "$@"
