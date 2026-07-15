#!/bin/bash
# Manage AORUS (Windows x64 CI runner, spyros-aorus-ssdf): a physical Windows PC
# kept powered off between uses (~300W draw). Mirrors the interface and safety
# rules of sentryrecovery's tools/arm64_vm.sh, adapted for a real machine (Wake-
# on-LAN + SSH shutdown) instead of a UTM VM (utmctl start/stop).
#
# Usage:
#   tools/aorus.sh on         # WOL + wait for SSH + brief runner-startup buffer
#   tools/aorus.sh off        # graceful Windows shutdown
#   tools/aorus.sh status     # network reachability + best-effort runner status
#   tools/aorus.sh keepalive  # on -> off
#
# GitHub auto-removes a self-hosted runner after 14 days offline (painful to
# re-register), so run `keepalive` on a schedule — see
# .github/workflows/aorus-keepalive.yaml.
#
# `on` does NOT poll GitHub's API to confirm the runner has checked in
# (see runner_status()'s own doc comment for why: GET .../actions/runners
# returns a hard 403 "Resource not accessible by integration" for the
# ephemeral GITHUB_TOKEN, confirmed directly in CI logs — no permissions:
# entry can fix this, "administration" isn't a grantable GITHUB_TOKEN
# scope at all). Instead it waits for SSH reachability, then a fixed
# buffer for the Windows service to start — and leans on GitHub's own
# job-to-runner matching to do the rest: build-windows's `needs:
# [wake-aorus]` already means it queues until spyros-aorus-ssdf actually
# picks up the job, however long the service takes to connect. That's
# the same mechanism that would decide readiness anyway; polling a
# second, less-authoritative source added complexity without adding
# correctness.
set -euo pipefail

MAC="D8:5E:D3:5D:CB:C7"     # onboard 1 GbE Intel I225-V — WOL-only, no host IP
BCAST="10.0.0.255"
HOST="10.0.0.2"             # 10 GbE X540-AT2 — no WOL support, but carries SSH
SSH_USER="Administrator"
REPO="sioakim/ssdf"
RUNNER="spyros-aorus-ssdf"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"
RUNNER_STARTUP_BUFFER="${RUNNER_STARTUP_BUFFER:-45}"

ssh_aorus() { ssh -o ConnectTimeout=15 -o BatchMode=yes "$SSH_USER@$HOST" "$@" 2>/dev/null; }

# Send the magic packet (6x0xFF + 16xMAC, UDP broadcast) via python3 — the brew
# `wakeonlan` perl script is broken on macOS 26 (stale perl5.30 shebang).
send_magic_packet() {
	MAC="$MAC" BCAST="$BCAST" python3 - <<'EOF'
import os, socket
mac = bytes.fromhex(os.environ["MAC"].replace(":", ""))
pkt = b"\xff" * 6 + mac * 16
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
for port in (9, 7):
	s.sendto(pkt, (os.environ["BCAST"], port))
s.close()
EOF
}

# Gate on network reachability first, not runner status alone: right after a
# stop, GitHub still reports the runner "online" for ~1 min (heartbeat
# timeout), so polling runner status alone can return a STALE online before
# the box has actually rebooted.
#
# Resends the magic packet every ~30s while waiting, not just once at the
# start: WOL is fire-and-forget UDP, and a packet sent too soon after a
# shutdown (before the NIC has settled into its WOL-listening low-power
# state) can be silently missed — observed once in practice, where a wake
# immediately following a shutdown never got a second chance until manually
# resent. A one-shot send has no way to recover from that; periodic resends
# do.
wait_reachable() {
	local timeout="$1" waited=0
	while [ "$waited" -lt "$timeout" ]; do
		ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$HOST" 'echo ok' >/dev/null 2>&1 && return 0
		if [ $((waited % 30)) -eq 0 ] && [ "$waited" -gt 0 ]; then
			send_magic_packet
		fi
		sleep 5
		waited=$((waited + 5))
	done
	return 1
}

wait_unreachable() {
	local timeout="$1" waited=0
	while [ "$waited" -lt "$timeout" ]; do
		ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$HOST" 'echo ok' >/dev/null 2>&1 || return 0
		sleep 5
		waited=$((waited + 5))
	done
	return 1
}

# Best-effort, interactive-debugging use only — `on`/`keepalive` never call
# this (see the file-level doc comment for why: it hard-403s for the
# ephemeral GITHUB_TOKEN CI actually has available, confirmed directly:
# "Resource not accessible by integration"; no permissions: entry can fix
# it). Works fine when GITHUB_TOKEN is a real, broader-scoped credential
# (e.g. `GITHUB_TOKEN=$(gh auth token) tools/aorus.sh status` from an
# interactive shell that's already run `gh auth login`).
runner_status() {
	if [ -n "${GITHUB_TOKEN:-}" ]; then
		local http_code body
		body=$(curl -s -w '\n%{http_code}' -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
			"https://api.github.com/repos/$REPO/actions/runners" 2>/dev/null)
		http_code=$(echo "$body" | tail -1)
		body=$(echo "$body" | sed '$d')
		if [ "$http_code" != "200" ]; then
			echo "runner_status: GET /actions/runners returned HTTP $http_code: $body" >&2
			echo "unknown"
			return
		fi
		local result
		# Defensive JSON parsing: a malformed/empty body must never make this
		# pipeline exit non-zero — under this script's set -e -o pipefail,
		# that would silently kill the whole script mid-poll rather than let
		# the caller's retry loop try again.
		result=$(echo "$body" | RUNNER="$RUNNER" python3 -c '
import json, os, sys
try:
	data = json.load(sys.stdin)
	for r in data.get("runners", []):
		if r["name"] == os.environ["RUNNER"]:
			print(r["status"])
			sys.exit()
	print("unknown")
except Exception as e:
	print(f"unknown (parse error: {e})")
')
		if [ "$result" != "online" ]; then
			echo "runner_status: HTTP 200 but parsed result was '$result', not online. Raw body: $body" >&2
		fi
		echo "$result"
		return
	fi
	echo "unknown"
}

case "${1:-status}" in
on)
	# Emits a COLD_WOKE=true/false line — a caller (the CI wrapper step) must
	# capture this and skip `off` later when false: "already up" means
	# something else is using the box, and this session didn't earn the
	# right to shut it down out from under whoever that is.
	if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$HOST" 'echo ok' >/dev/null 2>&1; then
		echo "AORUS already up (SSH reachable) — not sending a wake packet"
		cold_woke=false
	else
		echo "Sending magic packet to $MAC via $BCAST..."
		send_magic_packet
		sleep 3
		send_magic_packet # UDP — send twice for good measure
		echo "  waiting for SSH (timeout ${BOOT_TIMEOUT}s)..."
		wait_reachable "$BOOT_TIMEOUT" || {
			echo "  AORUS did not become SSH-reachable — check power LED, 1 GbE link light, BIOS ErP (must be Disabled for S5 WOL)" >&2
			exit 1
		}
		cold_woke=true
		echo "  SSH reachable; waiting ${RUNNER_STARTUP_BUFFER}s for the runner service to start (not API-confirmed — see file-level doc comment)..."
		sleep "$RUNNER_STARTUP_BUFFER"
	fi
	echo "COLD_WOKE=${cold_woke}"
	;;

off)
	echo "Shutting down AORUS..."
	ssh_aorus 'shutdown /s /t 5' || true
	wait_unreachable 60 || echo "  still responding after 60s — shutdown may be slow, check manually" >&2
	# Extra settle time before returning: "unreachable via SSH" (OS shut down)
	# isn't the same moment as "NIC has dropped into its WOL-listening
	# low-power state" — a wake attempted too soon after this point risks
	# the exact missed-magic-packet failure wait_reachable's resend logic
	# exists to paper over, but it's cheaper to just not race it here.
	sleep 15
	echo "  AORUS is down"
	;;

status)
	if ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_USER@$HOST" 'echo ok' >/dev/null 2>&1; then
		echo "AORUS: reachable"
	else
		echo "AORUS: unreachable (likely powered off)"
	fi
	echo "runner '$RUNNER': $(runner_status)"
	;;

keepalive)
	# Boot (giving the runner service RUNNER_STARTUP_BUFFER seconds to start
	# and check in with GitHub, resetting the 14-day offline timer), then
	# power off — but only if this call did the waking. If AORUS was
	# already up, someone else is using it: refreshing the registration by
	# booting is still useful, but powering off out from under them is not
	# this script's call to make.
	echo "keepalive: booting to refresh the runner registration..."
	on_output=$("$0" on)
	echo "$on_output"
	if echo "$on_output" | grep -q "COLD_WOKE=true"; then
		echo "  powering off..."
		"$0" off
	else
		echo "  AORUS was already up — leaving it running, not this script's box to power off"
	fi
	echo "  done"
	;;

*)
	echo "usage: $0 {on|off|status|keepalive}" >&2
	exit 2
	;;
esac
