#!/usr/bin/env bash
# demo_api.sh — end-to-end showcase of Mode 2 (API mode).
#
# Runs the closed loop live:
#   1. External Python service connects to Splunk via REST API
#   2. Pulls events from index=main
#   3. Evaluates them against the Sigma engine (outside Splunk)
#   4. Writes alerts BACK into Splunk (index=sigma_alerts)
#   5. Queries Splunk to show the alerts are now SPL-queryable
#
# Prereqs:
#   - Splunk running locally (http://localhost:8000)
#   - Sample data loaded: splunk add oneshot samples/attack_samples.jsonl ...
#   - SPLUNK_USERNAME and SPLUNK_PASSWORD exported
#
# Usage: bash scripts/demo_api.sh

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SPLUNK="${SPLUNK_HOME:-/Applications/Splunk}/bin/splunk"
INDEX="sigma_alerts"

: "${SPLUNK_USERNAME:?set SPLUNK_USERNAME}"
: "${SPLUNK_PASSWORD:?set SPLUNK_PASSWORD}"

BOLD=$'\033[1m'; DIM=$'\033[2m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
step() { echo; echo "${CYAN}${BOLD}▶ $1${RESET}"; }

step "1/4  Ensuring target index '${INDEX}' exists"
if "$SPLUNK" list index -auth "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" 2>/dev/null \
     | awk '{print $1}' | grep -qx "$INDEX"; then
  echo "${DIM}    already exists${RESET}"
else
  "$SPLUNK" add index "$INDEX" -auth "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" >/dev/null
  echo "${DIM}    created${RESET}"
fi

step "2/4  Clearing previous demo alerts from '${INDEX}'"
# | delete marks events non-searchable without restarting Splunk.
# Requires the 'can_delete' capability on the running user.
#   Grant it once with:  splunk edit user <name> -role admin -role can_delete
DELETE_OUT=$("$SPLUNK" search "index=${INDEX} | delete" \
  -earliest_time '-30d' -latest_time 'now' \
  -auth "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" -preview false 2>&1 || true)
if echo "$DELETE_OUT" | grep -q "events successfully deleted"; then
  N=$(echo "$DELETE_OUT" | grep -oE '[0-9]+ events successfully deleted' | awk '{print $1}')
  echo "${DIM}    cleared ${N} prior event(s)${RESET}"
elif echo "$DELETE_OUT" | grep -q "insufficient privileges"; then
  echo "${DIM}    (skip — user lacks can_delete role; alerts will accumulate)${RESET}"
else
  echo "${DIM}    (skipped)${RESET}"
fi

step "3/4  Running sigma_watch — external service calling Splunk's REST API"
python3 "$REPO/scripts/sigma_watch.py" --once --output-index "$INDEX"

step "4/4  Verifying alerts landed — querying via SPL"
echo "${DIM}    (waiting 3s for Splunk to index the written events)${RESET}"
sleep 3
"$SPLUNK" search \
  "index=${INDEX} | stats count by sigma_rule_title, sigma_level | sort -sigma_level -count" \
  -auth "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" -preview false

echo
echo "${BOLD}Closed loop demonstrated:${RESET}"
echo "  external Python service  →  Splunk REST API  →  alerts indexed  →  queryable via SPL"
echo
echo "  Open Splunk Web to see them: http://localhost:8000"
echo "  SPL to run:                  index=${INDEX}"
