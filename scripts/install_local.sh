#!/usr/bin/env bash
# Symlink the app into Splunk's app directory for live development.
# Edits to files in ./app take effect after a Splunk restart (or debug/refresh endpoint).

set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/Applications/Splunk}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_SRC="$REPO_ROOT/app"
APP_DST="$SPLUNK_HOME/etc/apps/splunk-sigma"

if [[ ! -d "$SPLUNK_HOME" ]]; then
  echo "ERROR: SPLUNK_HOME=$SPLUNK_HOME does not exist. Install Splunk Enterprise first."
  echo "  https://www.splunk.com/en_us/download/splunk-enterprise.html"
  exit 1
fi

if [[ -e "$APP_DST" ]]; then
  echo "Removing existing $APP_DST"
  rm -rf "$APP_DST"
fi

ln -s "$APP_SRC" "$APP_DST"
echo "Linked: $APP_DST -> $APP_SRC"
echo
echo "Next steps:"
echo "  1) $SPLUNK_HOME/bin/splunk restart"
echo "  2) Open http://localhost:8000 and log in"
echo "  3) Load sample data: $SPLUNK_HOME/bin/splunk add oneshot $REPO_ROOT/samples/attack_samples.jsonl -sourcetype _json -index main"
echo "  4) Run: index=main | sigma rules=\"app:*\""
