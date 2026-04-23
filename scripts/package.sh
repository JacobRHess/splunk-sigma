#!/usr/bin/env bash
# Build a .tgz of the Splunk app suitable for Splunkbase upload or splunk install.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_SRC="$REPO_ROOT/app"
DIST="$REPO_ROOT/dist"
VERSION=$(grep '^version' "$APP_SRC/default/app.conf" | head -1 | awk -F'= ' '{print $2}')
OUT="$DIST/splunk-sigma-${VERSION}.tgz"

mkdir -p "$DIST"

# Splunk expects the archive to contain a top-level directory named after the app id.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cp -R "$APP_SRC" "$TMP/splunk-sigma"
find "$TMP/splunk-sigma" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find "$TMP/splunk-sigma" -name "*.pyc" -delete

tar czf "$OUT" -C "$TMP" splunk-sigma
echo "Built: $OUT"
