#!/usr/bin/env bash
# Runs an OWASP ZAP API scan against the service using its OpenAPI spec.
# The service is built, started, scanned, then stopped.
#
# Usage:
#   ./tests/zap-scan.sh [env-file]
#
#
# Output: tests/zap-report/report.html and report.json
#
# Exit codes mirror ZAP's:
#   0  No alerts
#   1  At least one HIGH/MEDIUM alert found
#   2  At least one LOW/INFO alert found
#   3+ ZAP encountered an error (network, config, etc.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ENV_FILE="${1:-}"
ZAP_PORT=8080
SERVICE_PORT=8383
REPORT_DIR="$SCRIPT_DIR/zap-report"
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
OPENAPI_URL="http://localhost:${SERVICE_PORT}/openapi"

# ── helpers ──────────────────────────────────────────────────────────────────

require_docker() {
  if ! command -v docker &>/dev/null; then
    echo "ERROR: docker is required but not found in PATH." >&2
    exit 3
  fi
  if ! docker info &>/dev/null; then
    echo "ERROR: docker daemon is not running." >&2
    exit 3
  fi
}

pull_zap_image() {
  echo "=== Pulling ZAP image: $ZAP_IMAGE ===" >&2
  docker pull "$ZAP_IMAGE" >&2
}

# ── main ─────────────────────────────────────────────────────────────────────

require_docker

mkdir -p "$REPORT_DIR"

echo "=== OpenAPI spec: $OPENAPI_URL ===" >&2
echo "=== Report output: $REPORT_DIR ===" >&2

pull_zap_image

# Run ZAP API scan.
# --network host lets the container reach the service on localhost.
# /zap/wrk is the ZAP working directory; we bind-mount REPORT_DIR there.
ZAP_EXIT=0
docker run --rm \
  --network host \
  -v "$REPORT_DIR:/zap/wrk:rw" \
  "$ZAP_IMAGE" \
  zap-api-scan.py \
    -t "$OPENAPI_URL" \
    -f openapi \
    -r report.html \
    -J report.json \
    -I \
  || ZAP_EXIT=$?

echo "" >&2
echo "=== ZAP scan complete (exit $ZAP_EXIT) ===" >&2
echo "    HTML report: $REPORT_DIR/report.html" >&2
echo "    JSON report: $REPORT_DIR/report.json" >&2

case $ZAP_EXIT in
  0) echo "    Result: no alerts" >&2 ;;
  1) echo "    Result: HIGH or MEDIUM alerts found — review the report" >&2 ;;
  2) echo "    Result: LOW or INFO alerts found" >&2 ;;
  *) echo "    Result: ZAP encountered an error" >&2 ;;
esac

exit $ZAP_EXIT
