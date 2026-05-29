#!/usr/bin/env bash
# Builds the service, starts it, runs the .http scenario, then stops it.
# Requires: setup.sh run first; npm install run in tests/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../common/service.sh"

GENERATED_ENV="$SCRIPT_DIR/.generated.env"

if [[ ! -f "$GENERATED_ENV" ]]; then
  echo "Run setup.sh first." >&2
  exit 1
fi

trap cleanup_on_exit EXIT

build_service
start_service "$GENERATED_ENV"

echo "=== Running HTTP scenario: 01_basic_auth ==="
cd "$SCRIPT_DIR/http"
npx httpyac run "*.http" --env test --output short

echo "=== Scenario complete ==="
