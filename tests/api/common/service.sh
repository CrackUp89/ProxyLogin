#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$PROJECT_DIR/tests/bin/proxylogin"
SERVICE_PID_FILE="/tmp/proxylogin-test-$$.pid"
SERVICE_LOG_FILE="/tmp/proxylogin-test-$$.log"

build_service() {
  echo "Building service..." >&2
  (cd "$PROJECT_DIR" && go build -o "$BINARY" ./cmd/proxylogin)
  echo "Built: $BINARY" >&2
}

start_service() {
  local env_file="${1:-}"
  if [[ -n "$env_file" && -f "$env_file" ]]; then
    set -a; source "$env_file"; set +a
  fi
  "$BINARY" serve > "$SERVICE_LOG_FILE" 2>&1 &
  local pid=$!
  echo "$pid" > "$SERVICE_PID_FILE"
  local port="${HTTP_PORT:-80}"
  echo "Waiting for service on port $port (PID $pid)..." >&2
  local retries=0
  until curl -sf "http://localhost:${port}/v1/health" > /dev/null 2>&1; do
    sleep 0.5
    retries=$((retries + 1))
    if [[ $retries -ge 30 ]]; then
      echo "Service failed to start after 15s. Log:" >&2
      cat "$SERVICE_LOG_FILE" >&2
      exit 1
    fi
  done
  echo "Service ready on port $port" >&2
}

stop_service() {
  if [[ -f "$SERVICE_PID_FILE" ]]; then
    local pid
    pid=$(cat "$SERVICE_PID_FILE")
    kill "$pid" 2>/dev/null || true
    rm -f "$SERVICE_PID_FILE"
    echo "Service stopped (PID $pid)" >&2
  fi
}

# Call from traps so the service is always cleaned up.
cleanup_on_exit() {
  stop_service
}
