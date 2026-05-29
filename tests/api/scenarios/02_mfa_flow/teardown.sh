#!/usr/bin/env bash
# Removes the test user and (optionally) the user pool.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../common/aws.sh"

GENERATED_ENV="$SCRIPT_DIR/.generated.env"
DELETE_POOL=false
[[ "${1:-}" == "--delete-pool" ]] && DELETE_POOL=true

if [[ ! -f "$GENERATED_ENV" ]]; then
  echo "No .generated.env found; nothing to tear down." >&2
  exit 0
fi

source "$GENERATED_ENV"

echo "=== Teardown: 02_mfa_flow ==="

delete_test_user "$COGNITO_USER_POOL_ID" "$TEST_USERNAME"

if $DELETE_POOL; then
  delete_user_pool "$COGNITO_USER_POOL_ID"
fi

rm -f "$GENERATED_ENV"
rm -f "$SCRIPT_DIR/http/http-client.private.env.json"

echo "=== Teardown complete ==="
