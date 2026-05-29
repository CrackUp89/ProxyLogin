#!/usr/bin/env bash
# Creates a Cognito user pool + app client + a permanent test user.
# Writes .generated.env (service config) and http/http-client.private.env.json (IntelliJ/httpyac vars).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../common/aws.sh"

POOL_NAME="proxylogin-test-basic-auth"
CLIENT_NAME="proxylogin-test-basic-auth-client"
TEST_USER="test-basic@proxylogin.test"
TEST_PASSWORD="TestBasic1!"
TEST_PORT=8484

echo "=== Setup: 01_basic_auth ==="

POOL_ID=$(get_or_create_user_pool "$POOL_NAME" "OFF")

read -r CLIENT_ID CLIENT_SECRET <<< "$(get_or_create_user_pool_client "$POOL_ID" "$CLIENT_NAME")"

ensure_test_user "$POOL_ID" "$TEST_USER" "$TEST_PASSWORD" "true"

REGION="${AWS_REGION:-eu-west-1}"

cat > "$SCRIPT_DIR/.generated.env" <<EOF
AWS_REGION=${REGION}
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}
COGNITO_USER_POOL_ID=${POOL_ID}
COGNITO_CLIENT_ID=${CLIENT_ID}
COGNITO_CLIENT_SECRET=${CLIENT_SECRET}
COGNITO_JWKS_ISSUER=https://cognito-idp.${REGION}.amazonaws.com/${POOL_ID}
COGNITO_JWKS_SIGNING_KEY_URL=https://cognito-idp.${REGION}.amazonaws.com/${POOL_ID}/.well-known/jwks.json
TOKEN_MASQUERADE=false
TOKEN_COOKIES_ENABLED=false
STORAGE_TYPE=memory
HTTP_PORT=${TEST_PORT}
LOGGING_DEV=true
TEST_USERNAME=${TEST_USER}
TEST_PASSWORD=${TEST_PASSWORD}
EOF

cat > "$SCRIPT_DIR/http/http-client.private.env.json" <<EOF
{
  "test": {
    "host": "http://localhost:${TEST_PORT}",
    "username": "${TEST_USER}",
    "password": "${TEST_PASSWORD}"
  }
}
EOF

echo "=== Setup complete. Run run.sh to execute tests. ==="
