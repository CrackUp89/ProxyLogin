#!/usr/bin/env bash
# Creates a Cognito user pool with MFA=OPTIONAL + app client + a test user with a
# TEMPORARY password (triggers NEW_PASSWORD_REQUIRED on first login).
# The service is started with COGNITO_ENFORCE_MFA=true so after the password challenge
# the server requires MFA setup before issuing tokens.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../common/aws.sh"

POOL_NAME="proxylogin-test-mfa-flow"
CLIENT_NAME="proxylogin-test-mfa-flow-client"
TEST_USER="test-mfa@proxylogin.test"
TEMP_PASSWORD="TempMFA1!"
NEW_PASSWORD="NewMFA2@"
TEST_PORT=8485

echo "=== Setup: 02_mfa_flow ==="

POOL_ID=$(get_or_create_user_pool "$POOL_NAME" "OPTIONAL")

read -r CLIENT_ID CLIENT_SECRET <<< "$(get_or_create_user_pool_client "$POOL_ID" "$CLIENT_NAME")"

# Temporary password — Cognito will issue NEW_PASSWORD_REQUIRED on first login.
ensure_test_user "$POOL_ID" "$TEST_USER" "$TEMP_PASSWORD" "false"

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
COGNITO_ENFORCE_MFA=true
TOKEN_MASQUERADE=false
TOKEN_COOKIES_ENABLED=false
STORAGE_TYPE=memory
HTTP_PORT=${TEST_PORT}
LOGGING_DEV=true
TEST_USERNAME=${TEST_USER}
TEST_TEMP_PASSWORD=${TEMP_PASSWORD}
TEST_NEW_PASSWORD=${NEW_PASSWORD}
EOF

cat > "$SCRIPT_DIR/http/http-client.private.env.json" <<EOF
{
  "test": {
    "host": "http://localhost:${TEST_PORT}",
    "username": "${TEST_USER}",
    "temp_password": "${TEMP_PASSWORD}",
    "new_password": "${NEW_PASSWORD}"
  }
}
EOF

echo "=== Setup complete. Run run.sh to execute tests. ==="
