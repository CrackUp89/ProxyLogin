#!/usr/bin/env bash
set -euo pipefail

AWS_REGION="${AWS_REGION:-eu-west-1}"

find_user_pool_id() {
  local pool_name="$1"
  aws cognito-idp list-user-pools --max-results 60 --region "$AWS_REGION" \
    --query "UserPools[?Name=='${pool_name}'].Id" \
    --output text 2>/dev/null
}

create_user_pool() {
  local pool_name="$1"
  local mfa_config="${2:-OFF}"
  aws cognito-idp create-user-pool \
    --pool-name "$pool_name" \
    --policies '{"PasswordPolicy":{"MinimumLength":8,"RequireUppercase":true,"RequireLowercase":true,"RequireNumbers":true,"RequireSymbols":false}}' \
    --username-attributes "email" \
    --auto-verified-attributes "email" \
    --mfa-configuration "$mfa_config" \
    --region "$AWS_REGION" \
    --query "UserPool.Id" \
    --output text
}

get_or_create_user_pool() {
  local pool_name="$1"
  local mfa_config="${2:-OFF}"
  local pool_id
  pool_id=$(find_user_pool_id "$pool_name")
  if [[ -z "$pool_id" || "$pool_id" == "None" ]]; then
    echo "Creating user pool: $pool_name" >&2
    pool_id=$(create_user_pool "$pool_name" "$mfa_config")
  else
    echo "Using existing user pool: $pool_name ($pool_id)" >&2
  fi
  echo "$pool_id"
}

find_user_pool_client_id() {
  local pool_id="$1"
  local client_name="$2"
  aws cognito-idp list-user-pool-clients \
    --user-pool-id "$pool_id" \
    --max-results 60 \
    --region "$AWS_REGION" \
    --query "UserPoolClients[?ClientName=='${client_name}'].ClientId" \
    --output text 2>/dev/null
}

get_or_create_user_pool_client() {
  local pool_id="$1"
  local client_name="$2"
  local client_id
  client_id=$(find_user_pool_client_id "$pool_id" "$client_name")
  if [[ -z "$client_id" || "$client_id" == "None" ]]; then
    echo "Creating app client: $client_name" >&2
    local result
    result=$(aws cognito-idp create-user-pool-client \
      --user-pool-id "$pool_id" \
      --client-name "$client_name" \
      --explicit-auth-flows "ALLOW_USER_PASSWORD_AUTH" "ALLOW_REFRESH_TOKEN_AUTH" \
      --generate-secret \
      --region "$AWS_REGION" \
      --query "UserPoolClient.{ClientId:ClientId,ClientSecret:ClientSecret}" \
      --output json)
    local client_secret
    client_id=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['ClientId'])")
    client_secret=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['ClientSecret'])")
    echo "${client_id} ${client_secret}"
  else
    echo "Using existing app client: $client_name ($client_id)" >&2
    local client_secret
    client_secret=$(aws cognito-idp describe-user-pool-client \
      --user-pool-id "$pool_id" \
      --client-id "$client_id" \
      --region "$AWS_REGION" \
      --query "UserPoolClient.ClientSecret" \
      --output text)
    echo "${client_id} ${client_secret}"
  fi
}

# Creates a user. permanent=true sets a permanent password; permanent=false leaves temp password.
ensure_test_user() {
  local pool_id="$1"
  local username="$2"
  local password="$3"
  local permanent="${4:-true}"
  local user_status
  user_status=$(aws cognito-idp admin-get-user \
    --user-pool-id "$pool_id" \
    --username "$username" \
    --region "$AWS_REGION" \
    --query "UserStatus" \
    --output text 2>/dev/null || echo "NOT_FOUND")
  if [[ "$user_status" == "NOT_FOUND" ]]; then
    echo "Creating user: $username" >&2
    aws cognito-idp admin-create-user \
      --user-pool-id "$pool_id" \
      --username "$username" \
      --message-action SUPPRESS \
      --region "$AWS_REGION" > /dev/null
  else
    echo "User already exists: $username (status: $user_status)" >&2
  fi
  local set_pw_args=(
    --user-pool-id "$pool_id"
    --username "$username"
    --password "$password"
    --region "$AWS_REGION"
  )
  [[ "$permanent" == "true" ]] && set_pw_args+=(--permanent)
  aws cognito-idp admin-set-user-password "${set_pw_args[@]}"
  echo "Password set for: $username (permanent=$permanent)" >&2
}

delete_test_user() {
  local pool_id="$1"
  local username="$2"
  aws cognito-idp admin-delete-user \
    --user-pool-id "$pool_id" \
    --username "$username" \
    --region "$AWS_REGION" 2>/dev/null && echo "Deleted user: $username" >&2 || true
}

delete_user_pool() {
  local pool_id="$1"
  local clients
  clients=$(aws cognito-idp list-user-pool-clients \
    --user-pool-id "$pool_id" \
    --max-results 60 \
    --region "$AWS_REGION" \
    --query "UserPoolClients[].ClientId" \
    --output text 2>/dev/null || true)
  for client_id in $clients; do
    aws cognito-idp delete-user-pool-client \
      --user-pool-id "$pool_id" \
      --client-id "$client_id" \
      --region "$AWS_REGION" 2>/dev/null || true
  done
  aws cognito-idp delete-user-pool \
    --user-pool-id "$pool_id" \
    --region "$AWS_REGION" 2>/dev/null && echo "Deleted user pool: $pool_id" >&2 || true
}
