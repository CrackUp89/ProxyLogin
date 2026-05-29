#!/usr/bin/env bash
# Creates:
#   - IAM policy + user for the Jenkins EC2 Plugin (to provision build agents)
#   - IAM policy + instance profile/role for the build agent instances (to run tests)
#
# Usage:
#   AWS_REGION=eu-west-1 bash setup.sh
#
# After running, add the printed access key to Jenkins:
#   Manage Jenkins → Credentials → (global) → Add Credentials
#   Kind: AWS Credentials
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

JENKINS_USER="jenkins-ec2-plugin"
AGENT_ROLE="jenkins-proxy-login-build-agent"
EC2_POLICY_NAME="JenkinsEC2PluginPolicy"
AGENT_POLICY_NAME="JenkinsProxyLoginBuildAgentPolicy"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "AWS account: $ACCOUNT_ID"

# ── EC2 Plugin policy + user ──────────────────────────────────────────────────

echo ""
echo "=== Creating EC2 Plugin IAM user: $JENKINS_USER ==="

aws iam create-policy \
  --policy-name "$EC2_POLICY_NAME" \
  --policy-document "file://$SCRIPT_DIR/ec2-plugin-policy.json" \
  --description "Allows Jenkins EC2 Plugin to provision build agent instances" \
  2>/dev/null && echo "Policy created: $EC2_POLICY_NAME" \
  || echo "Policy already exists: $EC2_POLICY_NAME"

EC2_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${EC2_POLICY_NAME}"

aws iam create-user --user-name "$JENKINS_USER" \
  2>/dev/null && echo "User created: $JENKINS_USER" \
  || echo "User already exists: $JENKINS_USER"

aws iam attach-user-policy \
  --user-name "$JENKINS_USER" \
  --policy-arn "$EC2_POLICY_ARN"
echo "Policy attached to user."

echo ""
echo "Generating access key for $JENKINS_USER ..."
KEY_OUTPUT=$(aws iam create-access-key --user-name "$JENKINS_USER")
ACCESS_KEY_ID=$(echo "$KEY_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['AccessKey']['AccessKeyId'])")
SECRET_KEY=$(echo "$KEY_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['AccessKey']['SecretAccessKey'])")

echo ""
echo "┌─────────────────────────────────────────────────────────────────┐"
echo "│  Add these to Jenkins → Credentials → AWS Credentials           │"
echo "│  Access Key ID:     $ACCESS_KEY_ID"
echo "│  Secret Access Key: $SECRET_KEY"
echo "└─────────────────────────────────────────────────────────────────┘"
echo ""
echo "IMPORTANT: save the secret key now — AWS will not show it again."

# ── Build agent instance profile + role ──────────────────────────────────────

echo ""
echo "=== Creating build agent IAM role: $AGENT_ROLE ==="

TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ec2.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}'

aws iam create-role \
  --role-name "$AGENT_ROLE" \
  --assume-role-policy-document "$TRUST_POLICY" \
  --description "Attached to Jenkins build agent EC2 instances" \
  2>/dev/null && echo "Role created: $AGENT_ROLE" \
  || echo "Role already exists: $AGENT_ROLE"

aws iam create-policy \
  --policy-name "$AGENT_POLICY_NAME" \
  --policy-document "file://$SCRIPT_DIR/build-agent-policy.json" \
  --description "Allows Jenkins build agents to run proxylogin tests against Cognito" \
  2>/dev/null && echo "Policy created: $AGENT_POLICY_NAME" \
  || echo "Policy already exists: $AGENT_POLICY_NAME"

AGENT_POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${AGENT_POLICY_NAME}"

aws iam attach-role-policy \
  --role-name "$AGENT_ROLE" \
  --policy-arn "$AGENT_POLICY_ARN"
echo "Policy attached to role."

aws iam create-instance-profile \
  --instance-profile-name "$AGENT_ROLE" \
  2>/dev/null && echo "Instance profile created: $AGENT_ROLE" \
  || echo "Instance profile already exists: $AGENT_ROLE"

aws iam add-role-to-instance-profile \
  --instance-profile-name "$AGENT_ROLE" \
  --role-name "$AGENT_ROLE" \
  2>/dev/null && echo "Role added to instance profile." \
  || echo "Role already in instance profile."

echo ""
echo "=== Done ==="
echo ""
echo "In the EC2 Plugin config, set the IAM Instance Profile to: $AGENT_ROLE"
echo "The build agents will automatically get Cognito permissions via the instance role — no credentials needed in the Jenkinsfile."
