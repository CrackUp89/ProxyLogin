#!/usr/bin/env bash
# Provision script for the Jenkins build agent AMI.
# Runs as root inside the Packer builder instance.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y software-properties-common
add-apt-repository -y universe
apt-get update -qq

# ── Java (Jenkins agent process) ─────────────────────────────────────────────
apt-get install -y openjdk-21-jre-headless

# ── Docker ───────────────────────────────────────────────────────────────────
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | tee /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
systemctl enable docker

# ── GitHub CLI (gh) — used by Jenkinsfile Publish stage ──────────────────────
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] \
  https://cli.github.com/packages stable main" \
  | tee /etc/apt/sources.list.d/github-cli.list
apt-get update -qq
apt-get install -y gh

# ── Common utilities ──────────────────────────────────────────────────────────
apt-get install -y git curl jq python3 awscli zip unzip

# ── Jenkins agent user ────────────────────────────────────────────────────────
# The EC2 Plugin SSHes in as this user and runs the agent jar.
useradd -m -d /var/jenkins -s /bin/bash jenkins || true
usermod -aG docker jenkins          # allow Docker without sudo
usermod -aG docker ubuntu           # keep ubuntu user working too

mkdir -p /var/jenkins
chown jenkins:jenkins /var/jenkins

# ── Cloud-init hooks (run on every instance boot) ────────────────────────────
# 1. Raise the IMDS hop limit to 2 so Docker containers can call AWS APIs via
#    the instance role (default limit of 1 blocks the extra container hop).
#    Requires ec2:ModifyInstanceMetadataOptions on the instance role.
# 2. Copy the EC2-injected SSH public key from ubuntu to the jenkins user so
#    the EC2 Plugin can SSH in as jenkins.
cat > /etc/cloud/cloud.cfg.d/99-jenkins.cfg << 'EOF'
runcmd:
  - |
    TOKEN=$(curl -sf -X PUT "http://169.254.169.254/latest/api/token" \
      -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
    INSTANCE_ID=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" \
      http://169.254.169.254/latest/meta-data/instance-id)
    REGION=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" \
      http://169.254.169.254/latest/meta-data/placement/region)
    aws ec2 modify-instance-metadata-options \
      --instance-id "$INSTANCE_ID" \
      --http-put-response-hop-limit 2 \
      --region "$REGION"
  - mkdir -p /var/jenkins/.ssh
  - cp /home/ubuntu/.ssh/authorized_keys /var/jenkins/.ssh/authorized_keys
  - chown -R jenkins:jenkins /var/jenkins/.ssh
  - chmod 700 /var/jenkins/.ssh
  - chmod 600 /var/jenkins/.ssh/authorized_keys
EOF

# ── Pre-pull images ───────────────────────────────────────────────────────────
# Avoids large pulls on every first build after agent boot.
docker pull alpine:latest
docker pull golang:1.26-alpine
docker pull node:26-alpine
docker pull redis:8-alpine

# ── Cleanup ───────────────────────────────────────────────────────────────────
apt-get clean
rm -rf /var/lib/apt/lists/*
