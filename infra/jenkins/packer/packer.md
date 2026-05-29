# Jenkins Build Agent AMI — Packer

## Install Packer

**macOS**
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/packer
```

**Linux (Debian/Ubuntu)**
```bash
wget -O- https://apt.releases.hashicorp.com/gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install packer
```

**Windows**
```powershell
choco install packer
```

Verify:
```bash
packer version
```

---

## Prerequisites

AWS credentials must be available before running Packer. Either:

- Environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`
- Or an IAM instance profile if running Packer on an EC2 instance

---

## Build the AMI

```bash
cd infra/jenkins/packer

# Download the Amazon plugin
packer init .

# Build
packer build -var aws_region=eu-west-1 agent.pkr.hcl
```

Packer will print the new AMI ID at the end:
```
--> amazon-ebs.jenkins-agent: AMIs were created:
eu-west-1: ami-0123456789abcdef0
```

**Using AWS Login (`aws login`)**

It is recommended to perform a Packer build on fresh console instance.

Login into AWS:
```bash
aws login
```

Build
```bash
eval $(aws configure export-credentials --format env)
packer build -var aws_region=eu-west-1 agent.pkr.hcl
```

The credentials need the same EC2 permissions as the `jenkins-ec2-plugin` user
(see `../ec2-plugin-policy.json`).

---

## Configure Jenkins

1. **Manage Jenkins → Clouds → Amazon EC2 → Add a new AMI**
2. Set **AMI ID** to the value printed above
3. Set **Instance Type** to `t3.small`
4. Set **IAM Instance Profile** to `jenkins-proxy-login-build-agent`
5. Set **Remote user** to `jenkins`
6. Set **Remote FS root** to `/var/jenkins`

---

## Rebuild the AMI

Re-run `packer build` any time you change `provision.sh`.
Each build produces a new AMI with a fresh timestamp in its name —
update the AMI ID in Jenkins after each rebuild.
