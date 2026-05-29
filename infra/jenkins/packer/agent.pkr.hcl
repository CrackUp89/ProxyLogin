packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "eu-west-1"
}

# t3.small is the target runtime size; use something faster just for the AMI build itself.
variable "build_instance_type" {
  type    = string
  default = "t3.medium"
}

variable "agent_instance_profile" {
  type        = string
  description = "IAM instance profile to attach to the builder instance (needs ECR/S3 pull if any). Leave empty to rely on env-var credentials."
  default     = ""
}

locals {
  timestamp = formatdate("YYYY-MM-DD-hhmmss", timestamp())
}

source "amazon-ebs" "jenkins-agent" {
  region        = var.aws_region
  instance_type = var.build_instance_type
  force_deregister      = true
  force_delete_snapshot = true

  # Latest Ubuntu 22.04 LTS (Jammy) x86_64 — stable, well-tested with Docker
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"] # Canonical
    most_recent = true
  }

  ssh_username = "ubuntu"

  ami_name        = "jenkins-proxylogin-agent-${local.timestamp}"
  ami_description = "Jenkins build agent: Docker, Java 21, gh CLI - for proxylogin CI"

  # Require IMDSv2 on all instances launched from this AMI.
  imds_support = "v2.0"

  # Also enforce on the Packer builder instance itself, and raise the hop limit
  # so Docker containers can reach the IMDS endpoint during the build.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  # 20 GB is enough for the OS, Docker daemon, and cached Go images.
  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
  }

  iam_instance_profile = var.agent_instance_profile

  tags = {
    Name      = "jenkins-proxylogin-agent"
    Project   = "proxylogin"
    ManagedBy = "packer"
    BuiltAt   = local.timestamp
  }
}

build {
  sources = ["source.amazon-ebs.jenkins-agent"]

  provisioner "shell" {
    script          = "provision.sh"
    execute_command = "sudo bash '{{ .Path }}'"
  }
}
