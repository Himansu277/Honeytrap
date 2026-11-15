# ==============================================================================
# HoneyTrap - Single-Server EC2 Deployment (Amazon Linux 2023)
# Hosts HoneyTrap SSH Honeypot, Flask Dashboard, Nagios Core, Ansible & Puppet
# ==============================================================================

# Query latest official Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["137112412989"] # Official Amazon AWS Account ID

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Single HoneyTrap All-in-One EC2 Instance (100% Free Tier Eligible)
resource "aws_instance" "honeytrap_server" {
  ami                  = data.aws_ami.amazon_linux_2023.id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.honeytrap_subnet.id
  key_name             = var.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.honeytrap_sg.id]

  user_data = <<-EOF
#!/usr/bin/env bash
mkdir -p /etc/honeytrap
echo "S3_BUCKET_NAME=${aws_s3_bucket.evidence_bucket.bucket}" > /etc/honeytrap/env
echo "AWS_DEFAULT_REGION=${var.aws_region}" >> /etc/honeytrap/env
chmod 600 /etc/honeytrap/env

${file("${path.module}/user_data/server_init.sh")}
EOF

  root_block_device {
    volume_size           = var.root_volume_size # 25 GB gp3 EBS
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
    tags = {
      Name = "HoneyTrap-Server-RootDisk"
    }
  }

  tags = {
    Name = "HoneyTrap-Server"
    Role = "Honeypot-Dashboard-NagiosCore"
    OS   = "Amazon-Linux-2023"
  }
}
