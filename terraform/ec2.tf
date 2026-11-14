# ==============================================================================
# HoneyTrap - Single-Server EC2 Deployment
# Hosts HoneyTrap SSH Honeypot, Flask Dashboard, Nagios Core, Ansible & Puppet
# ==============================================================================

# Query latest official Ubuntu 22.04 LTS AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Single HoneyTrap All-in-One EC2 Instance (100% Free Tier Eligible)
resource "aws_instance" "honeytrap_server" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.honeytrap_subnet.id
  key_name             = var.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.honeytrap_sg.id]

  user_data = file("${path.module}/user_data/server_init.sh")

  root_block_device {
    volume_size           = 15 # 15 GB gp3 fits well inside AWS 30 GB Free Tier
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
  }
}
