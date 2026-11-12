# ==============================================================================
# HoneyTrap - EC2 Instances Deployment
# 1. Management Control Host (Bastion + Nagios + Puppet + Ansible + Dashboard)
# 2. Honeypot Host (Cowrie trap on Port 22)
# 3. Private Production Host (Hardened Web Server)
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

# 1. Management Control Node (Public Subnet)
resource "aws_instance" "management_node" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.public_subnet.id
  key_name             = var.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.management_sg.id]

  user_data = file("${path.module}/user_data/bastion_init.sh")

  root_block_device {
    volume_size           = 10
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  tags = {
    Name = "HoneyTrap-Management-ControlNode"
    Role = "Bastion-Nagios-Puppet-Ansible"
  }
}

# 2. Cowrie Honeypot Node (Isolated Honeypot Subnet)
resource "aws_instance" "honeypot_node" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.honeypot_subnet.id
  key_name             = var.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.honeypot_sg.id]

  user_data = file("${path.module}/user_data/honeypot_init.sh")

  root_block_device {
    volume_size           = 10
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
    tags = {
      Name = "HoneyTrap-Honeypot-RootDisk"
    }
  }

  tags = {
    Name = "HoneyTrap-Honeypot-Node"
    Role = "Cowrie-Trap"
  }
}

# 3. Private Production Node (Private Subnet)
resource "aws_instance" "production_node" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type
  subnet_id            = aws_subnet.private_prod_subnet.id
  key_name             = var.key_name
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name

  vpc_security_group_ids = [aws_security_group.production_sg.id]

  user_data = file("${path.module}/user_data/prod_init.sh")

  root_block_device {
    volume_size           = 10
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  tags = {
    Name = "HoneyTrap-Production-Node"
    Role = "Production-Protected"
  }
}
