# ==============================================================================
# HoneyTrap - Security Groups
# Implements strict one-way isolation and honeypot containment
# ==============================================================================

# 1. Management Security Group (Bastion, Nagios Core, Puppet Server)
resource "aws_security_group" "management_sg" {
  name        = "honeytrap-management-sg"
  description = "Allows admin access to Bastion, Nagios UI, and Puppet"
  vpc_id      = aws_vpc.honeytrap_vpc.id

  # Admin SSH access on custom admin port 2222 (protects from standard scanners)
  ingress {
    description = "Admin SSH on custom port"
    from_port   = var.admin_ssh_port
    to_port     = var.admin_ssh_port
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  # Nagios Web UI access (Port 80)
  ingress {
    description = "Nagios Web UI"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  # HoneyTrap Flask Dashboard UI (Port 5000)
  ingress {
    description = "HoneyTrap Dashboard UI"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  # Puppet Agent check-ins from within VPC (Port 8140)
  ingress {
    description = "Puppet Master communication from VPC subnets"
    from_port   = 8140
    to_port     = 8140
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Outbound: Full egress for package updates, NRPE polls, AWS APIs
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "HoneyTrap-SG-Management"
  }
}

# 2. Honeypot Security Group (Trap)
resource "aws_security_group" "honeypot_sg" {
  name        = "honeytrap-honeypot-sg"
  description = "Publicly open trap on port 22 for Cowrie; isolated from internal servers"
  vpc_id      = aws_vpc.honeytrap_vpc.id

  # Open SSH port 22 to world to lure bots and attackers
  ingress {
    description = "Lure: Open SSH Port 22 to the world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Fake Web Login Page (Port 8080) - low-interaction trap
  ingress {
    description = "Lure: Fake Web Admin Login"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Nagios NRPE monitoring poll (Port 5666) only from Management Subnet
  ingress {
    description = "NRPE Monitoring check from Nagios Server only"
    from_port   = 5666
    to_port     = 5666
    protocol    = "tcp"
    security_groups = [aws_security_group.management_sg.id]
  }

  # Real admin maintenance SSH on custom port 2222 only from Bastion / Admin IP
  ingress {
    description = "Maintenance SSH from Management Node"
    from_port   = var.admin_ssh_port
    to_port     = var.admin_ssh_port
    protocol    = "tcp"
    security_groups = [aws_security_group.management_sg.id]
  }

  # Outbound rule: Restrict outbound traffic so attacker CANNOT launch DDoS/botnet from honeypot
  # Allows only DNS (UDP 53) and HTTPS (443) for AWS S3 log upload and OS repo updates
  egress {
    description = "DNS resolution"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS for S3 log sync and Puppet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Puppet Master communication"
    from_port   = 8140
    to_port     = 8140
    protocol    = "tcp"
    security_groups = [aws_security_group.management_sg.id]
  }

  tags = {
    Name = "HoneyTrap-SG-Honeypot"
  }
}

# 3. Private Production Security Group (Real Protected Servers)
resource "aws_security_group" "production_sg" {
  name        = "honeytrap-production-sg"
  description = "Protected real production server; strict isolation from honeypot"
  vpc_id      = aws_vpc.honeytrap_vpc.id

  # Management SSH on port 2222 from Bastion only
  ingress {
    description = "Admin SSH from Management Bastion"
    from_port   = var.admin_ssh_port
    to_port     = var.admin_ssh_port
    protocol    = "tcp"
    security_groups = [aws_security_group.management_sg.id]
  }

  # Nagios NRPE poll (Port 5666) from Nagios Server only
  ingress {
    description = "NRPE Monitoring check from Nagios Server"
    from_port   = 5666
    to_port     = 5666
    protocol    = "tcp"
    security_groups = [aws_security_group.management_sg.id]
  }

  # Internal HTTP traffic from Management subnet only
  ingress {
    description = "Internal Application HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = [aws_security_group.management_sg.id]
  }

  # Outbound rule: Puppet master and updates
  egress {
    description = "Puppet Master"
    from_port   = 8140
    to_port     = 8140
    protocol    = "tcp"
    security_groups = [aws_security_group.management_sg.id]
  }

  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "HoneyTrap-SG-Production"
  }
}
