# ==============================================================================
# HoneyTrap - VPC and Subnet Infrastructure
# 3 Subnets: Public (Bastion/Nagios/Puppet), Honeypot (Trap), Private (Prod)
# ==============================================================================

# 1. Main Virtual Private Cloud
resource "aws_vpc" "honeytrap_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "HoneyTrap-VPC"
  }
}

# 2. Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.honeytrap_vpc.id

  tags = {
    Name = "HoneyTrap-IGW"
  }
}

# 3. Subnets
# Subnet A: Public Management (Bastion, Nagios Core, Puppet Server)
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.honeytrap_vpc.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "HoneyTrap-Subnet-Public-Management"
    Type = "Public"
  }
}

# Subnet B: Isolated Honeypot Subnet (Cowrie fake SSH trap)
resource "aws_subnet" "honeypot_subnet" {
  vpc_id                  = aws_vpc.honeytrap_vpc.id
  cidr_block              = var.honeypot_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "HoneyTrap-Subnet-Honeypot-DMZ"
    Type = "Honeypot"
  }
}

# Subnet C: Isolated Private Production Subnet (Real servers)
resource "aws_subnet" "private_prod_subnet" {
  vpc_id                  = aws_vpc.honeytrap_vpc.id
  cidr_block              = var.private_prod_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = {
    Name = "HoneyTrap-Subnet-Private-Production"
    Type = "Private"
  }
}

# 4. Route Tables
# Public Route Table (for Management / Bastion / Nagios)
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.honeytrap_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "HoneyTrap-RT-Public"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Honeypot Route Table (Inbound internet access, controlled outbound)
resource "aws_route_table" "honeypot_rt" {
  vpc_id = aws_vpc.honeytrap_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "HoneyTrap-RT-Honeypot"
  }
}

resource "aws_route_table_association" "honeypot_assoc" {
  subnet_id      = aws_subnet.honeypot_subnet.id
  route_table_id = aws_route_table.honeypot_rt.id
}

# Private Production Route Table (Internal only, zero direct internet ingress)
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.honeytrap_vpc.id

  tags = {
    Name = "HoneyTrap-RT-Private-Prod"
  }
}

resource "aws_route_table_association" "private_assoc" {
  subnet_id      = aws_subnet.private_prod_subnet.id
  route_table_id = aws_route_table.private_rt.id
}
