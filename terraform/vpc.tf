# ==============================================================================
# HoneyTrap - Simplified Single-Server VPC Infrastructure
# 1 VPC, 1 Internet Gateway, 1 Public Subnet, 1 Route Table
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

# 2. Internet Gateway (Enables inbound honeypot traffic & admin management)
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.honeytrap_vpc.id

  tags = {
    Name = "HoneyTrap-IGW"
  }
}

# 3. Single HoneyTrap Subnet
resource "aws_subnet" "honeytrap_subnet" {
  vpc_id                  = aws_vpc.honeytrap_vpc.id
  cidr_block              = var.subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "HoneyTrap-Subnet-Public"
  }
}

# 4. Route Table & Association
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
  subnet_id      = aws_subnet.honeytrap_subnet.id
  route_table_id = aws_route_table.public_rt.id
}
