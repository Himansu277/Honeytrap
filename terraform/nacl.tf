# ==============================================================================
# HoneyTrap - Network Access Control Lists (NACLs)
# Subnet-level packet filtering enforcing strict isolation
# ==============================================================================

# Honeypot Subnet NACL: Explicitly block any traffic heading to the Private Prod Subnet
resource "aws_network_acl" "honeypot_nacl" {
  vpc_id     = aws_vpc.honeytrap_vpc.id
  subnet_ids = [aws_subnet.honeypot_subnet.id]

  # 1. Allow inbound SSH port 22 from internet (Lure)
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 22
    to_port    = 22
  }

  # 2. Allow inbound fake web admin 8080 from internet
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 8080
    to_port    = 8080
  }

  # 3. Allow inbound NRPE checks from Public Management Subnet only
  ingress {
    rule_no    = 120
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.public_subnet_cidr
    from_port  = 5666
    to_port    = 5666
  }

  # 4. Allow inbound Maintenance SSH from Public Management Subnet
  ingress {
    rule_no    = 130
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.public_subnet_cidr
    from_port  = var.admin_ssh_port
    to_port    = var.admin_ssh_port
  }

  # 5. Allow return ephemeral traffic (ports 1024-65535)
  ingress {
    rule_no    = 140
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # --- OUTBOUND RULES ---

  # RULE 50: Explicit DENY any packet to Private Production Subnet
  egress {
    rule_no    = 50
    protocol   = "-1"
    action     = "deny"
    cidr_block = var.private_prod_subnet_cidr
    from_port  = 0
    to_port    = 0
  }

  # Allow HTTPS out to AWS APIs (S3 upload)
  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Allow DNS out
  egress {
    rule_no    = 110
    protocol   = "udp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 53
    to_port    = 53
  }

  # Allow Puppet Agent connection to Puppet Master in Public Subnet
  egress {
    rule_no    = 120
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.public_subnet_cidr
    from_port  = 8140
    to_port    = 8140
  }

  # Allow ephemeral return traffic back to internet clients
  egress {
    rule_no    = 130
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  tags = {
    Name = "HoneyTrap-NACL-Honeypot-Isolated"
  }
}
