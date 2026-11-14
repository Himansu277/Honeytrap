# ==============================================================================
# HoneyTrap - Simplified Single-Server Security Group
# Enforces strict isolation: public honeypot bait vs private admin access
# ==============================================================================

resource "aws_security_group" "honeytrap_sg" {
  name        = "honeytrap-single-server-sg"
  description = "Public honeypot trap with strictly restricted administrative access"
  vpc_id      = aws_vpc.honeytrap_vpc.id

  # ----------------------------------------------------------------------------
  # 1. PUBLIC HONEYPOT BAIT (Open to Internet)
  # ----------------------------------------------------------------------------
  ingress {
    description = "Honeypot Bait: SSH Decoy Port 22"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ----------------------------------------------------------------------------
  # 2. RESTRICTED ADMINISTRATIVE ACCESS (Strictly Limited to Admin IP)
  # Never exposed to 0.0.0.0/0!
  # ----------------------------------------------------------------------------
  ingress {
    description = "Admin SSH: Real maintenance SSH on custom port"
    from_port   = var.admin_ssh_port
    to_port     = var.admin_ssh_port
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  ingress {
    description = "HoneyTrap Dashboard UI (Port 5000)"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  ingress {
    description = "Nagios Core Web UI (Port 80)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
  }

  # ----------------------------------------------------------------------------
  # 3. OUTBOUND EGRESS (Controlled for updates and S3 evidence upload)
  # ----------------------------------------------------------------------------
  egress {
    description = "DNS queries"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS for APT repositories and AWS S3 evidence upload"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP for standard package updates"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "HoneyTrap-SG-SingleServer"
  }
}
