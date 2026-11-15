# ==============================================================================
# HoneyTrap - Simplified Single-Server Variables
# ==============================================================================

variable "aws_region" {
  description = "AWS region to deploy resources (Mumbai: ap-south-1)"
  type        = string
  default     = "ap-south-1"
}

variable "environment" {
  description = "Environment identifier (dev, demo, lab)"
  type        = string
  default     = "demo"
}

variable "vpc_cidr" {
  description = "CIDR block for HoneyTrap VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  description = "CIDR block for the HoneyTrap public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "admin_ip" {
  description = "Administrator public IP in CIDR format (e.g. 203.0.113.25/32). Required: Restricts Admin SSH (2222), Dashboard (5000), and Nagios (80) from public internet."
  type        = string
  # No default: Insecure 0.0.0.0/0 default removed. User must supply their specific IP.
}

variable "admin_ssh_port" {
  description = "Real administrative SSH port (isolated from honeypot port 22)"
  type        = number
  default     = 2222
}

variable "instance_type" {
  description = "EC2 instance size (t3.small provides 2 GiB RAM, ideal for Nagios Core, Apache httpd, and HoneyTrap)"
  type        = string
  default     = "t3.small"
}

variable "root_volume_size" {
  description = "Root EBS storage volume size in GB (gp3)"
  type        = number
  default     = 25
}

variable "key_name" {
  description = "Name of existing AWS KeyPair in target region for SSH access"
  type        = string
  default     = "honeytrap-key"
}
