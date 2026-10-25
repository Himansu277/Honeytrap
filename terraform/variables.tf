# ==============================================================================
# HoneyTrap - Terraform Variables
# ==============================================================================

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment tag (e.g. dev, demo, prod)"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "CIDR block for HoneyTrap VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Subnet CIDR for Bastion, Nagios, and Puppet control node"
  type        = string
  default     = "10.0.1.0/24"
}

variable "honeypot_subnet_cidr" {
  description = "Isolated Subnet CIDR for Cowrie Honeypot"
  type        = string
  default     = "10.0.2.0/24"
}

variable "private_prod_subnet_cidr" {
  description = "Isolated Private Subnet CIDR for internal production server"
  type        = string
  default     = "10.0.3.0/24"
}

variable "admin_ip" {
  description = "Administrator public IP (CIDR format e.g. 203.0.113.25/32) allowed to access management port"
  type        = string
  default     = "0.0.0.0/0" # Should be changed to admin's specific IP in production
}

variable "admin_ssh_port" {
  description = "Moved administrator SSH port (real SSH) to avoid honeypot port 22"
  type        = number
  default     = 2222
}

variable "instance_type" {
  description = "EC2 instance size (t3.micro is free-tier eligible)"
  type        = string
  default     = "t3.micro"
}

variable "key_name" {
  description = "Name of existing AWS KeyPair for SSH access"
  type        = string
  default     = "honeytrap-key"
}

variable "alert_email" {
  description = "Email address for AWS SNS alerts when honeypot is attacked"
  type        = string
  default     = "admin@example.com"
}
