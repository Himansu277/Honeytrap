# ==============================================================================
# HoneyTrap: A Self-Healing Honeypot Security Trap on AWS
# Terraform Configuration - Provider & Core Settings
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "HoneyTrap"
      ManagedBy   = "Terraform"
      Environment = var.environment
      Owner       = "Himansu-12304038"
    }
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}
