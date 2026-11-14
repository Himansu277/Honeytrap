# ==============================================================================
# HoneyTrap - Simplified S3 Evidence Bucket & IAM Security Policies
# ==============================================================================

# 1. Forensic Evidence S3 Bucket (Standard Low-Cost Object Storage)
resource "aws_s3_bucket" "evidence_bucket" {
  bucket        = "honeytrap-evidence-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = {
    Name        = "HoneyTrap-Evidence-Store"
    Description = "Storage for HoneyTrap incident triage packages"
  }
}

# Block all public access to evidence bucket (Private by default)
resource "aws_s3_bucket_public_access_block" "evidence_block" {
  bucket = aws_s3_bucket.evidence_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 2. IAM Role for HoneyTrap EC2 Instance
resource "aws_iam_role" "ec2_role" {
  name = "honeytrap-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Least-privilege IAM Policy: S3 upload and read only (No paid EBS snapshots or SNS)
resource "aws_iam_policy" "orchestration_policy" {
  name        = "honeytrap-s3-evidence-policy"
  description = "Allows server to upload and retrieve forensic evidence archives from S3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.evidence_bucket.arn,
          "${aws_s3_bucket.evidence_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "role_policy_attach" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.orchestration_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "honeytrap-instance-profile"
  role = aws_iam_role.ec2_role.name
}
