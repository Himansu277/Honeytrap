# ==============================================================================
# HoneyTrap - S3 Evidence Bucket & IAM Security Policies
# ==============================================================================

# 1. Forensic Evidence S3 Bucket
resource "aws_s3_bucket" "evidence_bucket" {
  bucket        = "honeytrap-evidence-${random_id.bucket_suffix.hex}"
  force_destroy = true

  tags = {
    Name        = "HoneyTrap-Evidence-Store"
    Description = "Immutable forensic storage for Cowrie attacker logs & memory dumps"
  }
}

# Bucket versioning to guarantee evidence integrity
resource "aws_s3_bucket_versioning" "evidence_versioning" {
  bucket = aws_s3_bucket.evidence_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Block all public access to evidence bucket
resource "aws_s3_bucket_public_access_block" "evidence_block" {
  bucket = aws_s3_bucket.evidence_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 2. IAM Role for HoneyTrap EC2 Instances
resource "aws_iam_role" "ec2_role" {
  name = "honeytrap-ec2-orchestration-role"

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

# IAM Policy for S3 upload, EBS snapshots, and SNS publish
resource "aws_iam_policy" "orchestration_policy" {
  name        = "honeytrap-incident-response-policy"
  description = "Allows Ansible & Nagios to save logs to S3, take EBS snapshots, and publish alerts"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # S3 Access
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
      },
      # EBS Snapshot creation for forensic preservation
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVolumes",
          "ec2:DescribeInstances",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      # SNS Notification
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [aws_sns_topic.attack_alerts.arn]
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

# 3. VPC Flow Logs for forensic network tracking
resource "aws_flow_log" "vpc_traffic_log" {
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.evidence_bucket.arn}/vpc-flow-logs/"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.honeytrap_vpc.id

  tags = {
    Name = "HoneyTrap-VPC-Flow-Logs"
  }
}
