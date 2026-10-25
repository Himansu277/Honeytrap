# ==============================================================================
# HoneyTrap - Terraform Outputs
# ==============================================================================

output "management_node_public_ip" {
  description = "Public IP of Bastion / Nagios / Puppet / Dashboard server"
  value       = aws_instance.management_node.public_ip
}

output "honeypot_node_public_ip" {
  description = "Public IP of Cowrie Honeypot (Attack Bait)"
  value       = aws_instance.honeypot_node.public_ip
}

output "production_node_private_ip" {
  description = "Private IP of Protected Production Server"
  value       = aws_instance.production_node.private_ip
}

output "evidence_s3_bucket" {
  description = "AWS S3 bucket for forensic evidence collection"
  value       = aws_s3_bucket.evidence_bucket.bucket
}

output "sns_alert_topic_arn" {
  description = "ARN of SNS Alert Topic"
  value       = aws_sns_topic.attack_alerts.arn
}

output "admin_ssh_command" {
  description = "Command to SSH into Management Node using custom admin port"
  value       = "ssh -i <your-key.pem> -p 2222 ubuntu@${aws_instance.management_node.public_ip}"
}

output "honeypot_test_command" {
  description = "Command to simulate attacker connecting to honeypot bait on port 22"
  value       = "ssh -p 22 root@${aws_instance.honeypot_node.public_ip}"
}

output "dashboard_url" {
  description = "HoneyTrap Threat Intelligence & Self-Healing Dashboard"
  value       = "http://${aws_instance.management_node.public_ip}:5000"
}

output "nagios_web_url" {
  description = "Nagios Core Web Console URL"
  value       = "http://${aws_instance.management_node.public_ip}/nagios (user: nagiosadmin / pass: honeytrap2026!)"
}
