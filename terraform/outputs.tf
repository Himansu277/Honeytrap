# ==============================================================================
# HoneyTrap - Simplified Single-Server Outputs
# ==============================================================================

output "server_public_ip" {
  description = "Public IPv4 address of the HoneyTrap All-in-One Server"
  value       = aws_instance.honeytrap_server.public_ip
}

output "evidence_s3_bucket" {
  description = "S3 bucket name for immutable forensic evidence storage"
  value       = aws_s3_bucket.evidence_bucket.bucket
}

output "admin_ssh_command" {
  description = "Command to SSH into management shell using relocated port 2222"
  value       = "ssh -i <your-key.pem> -p ${var.admin_ssh_port} ubuntu@${aws_instance.honeytrap_server.public_ip}"
}

output "honeypot_test_command" {
  description = "Command to test honeypot decoy bait on standard port 22"
  value       = "ssh -p 22 root@${aws_instance.honeytrap_server.public_ip}"
}

output "dashboard_url" {
  description = "HoneyTrap Threat Intelligence & Self-Healing Dashboard (Restricted to admin_ip)"
  value       = "http://${aws_instance.honeytrap_server.public_ip}:5000"
}

output "nagios_web_url" {
  description = "Genuine Nagios Core Web Interface (Restricted to admin_ip)"
  value       = "http://${aws_instance.honeytrap_server.public_ip}/nagios"
}
