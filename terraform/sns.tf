# ==============================================================================
# HoneyTrap - SNS Alerts Notification System
# ==============================================================================

resource "aws_sns_topic" "attack_alerts" {
  name         = "honeytrap-attack-alerts"
  display_name = "HoneyTrap Attack Incident Alert"

  tags = {
    Name = "HoneyTrap-SNS-Alerts"
  }
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.attack_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
