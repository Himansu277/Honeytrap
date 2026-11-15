# HoneyTrap: AWS Deployment & Operation Guide

This guide walks through deploying the HoneyTrap self-healing honeypot system to Amazon Web Services (AWS) using Terraform, Puppet, Nagios, and Ansible.

---

## 1. Prerequisites

Before deploying, ensure you have:
1. **AWS Account**: With permissions for EC2, VPC, S3, IAM, and SNS.
2. **AWS CLI installed & configured**: Run `aws configure` with your Access Key and Secret Key.
3. **Terraform CLI**: Version `>= 1.5.0`.
4. **SSH Key Pair in AWS**: Created under EC2 -> Key Pairs (e.g. named `honeytrap-key`).

---

## 2. Configuration & Parameter Setup

Navigate to the `terraform/` directory:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your text editor:

```hcl
aws_region     = "us-east-1"
environment    = "production"
instance_type  = "t3.micro"       # Eligible for AWS Free Tier
key_name       = "honeytrap-key"   # Your AWS Key Pair name
admin_ip       = "YOUR_PUBLIC_IP/32" # Get with: curl https://checkip.amazonaws.com
admin_ssh_port = 2222
alert_email    = "your-email@example.com"
```

---

## 3. Automated Cloud Deployment

Run the automated deployment script or execute Terraform directly:

### Linux / Mac / WSL:
```bash
chmod +x ../scripts/deploy_aws.sh
../scripts/deploy_aws.sh
```

### Windows (PowerShell):
```powershell
..\scripts\deploy_aws.ps1
```

### Manual Steps:
```bash
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

---

## 4. Post-Deployment Verification

Terraform outputs the provisioned resources:

```
Outputs:
management_node_public_ip = "54.210.12.34"
honeypot_node_public_ip   = "52.90.56.78"
evidence_s3_bucket        = "honeytrap-evidence-a1b2c3d4"
sns_alert_topic_arn       = "arn:aws:sns:us-east-1:123456789012:honeytrap-attack-alerts"
dashboard_url             = "http://54.210.12.34:5000"
nagios_web_url            = "http://54.210.12.34/nagios"
```

1. **Confirm Email Subscription**: Check your inbox for the AWS SNS subscription confirmation email and click "Confirm subscription".
2. **Access the Threat Dashboard**: Open `http://<management_node_public_ip>:5000` in your web browser.
3. **Access Nagios Core**: Open `http://<server_public_ip>/nagios` (Username: `nagiosadmin`, Password: retrieve from `/etc/nagios/nagiosadmin.cred` via `sudo cat /etc/nagios/nagiosadmin.cred` over SSH).

---

## 5. Simulating Attacks & Verifying Self-Healing

From your local computer, simulate an attacker connecting to the honeypot:

```bash
# 1. Attempt login to the trap on port 22
ssh -p 22 root@<honeypot_node_public_ip>

# 2. Try common passwords: 'password', '123456', 'admin'
# Cowrie will grant a fake shell!
root@srv-prod-db01:~# uname -a
root@srv-prod-db01:~# cat /etc/passwd
root@srv-prod-db01:~# exit
```

### Observe the Self-Healing Reaction:
1. Within 60 seconds, Nagios NRPE executes `check_cowrie_activity.sh`.
2. Nagios turns status to **CRITICAL**.
3. Event handler invokes `ansible-playbook playbooks/incident_response.yml`:
   - Gathers memory/process snapshots.
   - Compresses logs into `incident_evidence_<timestamp>.tar.gz`.
   - Uploads archive to the S3 bucket.
   - Triggers an Amazon EBS snapshot of the root disk.
4. Event handler invokes `ansible-playbook playbooks/rebuild_honeypot.yml`:
   - Purges compromised sessions and contaminated directories.
   - Enforces Puppet baseline configuration.
   - Re-arms Cowrie on port 22.
5. Threat dashboard and Nagios status return to **ARMED / HEALTHY**.

---

## 6. Teardown / Destruction (Zero Cloud Cost)

When finished testing or evaluating the project, destroy all resources to ensure zero unexpected AWS charges:

```bash
cd terraform
terraform destroy -auto-approve
```
