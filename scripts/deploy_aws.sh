#!/usr/bin/env bash
# ==============================================================================
# HoneyTrap - AWS Deployment Helper Script
# Runs Terraform Init, Plan, and Apply
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$SCRIPT_DIR/../terraform"

echo "[*] Navigating to Terraform directory: $TERRAFORM_DIR"
cd "$TERRAFORM_DIR"

if [ ! -f "terraform.tfvars" ]; then
    echo "[!] terraform.tfvars not found. Creating from template..."
    cp terraform.tfvars.example terraform.tfvars
    echo "[!] Please review and edit terraform.tfvars with your IP and SSH key name."
fi

echo "[*] Initializing Terraform AWS providers..."
terraform init

echo "[*] Generating Terraform Execution Plan..."
terraform plan -out=tfplan

read -p "Do you want to deploy HoneyTrap to AWS now? (yes/no): " CONFIRM
if [ "$CONFIRM" == "yes" ]; then
    echo "[*] Applying infrastructure changes to AWS..."
    terraform apply tfplan
    echo "[+] Deployment complete! Terraform outputs displayed above."
else
    echo "Deployment aborted by user."
fi
