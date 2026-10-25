# HoneyTrap - AWS Deployment Helper Script (PowerShell)
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "           HoneyTrap: AWS Automated Cloud Deployment Manager                  " -ForegroundColor Yellow
Write-Host "==============================================================================" -ForegroundColor Cyan

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$terraformDir = Join-Path $scriptPath "..\terraform"

Set-Location $terraformDir

if (-not (Test-Path "terraform.tfvars")) {
    Write-Host "[!] Creating terraform.tfvars from terraform.tfvars.example..." -ForegroundColor Yellow
    Copy-Item "terraform.tfvars.example" "terraform.tfvars"
    Write-Host "[!] Please ensure your AWS KeyPair name and IP are set in terraform.tfvars" -ForegroundColor Green
}

Write-Host "[*] Initializing Terraform..." -ForegroundColor Cyan
terraform init

Write-Host "[*] Creating deployment execution plan..." -ForegroundColor Cyan
terraform plan -out=tfplan

$confirm = Read-Host "Proceed with deployment to AWS? (yes/no)"
if ($confirm -eq "yes") {
    Write-Host "[*] Provisioning HoneyTrap resources on AWS..." -ForegroundColor Green
    terraform apply tfplan
    Write-Host "[+] HoneyTrap deployed successfully!" -ForegroundColor Cyan
} else {
    Write-Host "Deployment cancelled." -ForegroundColor Red
}
