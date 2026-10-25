# HoneyTrap Dashboard PowerShell Launcher
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "          Starting HoneyTrap Cyber Threat Intelligence Dashboard             " -ForegroundColor Yellow
Write-Host "==============================================================================" -ForegroundColor Cyan

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $scriptPath "..")

Write-Host "[*] Checking Python dependencies..." -ForegroundColor Green
python -m pip install -r dashboard/requirements.txt --quiet

Write-Host "[+] Launching Dashboard on http://127.0.0.1:5000 ..." -ForegroundColor Cyan
python dashboard/app.py
