@echo off
echo ==============================================================================
echo           Starting HoneyTrap Cyber Threat Intelligence Dashboard
echo ==============================================================================
cd /d "%~dp0\.."

python -m pip install -r dashboard\requirements.txt >nul 2>&1
echo [+] Starting Flask Web Server on http://127.0.0.1:5000 ...
python dashboard\app.py
pause
