@echo off
echo ==============================================================================
echo                 Running HoneyTrap Self-Healing Test Suite
echo ==============================================================================
cd /d "%~dp0\.."

python simulation\test_self_healing_cycle.py
pause
