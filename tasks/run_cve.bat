@echo off
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
python scripts\send_cve_daily.py >> "logs\cve_run_log.txt" 2>&1
