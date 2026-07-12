@echo off
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python scripts\send_github_advisory_daily.py >> "logs\send_github_advisory_run_log.txt" 2>&1
