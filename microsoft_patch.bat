@echo off
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python scripts\send_microsoft_patch_daily.py >> "logs\microsoft_patch_run_log.txt" 2>&1
