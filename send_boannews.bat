@echo off
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python scripts\send_boannews_daily.py >> "logs\send_boannews_run_log.txt" 2>&1
