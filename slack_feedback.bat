@echo off
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python scripts\slack_feedback_poller.py >> "logs\slack_feedback_run_log.txt" 2>&1
