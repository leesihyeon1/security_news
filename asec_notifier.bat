@echo off
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python scripts\asec_notifier.py >> "logs\asec_notifier_run_log.txt" 2>&1
