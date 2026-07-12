@echo off
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python scripts\generate_report.py --period daily >> "logs\daily_report_run_log.txt" 2>&1
