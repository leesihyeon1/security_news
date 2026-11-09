@echo off
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
python scripts\generate_report.py --period weekly >> "logs\weekly_report_run_log.txt" 2>&1
