@echo off
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python scripts\generate_report.py --period daily >> "logs\daily_report_run_log.txt" 2>&1
python scripts\task_health.py >> "logs\task_health_run_log.txt" 2>&1
