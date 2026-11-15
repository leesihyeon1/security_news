@echo off
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
python scripts\generate_report.py --period daily >> "logs\daily_report_run_log.txt" 2>&1
python scripts\task_health.py >> "logs\task_health_run_log.txt" 2>&1
rem AI Discovery calls the model for new candidates only (cached otherwise); it runs last because it can take a while.
python scripts\threat_discovery.py --push >> "logs\threat_discovery_run_log.txt" 2>&1
