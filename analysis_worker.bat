@echo off
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python scripts\analysis_worker.py >> "logs\analysis_worker_run_log.txt" 2>&1
