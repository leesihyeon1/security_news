@echo off
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
python scripts\update_intel_data.py >> "logs\update_intel_data_run_log.txt" 2>&1
