@echo off
cd /d "%~dp0"
if not exist "logs" mkdir "logs"
python scripts\curator_digest.py >> "logs\curator_digest_run_log.txt" 2>&1
