@echo off
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
python scripts\rss_collector.py --all >> "logs\rss_collector_run_log.txt" 2>&1
