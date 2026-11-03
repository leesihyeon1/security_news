@echo off
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
python scripts\publish_trending_titles.py >> "logs\publish_trending_run_log.txt" 2>&1
