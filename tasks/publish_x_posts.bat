@echo off
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
python scripts\collect_x_post_urls.py --push >> "logs\publish_x_posts_run_log.txt" 2>&1
exit /b 0
