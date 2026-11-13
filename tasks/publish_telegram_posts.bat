@echo off
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
echo [%date% %time%] >> "logs\publish_telegram_posts_run_log.txt"
python scripts\collect_telegram_posts.py --push >> "logs\publish_telegram_posts_run_log.txt" 2>&1
exit /b %errorlevel%
