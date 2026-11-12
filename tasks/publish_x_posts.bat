@echo off
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
echo [%date% %time%] >> "logs\publish_x_posts_run_log.txt"
python scripts\collect_x_post_urls.py --push >> "logs\publish_x_posts_run_log.txt" 2>&1
rem A non-zero result is what task_health.py reports to Slack.
exit /b %errorlevel%
