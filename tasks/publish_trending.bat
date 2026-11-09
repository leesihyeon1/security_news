@echo off
cd /d "%~dp0.."
if not exist "logs" mkdir "logs"
python scripts\publish_trending_titles.py >> "logs\publish_trending_run_log.txt" 2>&1
rem Update the code last, on one line, so cmd never reads this file after it changes.
copy /y "%~dp0update_code.bat" "%TEMP%\security_news_update_code.bat" >nul & call "%TEMP%\security_news_update_code.bat" "%~dp0.." & exit /b 0
