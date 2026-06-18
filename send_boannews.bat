@echo off
set EMAIL_ADDRESS=user@example.com
set EMAIL_APP_PASSWORD=REDACTED_APP_PASSWORD
set SLACK_WEBHOOK_URL=https://hooks.slack.com/services/REDACTED

cd /d "D:\dev\boannews_mail"
python send_boannews_daily.py >> send_boannews_run_log.txt 2>&1