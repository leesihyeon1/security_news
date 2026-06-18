@echo off
set EMAIL_ADDRESS=user@example.com
set EMAIL_APP_PASSWORD=REDACTED_APP_PASSWORD
set SLACK_WEBHOOK_URL=https://hooks.slack.com/services/REDACTED

cd /d "D:\dev\boannews_mail"
python send_github_advisory_daily.py >> send_github_advisory_run_log.txt 2>&1