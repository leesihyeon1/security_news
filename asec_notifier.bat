@echo off
set EMAIL_ADDRESS=user@example.com
set EMAIL_APP_PASSWORD=REDACTED_APP_PASSWORD
set SLACK_WEBHOOK_URL=https://hooks.slack.com/services/REDACTED

cd /d "D:\dev\boannews_mail"
python asec_notifier.py >> asec_notifier_run_log.txt 2>&1