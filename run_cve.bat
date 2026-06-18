@echo off
set EMAIL_ADDRESS=user@example.com
set EMAIL_APP_PASSWORD=REDACTED_APP_PASSWORD
set NVD_API_KEY=7f9fc677-e3b7-4c4f-b4e1-db1c445d13e7
set CVE_LOOKBACK_HOURS=48
set MIN_NVD_CVSS_SCORE=7.0
set SLACK_WEBHOOK_URL=https://hooks.slack.com/services/REDACTED

cd /d "D:\dev\boannews_mail"
python send_cve_daily.py >> cve_run_log.txt 2>&1