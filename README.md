# boannews_mail

Security news clipping and notification scripts for email and Slack.

## Setup

1. Create a Python virtual environment.

   ```bat
   python -m venv .venv
   .venv\Scripts\activate
   ```

2. Install dependencies.

   ```bat
   pip install -r requirements.txt
   ```

3. Copy `.env.example` to `.env` and fill in the required values.

   ```bat
   copy .env.example .env
   ```

## Environment

Required for email delivery:

- `EMAIL_ADDRESS`
- `EMAIL_APP_PASSWORD`
- `TO_EMAIL`
- `SMTP_SERVER`
- `SMTP_PORT`

Optional Slack webhooks:

- `SLACK_WEBHOOK_ASEC`
- `SLACK_WEBHOOK_BOANNEWS`
- `SLACK_WEBHOOK_CVE`
- `SLACK_WEBHOOK_GITHUB`
- `SLACK_WEBHOOK_KISA`
- `SLACK_WEBHOOK_MS`
- `SLACK_WEBHOOK_URGENT`

Optional API tokens:

- `NVD_API_KEY`
- `GITHUB_TOKEN`

## Run

Each `.bat` file can be run from any directory because it resolves paths from its own location.

```bat
asec_notifier.bat
send_boannews.bat
run_cve.bat
github_advisory.bat
send_kisa.bat
microsoft_patch.bat
```

## Runtime Files

Runtime outputs are intentionally ignored by Git:

- `logs/`: execution logs
- `state/`: sent-item state used to prevent duplicate notifications
- `data/`: collected event data
- `.env`: local secrets and delivery settings

## Asset Matching

Organization asset keywords are managed in `assets/inventory.yml`.
When a Slack notification contains a matching product name or alias, the message is sent to `SLACK_WEBHOOK_URGENT`.
If there is no match, each script uses its normal Slack webhook setting.
