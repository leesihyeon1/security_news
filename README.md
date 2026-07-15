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

## Reports

All collector scripts append normalized events to `data/events.jsonl`.
`scripts/generate_report.py` aggregates them (counts, CVSS distribution, KEV,
asset matches) and asks the local Ollama model for a narrative analysis, then
sends the report via email and Slack (`SLACK_WEBHOOK_REPORT`, falling back to
`SLACK_WEBHOOK_URL`).

```bat
daily_report.bat
weekly_report.bat
python scripts\generate_report.py --period weekly --dry-run
```

If Ollama is unavailable, the report is still sent with statistics only.

## Runtime Files

Runtime outputs are intentionally ignored by Git:

- `logs/`: execution logs
- `state/`: sent-item state used to prevent duplicate notifications
- `data/`: collected event data
- `.env`: local secrets and delivery settings

## Importance Filtering (RSS collector)

`scripts/rss_collector.py` scores every article 0-100 by combining triage
signals (exploitation status, asset match, impact) with LLM enrichment
(severity, relevance, category). Articles below `NEWS_ALERT_MIN_SCORE`
(default 50) are stored in `data/events.jsonl` for the daily report but do
not trigger immediate email/Slack alerts. P1/P2 triage always alerts.

Per-feed options in `assets/feeds.json`:

- `min_score`: per-feed alert threshold override
- `ignore_asset_terms`: inventory terms to ignore during asset matching
  (prevents vendor blogs from always matching their own company name)

```bat
python scripts\rss_collector.py --feed thehackernews --dry-run --no-enrich --limit 2
```

Dry-run output shows each article's score, contributing factors, and whether
it would alert.

## Asset Matching

Organization asset keywords are managed in `assets/inventory.yml`.
When a Slack notification contains a matching product name or alias, the message is sent to `SLACK_WEBHOOK_URGENT`.
If there is no match, each script uses its normal Slack webhook setting.
