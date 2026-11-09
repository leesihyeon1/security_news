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

Scheduled-task `.bat` files live in `tasks/`. Each can be run from any directory because it changes to the repository root first. `tasks/move_tasks_to_folder.ps1` (run as administrator) points existing scheduled tasks at this folder.

```bat
tasks\rss_collector.bat
tasks\asec_notifier.bat
tasks\send_boannews.bat
tasks\run_cve.bat
tasks\github_advisory.bat
tasks\send_kisa.bat
tasks\microsoft_patch.bat
tasks\curator_digest.bat
```

`rss_collector.bat` runs all enabled feeds in `assets/feeds.json` (`--all`). For manual testing, run
`python scripts\rss_collector.py --feed <name> --dry-run` directly instead.

## Tests

```bat
pip install -r requirements.txt
python -m pytest
```

Covers the pure-logic pieces (tail-read log parsing, trend-read quality gates,
analyst-review rubric parsing, HN buzz caching, Slack feedback ref-mapping) with
temp files and mocked network calls — no real `data/` files or credentials needed.

## Reports

All collector scripts append normalized events to `data/events.jsonl`.
`scripts/generate_report.py` aggregates them (counts, CVSS distribution, KEV,
asset matches) and asks the configured LLM for a narrative analysis, then
sends the report via email and Slack (`SLACK_WEBHOOK_REPORT`, falling back to
`SLACK_WEBHOOK_URL`).

```bat
tasks\daily_report.bat
tasks\weekly_report.bat
python scripts\generate_report.py --period weekly --dry-run
```

If the LLM is unavailable, the report is still sent with statistics only.

### Trend reads (curated recommendations)

Reports include a "읽을만한 동향" section: articles that did not meet the
alert threshold but are worth reading. Candidates are non-alerted news
that answer a PIR, or high-relevance threat/trend articles, or
medium-relevance analysis from reliability-B sources (vendor research
with own telemetry). Re-reports of stories already alerted via another
source (cluster match) and events labeled noise via feedback are
excluded. Selection is greedy: PIR coverage is seeded with PIRs already
answered by alerted articles in the period, so recommendations fill the
gaps alerts left — high-weight uncovered PIRs are picked first, then any
uncovered PIR, then remaining slots fill by insight order (PIR-high matches,
PIR count, topic freshness — actors/malware already alerted in the
period rank lower, LLM confidence (low ranks lower), relevance, novelty
(new > update > known), content depth as judged by the LLM
(analysis > report > news > opinion), intel richness (IOC/ATT&CK
count), importance score, recency), with one article per story cluster,
one per actor/malware topic, and at most 2 per category (caps lifted if
slots remain). Each item carries a hash for `feedback.py` labeling.

### Curator digest (periodic, between reports)

`curator_digest.bat` runs the same trend-read selection
(`generate_report.pick_trend_reads`) but differs in two ways: scoped to
whatever was collected since its last run (tracked in
`state/curator_digest_state.json`, default 4h lookback on first run) instead
of a full day/week, and `include_alerted=True` — already-alerted events are
still eligible, since this digest has no separate cards/TOP-N section to
already show them (unlike the full report, where trend reads deliberately
exclude alerted events to avoid double-showing within the same report).
Meant to be scheduled every 3-4 hours, independent of
`daily_report.bat`/`weekly_report.bat` — the same article can show up in
both, on purpose (no cross-run dedup). Caps at 3 items (vs. 5 in the full
report) and posts to `SLACK_WEBHOOK_CURATOR` (falls back to
`SLACK_WEBHOOK_REPORT`, then `SLACK_WEBHOOK_URL`). Sends nothing if there's
nothing worth surfacing in that window.

```bat
python scripts\curator_digest.py --hours 4 --dry-run   # test a window without touching state
```

### Historical search

Reports only show a snapshot of the collection period. To check whether a
CVE, actor, or asset match is new or a recurring pattern, query the full
event log directly:

```bat
python scripts\search_events.py --actor Lazarus --since 90d
python scripts\search_events.py --cve CVE-2026-25089
python scripts\search_events.py --asset Fortinet --level P1 --since 6m
```

Prints matching events chronologically plus a per-week/per-month count
histogram. Filters: `--actor`, `--malware`, `--cve`, `--source`, `--category`,
`--pir`, `--asset`, `--level`, `--keyword`, `--since`/`--until` (`90d`/`12w`/
`6m`/`1y` or `YYYY-MM-DD`). At least one filter is required.

## Web Dashboard (optional)

`boannews_vercel/` is a separate repo/deploy target with two sibling
sub-projects, each its own Vercel project (Root Directory setting):
`boannews_vercel/dashboard/` (a static site showing the daily/weekly report
split into domestic/overseas tabs) and `boannews_vercel/click-tracker/`
(the click-tracking redirect, see below). `generate_report.py` publishes to
`dashboard/data/` via `scripts/publish_web_dashboard.py` when
`WEB_DASHBOARD_REPO_PATH` is set — see `boannews_vercel/README.md` and
`boannews_vercel/dashboard/README.md` for structure and deployment steps.
Unset by default; the main report send is unaffected either way (publish
failures are logged, never raised).

## LLM Provider

All LLM calls (article enrichment, summaries, report narrative) go through
`common_utils.llm_generate()`. Set `LLM_PROVIDER` in `.env`:

- `ollama` (default): local Ollama (`OLLAMA_URL`, `OLLAMA_MODEL`).
- `nvidia`: NVIDIA NIM API (build.nvidia.com) using `NVIDIA_API_KEY` and
  `NVIDIA_MODEL` (default `nvidia/nemotron-3-ultra-550b-a55b`). Free tier is rate-limited
  to ~40 requests/min; a 429 is retried once after a short wait. If the NIM
  call fails, the request automatically falls back to local Ollama.

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
(default 45) are stored in `data/events.jsonl` for the daily report but do
not trigger immediate email/Slack alerts. P1/P2 triage always alerts.
The LLM also judges the exploitation status reported by the article
(active/poc/none); this overrides keyword-based triage in both directions
(a retrospective mention of past exploitation is downgraded, Korean
phrasing variants missed by keywords are upgraded), while fact-based
signals (CISA KEV, MSRC, EPSS) are never overridden.

Scoring is band-based (Recorded Future style): the strongest triggered
rule sets the band — High 65-100 (active exploitation), Moderate 30-64
(PoC, asset match, critical/high severity, high relevance), Info 5-24 —
and remaining rules push the score up within the band. Weak signals alone
can never reach the High band, so a score of 65+ always means a strong
signal exists. Each reason carries its evidence (EPSS value, matched
asset names, CVE list). Product-event articles are capped at 20.

Per-feed options in `assets/feeds.json`:

- `min_score`: per-feed alert threshold override
- `ignore_asset_terms`: inventory terms to ignore during asset matching
  (prevents vendor blogs from always matching their own company name)
- `reliability`: simplified Admiralty source grade applied as a score
  multiplier — `A` x1.0 (authoritative/first-party), `B` x0.9 (vendor
  research with own telemetry), `C` x0.75 (secondary news outlets).
  Unset means neutral (x1.0). P1/P2 triage alerts regardless of the
  multiplier because those decisions are based on factual signals.
  Review grades periodically against each source's track record.

```bat
python scripts\rss_collector.py --feed thehackernews --dry-run --no-enrich --limit 2
```

Dry-run output shows each article's score, contributing factors, and whether
it would alert.

### Cross-source clustering

Before alerting, each article is matched against events collected in the
last `CLUSTER_WINDOW_HOURS` (default 72h): same story = shared CVEs
(containment >= 0.5) or similar title (token Jaccard >= 0.5). Catalog
sources (NVD, GitHub Advisory) are excluded from matching.

- **Corroboration bonus**: each additional distinct source adds +10 (A/B
  reliability) or +5 (C/unknown — circular-reporting discount), capped at
  +20. Multi-source coverage can push a below-threshold story over the line.
- **Duplicate suppression**: if the story was already alerted, the new
  article is stored for reports but not re-alerted — unless its triage
  level escalated (e.g. P3 -> P1 "now exploited"), which re-alerts.

Cluster decisions are stored per event (`cluster` field) in events.jsonl.
Note: title matching works best for English titles; Korean titles rely
mostly on CVE matching due to particle suffixes.

## Intel Reference Data (extraction/normalization)

`assets/intel/` holds processed reference data used during extraction:

- `threat_actor_aliases.json`: MISP Galaxy alias map — `make_event`
  normalizes threat actor names to canonical ones (e.g. Hidden Cobra →
  Lazarus Group) so cross-source counting works
- `attack_techniques.json`: official MITRE ATT&CK technique catalog —
  the LLM may propose technique IDs for narrative descriptions, and only
  IDs present in this catalog survive (hallucination guard); regex still
  extracts explicitly mentioned IDs
- `benign_iocs.json`: MISP warninglists (public DNS, Cloudflare, Google,
  Microsoft) — extracted IOCs matching benign infrastructure are dropped

The processed files are committed so everything works out of the box.
Refresh them quarterly (or when needed) with:

```bat
tasks\update_intel_data.bat
```

If a file is missing, the related feature silently disables (alias names
pass through, LLM technique proposals are discarded, no benign filtering).

## PIR Alignment (Priority Intelligence Requirements)

`assets/pir.json` declares the questions this organization needs answered
(asset-targeting exploitation, Korea-targeted ransomware/supply-chain,
AI-related attacks, endpoint initial-access trends like ClickFix/phishing).
The LLM enrichment judges which PIRs each article answers (validated
against the defined IDs), and matches feed into:

- **Scoring**: a high-weight PIR match is a Moderate band rule (+8 push),
  medium-weight is Info (+3); also exposed to feedback learning as
  `pir_high`/`pir_other` features
- **Reports**: a "PIR 현황" section groups the period's articles by PIR
  with counts, right after the AI analysis. PIRs with zero matches in
  the period are listed as 무응답 (collection gap) — a signal that
  sources don't cover the topic, the question is too narrow, or the LLM
  is missing the match

Edit `pir.json` (not code) when priorities change. "Exclude product
promo" is handled separately by the 제품행사 category score cap, not a
PIR. If the file is missing, the prompt and scoring silently omit PIRs.

## Feedback Learning

Label alerts as useful/noise, then learn scoring weights from your own
judgments instead of hand-tuned points.

**Collecting labels** (stored in `data/feedback.jsonl`):

- CLI: `python scripts\feedback.py --list` shows recent alerts with a
  10-char `ref` hash; `--useful <ref>` / `--noise <ref>` records a label.
- Slack: react to alert messages (each article shows its `ref:` in a
  context line) and run `slack_feedback.bat` (schedule daily). Useful:
  👍 🔥 📌 ⭐ 💯 — noise: 👎 🚫 💤 (still a binary useful/noise label
  underneath; the wider emoji choice just gives reactions more natural
  nuance than forcing every "this matters, bookmark it" into a plain
  👍). Requires `SLACK_BOT_TOKEN` + `SLACK_FEEDBACK_CHANNELS`; a reaction
  on a multi-article message labels every article in it — use the CLI
  for per-article control.
- Auto (KEV): `kev_feedback_labeler.py` (runs nightly via
  `slack_feedback.bat`) scans events whose CVE later appeared in CISA
  KEV — proof the alert/recommendation was actually right, independent
  of anyone's opinion — and labels them `useful` (`via: auto_kev`).
  Only `useful` is ever auto-generated; a CVE never reaching KEV isn't
  evidence of `noise`, so that side still needs a human call. Never
  overwrites an event that already has a label.
- Auto (clicks, optional): if `CLICK_TRACK_BASE_URL` is set, report/alert
  links get rewritten through a small Vercel redirect function (see
  `boannews_vercel/click-tracker/README.md` for deployment) that logs the
  click to Redis (`REDIS_URL`, e.g. from Vercel Storage). `click_feedback_puller.py` (also nightly) pulls that
  log and labels the clicked event `useful` (`via: click`). Unset by
  default — `tracking_url()` returns the original URL unchanged, no
  behavior change unless you deploy the tracker.

**Training**: once you have 30+ labels (10+ per class):

```bat
python scripts\train_weights.py --dry-run   # inspect learned weights
python scripts\train_weights.py             # write data\learned_weights.json
python scripts\train_weights.py --reset     # back to rule-based scoring
```

While `data/learned_weights.json` exists, `score_importance` returns the
logistic model's usefulness probability x100 (same 0-100 scale and alert
threshold; P1/P2 still always alerts). Deleting the file reverts to the
built-in rule weights instantly. Retrain quarterly or whenever your
interests shift. The file lives in `data/` (not synced via git) — retrain
per machine or copy it manually.

## News Categorization

The LLM enrichment classifies each article into one of: 취약점, 악성코드,
침해사고, 개인정보유출, 공격캠페인, 공급망공격, 피싱사기, 정책규제,
기술동향, 제품행사, 기타. Threat categories add importance score
(공급망공격 counts as a moderate signal since asset matching structurally
misses it); 피싱사기 (consumer scams) and 정책규제 are penalized;
제품행사 is capped at 20. 기술동향 feeds the report's trend-reads
curation. The category appears as a
tag (e.g. `[취약점]`) in email/Slack alerts, and daily/weekly reports include
a "카테고리별 뉴스" section grouping collected articles by category
(priority-sorted within each group, capped per category). Events without a
category (API sources such as NVD, or when the LLM is unavailable) are not
shown in that section but remain in the priority lists.

## Asset Matching

Organization asset keywords are managed in `assets/inventory.yml`.
When a Slack notification contains a matching product name or alias, the message is sent to `SLACK_WEBHOOK_URGENT`.
If there is no match, each script uses its normal Slack webhook setting.

Each asset may declare an optional `criticality: high|low` (default
high — exposed/core assets). Active exploitation matching only
low-criticality assets triages as P2 instead of P1, so internal or
low-value assets do not page the urgent channel:

```yaml
  - name: Memoq
    aliases: [Memoq, memoQ]
    criticality: low
```

The LLM enrichment also extracts `affected_versions` and patch status
(`fix_available`, `patch_info`) from articles; alerts show them as a
"대응:" line (affected version range and available fix) so the
"are we affected / is there a patch" decision can be made from the
alert itself. Articles the LLM marks `confidence: low` receive a score
penalty and rank lower in trend-reads.
