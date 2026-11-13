# Telegram public channel collector

The dashboard's Telegram button shows short, recent claims from public channels.
The initial source, `@RansomFeedNews`, aggregates ransomware victim claims. It is
an aggregation channel, not a direct statement by a threat actor. Every card is
marked as an unverified claim and links to the original Telegram post.

`assets/telegram_channels.json` lists sources. Add a public handle there after
checking that it is current and relevant. Use `kind: "claims"` for a direct
source: only posts with leak, breach, ransom, sale, or recruitment terms are
selected. `kind: "ransomware_feed"` parses the Ransomfeed actor and claimed
victim fields. Only posts from the last seven days are exported. The collector
reads `https://t.me/s/<handle>` without an account or bot token; it does not
download media, samples, or linked files. Telegram may change its public page
markup, so monitor the collector's run log and the dashboard's stale notice.

## Refresh

From the collection repository's operating checkout, run
`tasks\publish_telegram_posts.bat`. It reads public pages, syncs the separate
dashboard operating checkout named by `WEB_DASHBOARD_REPO_PATH`, then commits
and pushes only `dashboard/data/telegram-posts.json`. A total source failure
leaves existing data untouched. A run with no changed posts makes no commit.

For a local check without a Git push:

```powershell
python scripts\collect_telegram_posts.py --output telegram-preview.json
```

Set a Windows task for `tasks\publish_telegram_posts.bat` every two hours, like
the existing `publish_x_posts` task. Point the task at the **operating**
collection checkout, never this development checkout. See
`tasks\register_telegram_posts.ps1` for an idempotent registration command.

Failures are logged to `logs\publish_telegram_posts_run_log.txt`.
