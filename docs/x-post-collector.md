# X post URL collector

The dashboard's X panel embeds posts listed in `dashboard/data/x-posts.json`
with X's official single-post embed. This local tool fills that file: it opens
the profiles in `ACCOUNTS` (`scripts/collect_x_post_urls.py`) in a normal
Microsoft Edge window placed off-screen with a dedicated profile and keeps only post
URLs (newest first, reposts of other authors excluded).

- Edge is used because Playwright's bundled Chromium fails to start on this PC
  ("side-by-side configuration is incorrect"); the bundled one is the fallback.
- Headless runs are not used: X answers them with an HTTP error.
- Signing in is optional; X serves public profiles to signed-out visitors.

## One-time setup

```powershell
python -m pip install -r requirements-x-collector.txt
```

Optional: `python scripts\collect_x_post_urls.py --login`, sign in in the
window that opens, then press Enter in the terminal. The profile lives in
`~/.boannews-x-profile`; nothing is stored in Git.

## Refreshing

`tasks\publish_x_posts.bat` runs `--push` (scheduled task `publish_x_posts`):
it collects, syncs the dashboard clone (`WEB_DASHBOARD_REPO_PATH`),
writes `x-posts.json`, and commits and pushes only that file, so Vercel deploys
the new list. Runs within 2 hours of the last refresh are skipped (`--force`
overrides), and a run with no new posts makes no commit.

Writing the file without committing is not enough: the report publisher resets
`dashboard/data` to the remote at each run, which would discard it.

Without `--push` it writes to the sibling `boannews_vercel_deploy` clone
without committing.

## Failures

Accounts that fail keep their previously saved URLs. If X starts requiring a
sign-in, the run stops with `login required; run --login` in
`logs\publish_x_posts_run_log.txt`.
The tool does not solve challenges or retry blocked pages. X may restrict
scripted access to signed-in accounts; keep the interval modest.
