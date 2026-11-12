# X post collector

The dashboard's X panel shows recent posts from a fixed list of security
accounts (`ACCOUNTS` in `scripts/collect_x_post_urls.py`) with X's official
single-post embed. Post URLs come from the official X API v2
(`GET /2/users/:id/tweets`, excluding reposts and replies).

Why not other routes:

- The profile timeline embed (`twitter-timeline`) is rejected by X with
  `429 Rate limit exceeded` for anonymous visitors.
- Opening profile pages with a signed-in browser and reading links is scraping,
  which X does not permit, and it breaks on login challenges.

## Setup

1. Create an app in the X Developer Console and copy its Bearer Token.
2. Add `X_BEARER_TOKEN=...` to the local `.env` (never commit it).

The daily dashboard publish then refreshes `dashboard/data/x-posts.json` and
commits it with the other data files. Without the token the step is skipped and
the last saved list stays. To run it on its own:

```powershell
.venv\Scripts\python.exe scripts\collect_x_post_urls.py
```

## Cost and limits

X bills API reads per returned post. Each account asks only for posts newer
than its newest saved one (`since_id`, at most 5), and user IDs are cached in
the output file, so a run with no new posts costs little. A 429 stops further
requests for that run without retrying; the previous posts are kept.
