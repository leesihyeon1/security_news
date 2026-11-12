"""Collect recent public X post URLs through the official X API v2.

The dashboard renders each saved URL with X's official single-post embed. The
profile timeline embed and scripted profile pages are not used: X rejects the
former with 429 for anonymous visitors and does not permit the latter.

Requires X_BEARER_TOKEN (app-only bearer token from the X Developer Console).
Without it, nothing is fetched and the existing file stays as it is. Reads are
billed per returned post, so each account asks only for posts newer than the
newest saved one (since_id) and the run makes no retries.
"""

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

API = "https://api.x.com/2"
TIMEOUT_SECONDS = 15
ACCOUNTS = {
    "breaking": ("DarkWebInformer", "DailyDarkWeb", "TheHackersNews", "vxunderground"),
    "insight": ("SwiftOnSecurity", "briankrebs", "troyhunt", "cyb3rops", "skim71"),
}
OUTPUT = Path(__file__).resolve().parents[2] / "boannews_vercel_deploy" / "dashboard" / "data" / "x-posts.json"
POST_RE = re.compile(r"^https://(?:www\.)?(?:x|twitter)\.com/([A-Za-z0-9_]{1,15})/status/(\d+)(?:[/?#].*)?$", re.I)
ID_RE = re.compile(r"^\d{1,25}$")


class RateLimited(RuntimeError):
    pass


def normalize_post(url, account):
    match = POST_RE.match(url or "")
    if not match or match.group(1).lower() != account.lower():
        return None
    return f"https://x.com/{account}/status/{match.group(2)}"


def post_id(url):
    return int(url.rsplit("/", 1)[-1])


def _get(session, path, token, params):
    response = session.get(API + path, params=params, timeout=TIMEOUT_SECONDS,
                           headers={"Authorization": "Bearer " + token, "User-Agent": "security-news-dashboard"})
    if response.status_code == 429:
        raise RateLimited("X API rate limit (reset {})".format(response.headers.get("x-rate-limit-reset", "?")))
    if response.status_code in (401, 403):
        # Never echo the token or response body; a status code is enough to act on.
        raise RuntimeError("X API rejected the token ({})".format(response.status_code))
    response.raise_for_status()
    return response.json()


def lookup_user_ids(session, token, names):
    data = _get(session, "/users/by", token, {"usernames": ",".join(names)})
    return {row["username"].lower(): row["id"] for row in data.get("data", [])
            if ID_RE.match(str(row.get("id", ""))) and row.get("username")}


def recent_posts(session, token, user_id, account, since_id=None):
    params = {"max_results": 5, "exclude": "retweets,replies", "tweet.fields": "created_at"}
    if since_id:
        params["since_id"] = str(since_id)
    data = _get(session, "/users/{}/tweets".format(user_id), token, params)
    rows = []
    for tweet in data.get("data", []):
        if ID_RE.match(str(tweet.get("id", ""))):
            rows.append({"url": f"https://x.com/{account}/status/{tweet['id']}",
                         "created_at": tweet.get("created_at")})
    return rows


def load_existing(output):
    if not output.exists():
        return {}, {}
    data = json.loads(output.read_text(encoding="utf-8"))
    old = {}
    for item in data.get("posts", []):
        author = item.get("author") if isinstance(item, dict) else None
        url = normalize_post(item.get("url"), author) if author else None
        if url:
            old.setdefault(author.lower(), []).append({**item, "url": url})
    ids = {k.lower(): v for k, v in (data.get("accounts") or {}).items() if ID_RE.match(str(v))}
    return old, ids


def refresh(output, token, per_account=3, session=None, now=None):
    """Update output with the newest posts. Returns the number of new posts found."""
    session = session or requests.Session()
    now = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    old, ids = load_existing(output)
    names = [name for group in ACCOUNTS.values() for name in group]
    missing = [name for name in names if name.lower() not in ids]
    if missing:
        ids.update(lookup_user_ids(session, token, missing))

    posts, added, limited = [], 0, False
    for group, accounts in ACCOUNTS.items():
        for account in accounts:
            saved = old.get(account.lower(), [])
            fresh = []
            if not limited and account.lower() in ids:
                newest = max((post_id(p["url"]) for p in saved), default=None)
                try:
                    fresh = recent_posts(session, token, ids[account.lower()], account, newest)
                except RateLimited as error:
                    print("[!] {}: {} - 나머지 계정은 이전 목록을 유지합니다".format(account, error))
                    limited = True
                except (OSError, ValueError) as error:
                    print("[!] {}: 건너뜀 ({})".format(account, type(error).__name__))
            known = {p["url"] for p in saved}
            fresh = [dict(p, author=account, group=group, collected_at=now) for p in fresh if p["url"] not in known]
            added += len(fresh)
            merged = sorted(fresh + [dict(p, group=group) for p in saved], key=lambda p: post_id(p["url"]), reverse=True)
            posts.extend(merged[:per_account])

    if not posts:
        raise RuntimeError("No posts collected; existing output was not changed")
    posts.sort(key=lambda p: post_id(p["url"]), reverse=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_suffix(".json.tmp")
    accounts = {name: ids[name.lower()] for name in names if name.lower() in ids}
    pending.write_text(json.dumps({"updated_at": now, "accounts": accounts, "posts": posts},
                                  ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    pending.replace(output)
    return added


def publish(data_dir, per_account=3):
    """Dashboard publish hook: a no-op unless X_BEARER_TOKEN is configured."""
    token = os.environ.get("X_BEARER_TOKEN", "").strip()
    if not token:
        return None
    added = refresh(Path(data_dir) / "x-posts.json", token, per_account)
    print("[*] X 게시물 새로 {}건".format(added))
    return added


def main():
    import common_utils

    common_utils.load_env_file()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--per-account", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.per_account <= 5:
        parser.error("--per-account must be between 1 and 5")
    token = os.environ.get("X_BEARER_TOKEN", "").strip()
    if not token:
        parser.error("X_BEARER_TOKEN is not set (.env)")
    added = refresh(args.output, token, args.per_account)
    print("Saved to {} (new posts: {})".format(args.output, added))


if __name__ == "__main__":
    main()
