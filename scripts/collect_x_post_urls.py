"""Collect recent public X post URLs with a locally signed-in Chromium profile.

Each run opens the accounts in ACCOUNTS in a normal Microsoft Edge window placed
off-screen (so it does not pop up while the PC is in use), keeps only post
URLs, and saves them to the dashboard's x-posts.json,
which the dashboard renders with X's official single-post embed. Signing in
(--login, once) is optional; X serves public profiles to signed-out visitors.
Headless runs are not used: X rejects them.

--push refreshes the file inside the dashboard clone and commits and pushes it
(scheduled via tasks/publish_x_posts.bat). It does not solve challenges or retry
blocked pages; accounts that fail keep their previously saved URLs.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ACCOUNTS = {
    "breaking": ("DarkWebInformer", "DailyDarkWeb", "TheHackersNews", "vxunderground"),
    "insight": ("SwiftOnSecurity", "troyhunt", "cyb3rops", "skim71"),
}
PROFILE = Path.home() / ".boannews-x-profile"
OUTPUT = Path(__file__).resolve().parents[2] / "boannews_vercel_deploy" / "dashboard" / "data" / "x-posts.json"
RELATIVE_OUTPUT = "dashboard/data/x-posts.json"
POST_RE = re.compile(r"^https://(?:www\.)?(?:x|twitter)\.com/([A-Za-z0-9_]{1,15})/status/(\d+)(?:[/?#].*)?$", re.I)
# Guards against back-to-back runs; the task itself runs every 2 hours.
MIN_INTERVAL = timedelta(minutes=90)
# An account that has not loaded for this long is reported, like a stalled news source.
ACCOUNT_STALE_AFTER = timedelta(hours=24)
STATE_NAME = "x_posts_health.json"


def normalize_post(url, account):
    match = POST_RE.match(url or "")
    if not match or match.group(1).lower() != account.lower():
        return None
    return f"https://x.com/{account}/status/{match.group(2)}"


def post_id(url):
    return int(url.rsplit("/", 1)[-1])


def extract_posts(links, account, limit=2):
    found = {post for link in links if (post := normalize_post(link, account))}
    return sorted(found, key=post_id, reverse=True)[:limit]


def load(output):
    if not output.exists():
        return {}
    return json.loads(output.read_text(encoding="utf-8"))


def is_due(data, now, interval=MIN_INTERVAL):
    try:
        updated = datetime.fromisoformat(data.get("checked_at") or data["updated_at"])
    except (KeyError, TypeError, ValueError):
        return True
    return now - updated >= interval


def open_browser(playwright, profile, hidden=True):
    """Installed Edge first: Playwright's bundled Chromium fails to start on some PCs."""
    options = {"headless": False, "viewport": {"width": 1280, "height": 900},
               # A real (non-headless) window, just positioned off the visible desktop.
               "args": ["--window-position=-32000,-32000", "--window-size=1280,900"] if hidden else []}
    try:
        return playwright.chromium.launch_persistent_context(str(profile), channel="msedge", **options)
    except Exception as exc:
        print(f"Edge unavailable ({type(exc).__name__}); trying bundled Chromium")
        return playwright.chromium.launch_persistent_context(str(profile), **options)


def scrape(profile, accounts, per_account):
    """Return {account: [urls]} for accounts that loaded; failures are left out."""
    from playwright.sync_api import sync_playwright

    found = {}
    with sync_playwright() as playwright:
        context = open_browser(playwright, profile)
        page = context.new_page()
        try:
            for account in accounts:
                try:
                    page.goto(f"https://x.com/{account}", wait_until="domcontentloaded", timeout=30000)
                    try:
                        page.locator("article a[href*='/status/']").first.wait_for(timeout=20000)
                    except Exception:
                        if "/login" in page.url or "/i/flow/" in page.url:
                            raise RuntimeError("login required; run --login") from None
                        raise
                    page.wait_for_timeout(1500)  # let the first screen of posts render
                    links = page.locator("article a[href*='/status/']").evaluate_all(
                        "nodes => nodes.map(node => node.href)"
                    )
                    urls = extract_posts(links, account, per_account)
                    if not urls:
                        raise RuntimeError("no post URLs found")
                    found[account] = urls
                    print(f"{account}: {len(urls)}")
                except Exception as exc:
                    print(f"{account}: skipped ({type(exc).__name__}: {str(exc).splitlines()[0]})")
                    if "login required" in str(exc):
                        break
        finally:
            context.close()
    return found


def merge(data, found, per_account, now):
    """New post list: fresh URLs first, previous ones fill in for failed accounts."""
    old = {}
    for item in data.get("posts", []):
        author = item.get("author") if isinstance(item, dict) else None
        url = normalize_post(item.get("url"), author) if author else None
        if url:
            old.setdefault(author.lower(), []).append({**item, "url": url})
    stamp = now.isoformat(timespec="seconds")
    posts = []
    for group, accounts in ACCOUNTS.items():
        for account in accounts:
            previous = {p["url"]: p for p in old.get(account.lower(), [])}
            if account in found:
                rows = [previous.get(url) or {"url": url, "author": account, "collected_at": stamp}
                        for url in found[account]]
            else:
                rows = list(previous.values())
            rows = sorted(({**row, "group": group} for row in rows), key=lambda p: post_id(p["url"]), reverse=True)
            posts.extend(rows[:per_account])
    posts.sort(key=lambda p: post_id(p["url"]), reverse=True)
    # Same list as before: keep the file byte-identical so no commit or deploy follows.
    if posts == data.get("posts"):
        return data
    return {"updated_at": stamp, "posts": posts}


def write(output, data):
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_suffix(".json.tmp")
    pending.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    pending.replace(output)


def record_health(state_path, found, now, accounts=None):
    """Remember each account's last successful load; return accounts failing for too long."""
    try:
        state = json.loads(Path(state_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    stamp = now.isoformat(timespec="seconds")
    stale = []
    for account in accounts or all_accounts():
        if account in found:
            state[account] = stamp
            continue
        state.setdefault(account, stamp)  # first sighting starts the clock
        if now - datetime.fromisoformat(state[account]) > ACCOUNT_STALE_AFTER:
            stale.append(account)
    Path(state_path).parent.mkdir(parents=True, exist_ok=True)
    Path(state_path).write_text(json.dumps(state, indent=1), encoding="utf-8")
    return stale


def all_accounts():
    return [account for accounts in ACCOUNTS.values() for account in accounts]


def refresh(output, profile, per_account, now=None):
    now = now or datetime.now(timezone.utc)
    data = load(output)
    found = scrape(profile, all_accounts(), per_account)
    if not found:
        raise RuntimeError("No posts collected; existing output was not changed")
    write(output, merge(data, found, per_account, now))
    print(f"Saved {len(found)} accounts to {output}")
    return len(found)


def push(repo_path, profile, per_account, force=False, now=None, state_path=None):
    """Refresh x-posts.json in the dashboard clone, then commit and push only that file.

    Returns a process exit code: 0 when healthy (including "nothing new"), 1 when
    nothing loaded, publishing failed, or an account has failed for over a day.
    The task's non-zero result is what task_health reports to Slack.
    """
    import publish_web_dashboard as pwd

    now = now or datetime.now(timezone.utc)
    repo = Path(repo_path or pwd.REPO_PATH)
    if not str(repo_path or pwd.REPO_PATH) or not pwd._validate_publish_repo(repo):
        print("[-] WEB_DASHBOARD_REPO_PATH is not a usable dashboard clone")
        return 1
    if state_path is None:
        import common_utils
        state_path = common_utils.STATE_DIR / STATE_NAME
    target = repo / RELATIVE_OUTPUT
    try:
        last = json.loads(Path(state_path).read_text(encoding="utf-8")).get("_last_run")
    except (OSError, ValueError, AttributeError):
        last = None
    if not force and not is_due({"checked_at": last} if last else load(target), now):
        print("[*] X posts were refreshed recently; skipped")
        return 0
    # Browse outside the repo lock: a slow page must not hold up the report publisher.
    found = scrape(profile, all_accounts(), per_account)
    stale = record_health(state_path, found, now)
    state = json.loads(Path(state_path).read_text(encoding="utf-8"))
    state["_last_run"] = now.isoformat(timespec="seconds")
    Path(state_path).write_text(json.dumps(state, indent=1), encoding="utf-8")
    if stale:
        print("[-] No successful load for over {}h: {}".format(
            int(ACCOUNT_STALE_AFTER.total_seconds() // 3600), ", ".join(stale)))
    if not found:
        print("[-] No posts collected; nothing published")
        return 1
    try:
        published = _commit_and_push(pwd, repo, target, found, per_account, now)
    except Exception as error:  # git or lock failure: the next run rebases and retries
        print("[-] X posts publish failed: {}".format(pwd.redact_url(str(error))))
        return 1
    if published:
        print(f"[+] Published X posts from {len(found)} accounts")
    return 1 if stale else 0


def _commit_and_push(pwd, repo, target, found, per_account, now):
    with pwd.repo_lock(repo):
        branch = pwd._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo).strip()
        # Sync first: the report publisher resets dashboard/data to origin, so an
        # uncommitted x-posts.json would be lost at its next run.
        pwd._sync_to_remote_head(repo, branch)
        write(target, merge(load(target), found, per_account, now))
        pwd._run_git(["add", RELATIVE_OUTPUT], cwd=repo)
        if not pwd._has_staged_changes(RELATIVE_OUTPUT, cwd=repo):
            print("[*] No new X posts")
            return False
        pwd._run_git(["commit", "-m", "Update X posts"], cwd=repo)
        pwd._run_git(["push", "origin", branch], cwd=repo)
    return True


def main():
    import common_utils

    common_utils.load_env_file()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--login", action="store_true", help="open Chromium for interactive X sign-in")
    parser.add_argument("--push", action="store_true", help="refresh, commit and push x-posts.json in the dashboard clone")
    parser.add_argument("--force", action="store_true", help="with --push, ignore the minimum refresh interval")
    parser.add_argument("--profile", type=Path, default=PROFILE)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--per-account", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.per_account <= 5:
        parser.error("--per-account must be between 1 and 5")
    if args.login:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            context = open_browser(playwright, args.profile, hidden=False)
            page = context.new_page()
            page.goto("https://x.com/login")
            input("Sign in in Chromium, then press Enter here to close it: ")
            context.close()
        return
    if args.push:
        sys.exit(push(None, args.profile, args.per_account, force=args.force))
    refresh(args.output, args.profile, args.per_account)


if __name__ == "__main__":
    main()
