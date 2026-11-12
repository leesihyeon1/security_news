"""Collect public X post URLs with a locally authenticated Chromium profile.

Run --login once to sign in interactively. This is an opt-in local job; it does
not solve challenges, retry blocked requests, or store session data in Git.
"""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


ACCOUNTS = {
    "insight": ("SwiftOnSecurity", "briankrebs", "troyhunt", "cyb3rops", "skim71"),
    "breaking": ("DarkWebInformer", "DailyDarkWeb", "TheHackersNews", "vxunderground"),
}
PROFILE = Path.home() / ".boannews-x-profile"
OUTPUT = Path(__file__).resolve().parents[2] / "boannews_vercel_deploy" / "dashboard" / "data" / "x-posts.json"
POST_RE = re.compile(r"^https://(?:x|twitter)\.com/([A-Za-z0-9_]{1,15})/status/(\d+)(?:[/?#].*)?$", re.I)


def normalize_post(url, account):
    match = POST_RE.match(url)
    if not match or match.group(1).lower() != account.lower():
        return None
    return f"https://x.com/{account}/status/{match.group(2)}"


def extract_posts(links, account, limit=2):
    found = {post for link in links if (post := normalize_post(link, account))}
    return sorted(found, key=lambda url: int(url.rsplit("/", 1)[-1]), reverse=True)[:limit]


def refresh(output, profile, per_account):
    from playwright.sync_api import sync_playwright

    old = {}
    if output.exists():
        data = json.loads(output.read_text(encoding="utf-8"))
        for item in data.get("posts", []):
            if isinstance(item, dict) and item.get("author"):
                old.setdefault(item["author"].lower(), []).append(item)

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    posts = []
    with sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(
            str(profile), headless=False, viewport={"width": 1280, "height": 900}
        )
        page = context.new_page()
        try:
            for group, accounts in ACCOUNTS.items():
                for account in accounts:
                    try:
                        page.goto(f"https://x.com/{account}", wait_until="domcontentloaded", timeout=30000)
                        page.locator("article").first.wait_for(timeout=15000)
                        links = page.locator("article a[href*='/status/']").evaluate_all(
                            "nodes => nodes.map(node => node.href)"
                        )
                        urls = extract_posts(links, account, per_account)
                        if not urls:
                            raise RuntimeError("no post URLs found")
                        posts.extend({"url": url, "author": account, "group": group, "collected_at": now} for url in urls)
                        print(f"{account}: {len(urls)}")
                    except Exception as exc:
                        print(f"{account}: skipped ({type(exc).__name__}: {exc})")
                        posts.extend(old.get(account.lower(), [])[:per_account])
        finally:
            context.close()

    if not posts:
        raise RuntimeError("No posts collected; existing output was not changed")
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_suffix(".json.tmp")
    pending.write_text(json.dumps({"posts": posts}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    pending.replace(output)
    print(f"Saved {len(posts)} URLs to {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--login", action="store_true", help="open Chromium for interactive X sign-in")
    parser.add_argument("--profile", type=Path, default=PROFILE)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--per-account", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.per_account <= 5:
        parser.error("--per-account must be between 1 and 5")
    if args.login:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(str(args.profile), headless=False)
            page = context.new_page()
            page.goto("https://x.com/login")
            input("Sign in in Chromium, then press Enter here to close it: ")
            context.close()
        return
    refresh(args.output, args.profile, args.per_account)


if __name__ == "__main__":
    main()
