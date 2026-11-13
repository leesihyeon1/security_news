"""Collect public Telegram channel claims for the dashboard.

Only Telegram's public /s/ pages are read. No account, bot token, media download,
or linked leak site is used. The dashboard receives short text excerpts and links
back to Telegram; every item remains an unverified source claim.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

CHANNELS_FILE = Path(__file__).resolve().parents[1] / "assets" / "telegram_channels.json"
OUTPUT = Path(__file__).resolve().parents[2] / "boannews_vercel_deploy" / "dashboard" / "data" / "telegram-posts.json"
RELATIVE_OUTPUT = "dashboard/data/telegram-posts.json"
HANDLE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,31}$")
POST_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]{4,31})/(\d+)$")
SIGNALS = {
    "유출 주장": re.compile(r"leak|breach|exfiltrat|stolen data|data dump|유출|침해|탈취|해킹", re.I),
    "판매·모집": re.compile(r"for sale|selling|recruit|affiliate|initial access|판매|모집|구인", re.I),
    "랜섬웨어 주장": re.compile(r"ransom|victim|extort|랜섬|인질", re.I),
}
MAX_AGE = timedelta(days=7)


class ChannelPage(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.posts = []
        self.current = None
        self.depth = 0
        self.text_depth = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = set(attrs.get("class", "").split())
        if tag == "div" and self.current is None and "data-post" in attrs:
            self.current = {"id": attrs["data-post"], "date": None, "parts": []}
            self.depth = 1
            return
        if self.current is None:
            return
        if tag == "div":
            self.depth += 1
            if "tgme_widget_message_text" in classes:
                self.text_depth = self.depth
        elif tag == "time":
            self.current["date"] = attrs.get("datetime")
        elif tag == "br" and self.text_depth is not None:
            self.current["parts"].append(" ")

    def handle_endtag(self, tag):
        if self.current is None or tag != "div":
            return
        if self.text_depth == self.depth:
            self.text_depth = None
        self.depth -= 1
        if self.depth == 0:
            self.posts.append(self.current)
            self.current = None

    def handle_data(self, data):
        if self.current is not None and self.text_depth is not None:
            self.current["parts"].append(data)


def channels(path=CHANNELS_FILE):
    rows = json.loads(Path(path).read_text(encoding="utf-8"))["channels"]
    result = []
    for row in rows:
        handle = row["handle"]
        if not HANDLE_RE.fullmatch(handle):
            raise ValueError(f"Invalid Telegram handle: {handle!r}")
        result.append({"handle": handle, "label": row["label"],
                       "kind": row.get("kind", "claims")})
    if not result:
        raise ValueError("No Telegram channels configured")
    return result


def fetch_page(handle):
    request = Request(f"https://t.me/s/{handle}", headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityNews/1.0)"})
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise ValueError("Telegram redirected; page was not read")

    with build_opener(NoRedirect).open(request, timeout=20) as response:
        if urlparse(response.geturl()).hostname not in {"t.me", "www.t.me"}:
            raise ValueError("Telegram redirected outside t.me")
        data = response.read(1_000_001)
        if len(data) > 1_000_000:
            raise ValueError("Telegram page exceeds 1 MB")
        return data.decode("utf-8", errors="replace")


def safe_excerpt(value):
    value = re.sub(r"https?://\S+|t\.me/\S+", " ", value)
    value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[이메일 생략]", value)
    value = re.sub(r"(?<!\d)(?:\+?\d[\d ()-]{8,}\d)(?!\d)", "[번호 생략]", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:240].rstrip()


def parse_page(html, channel, now):
    parser = ChannelPage()
    parser.feed(html)
    if not parser.posts:
        raise ValueError("No public messages found")
    result = []
    for item in parser.posts:
        match = POST_RE.fullmatch(item["id"])
        if not match or match.group(1).lower() != channel["handle"].lower():
            continue
        try:
            published = datetime.fromisoformat(item["date"]).astimezone(timezone.utc)
        except (TypeError, ValueError):
            continue
        if not timedelta(0) <= now - published <= MAX_AGE:
            continue
        raw = " ".join(item["parts"])
        if channel["kind"] == "ransomware_feed":
            claim = re.search(r"🥷\s*(.*?)\s*🎯\s*(.*?)(?:\s*🔗|$)", raw, re.S)
            if not claim:
                continue
            raw = f"{claim.group(1).strip()} · {claim.group(2).strip()}"
        category = next((label for label, pattern in SIGNALS.items() if pattern.search(raw)), None)
        if channel["kind"] != "ransomware_feed" and category is None:
            continue
        excerpt = safe_excerpt(raw)
        if not excerpt:
            continue
        result.append({"url": f"https://t.me/{channel['handle']}/{match.group(2)}",
                       "channel": channel["handle"], "channel_label": channel["label"],
                       "published_at": published.isoformat(timespec="seconds"),
                       "category": category or "랜섬웨어 주장", "excerpt": excerpt,
                       "source_type": "집계 채널" if channel["kind"] == "ransomware_feed" else "공개 채널"})
    return result


def collect(config, now, fetch=fetch_page):
    found = {}
    for channel in config:
        try:
            rows = parse_page(fetch(channel["handle"]), channel, now)
            found[channel["handle"]] = rows
            print(f"{channel['handle']}: {len(rows)} relevant posts")
        except Exception as exc:
            print(f"{channel['handle']}: skipped ({type(exc).__name__}: {str(exc).splitlines()[0]})")
    return found


def merge(existing, found, config, now, per_channel=12):
    previous = existing.get("posts", [])
    enabled = {row["handle"] for row in config}
    posts = []
    for handle in enabled:
        rows = found.get(handle)
        if rows is None:
            rows = [row for row in previous if row.get("channel") == handle]
        posts.extend(sorted(rows, key=lambda row: row["published_at"], reverse=True)[:per_channel])
    fresh = []
    for row in posts:
        try:
            age = now - datetime.fromisoformat(row["published_at"]).astimezone(timezone.utc)
        except (KeyError, TypeError, ValueError):
            continue
        if timedelta(0) <= age <= MAX_AGE:
            fresh.append(row)
    fresh.sort(key=lambda row: row["published_at"], reverse=True)
    if fresh == previous:
        return existing
    return {"updated_at": now.isoformat(timespec="seconds"), "posts": fresh}


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def refresh(output, config, now, fetch=fetch_page):
    found = collect(config, now, fetch)
    if not found:
        raise RuntimeError("No Telegram channels loaded; existing output was not changed")
    existing = json.loads(output.read_text(encoding="utf-8")) if output.exists() else {}
    merged = merge(existing, found, config, now)
    if merged != existing:
        write(output, merged)
    return merged != existing


def push(repo, config, now, fetch=fetch_page):
    import publish_web_dashboard as publisher
    if not publisher._validate_publish_repo(repo):
        raise ValueError("WEB_DASHBOARD_REPO_PATH is not a usable dashboard clone")
    # Fetch before taking the shared publishing lock.
    found = collect(config, now, fetch)
    if not found:
        raise RuntimeError("No Telegram channels loaded; nothing published")
    target = repo / RELATIVE_OUTPUT
    with publisher.repo_lock(repo):
        branch = publisher._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo).strip()
        publisher._sync_to_remote_head(repo, branch)
        existing = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
        merged = merge(existing, found, config, now)
        if merged == existing:
            print("[*] No new Telegram posts")
            return False
        write(target, merged)
        publisher._run_git(["add", RELATIVE_OUTPUT], cwd=repo)
        if not publisher._has_staged_changes(RELATIVE_OUTPUT, cwd=repo):
            return False
        publisher._run_git(["commit", "-m", "Update Telegram posts"], cwd=repo)
        publisher._run_git(["push", "origin", branch], cwd=repo)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--push", action="store_true")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--channels", type=Path, default=CHANNELS_FILE)
    args = parser.parse_args()
    config = channels(args.channels)
    now = datetime.now(timezone.utc)
    if args.push:
        import common_utils
        common_utils.load_env_file()
        import publish_web_dashboard as publisher
        if not publisher.REPO_PATH:
            parser.error("WEB_DASHBOARD_REPO_PATH is required for --push")
        changed = push(Path(publisher.REPO_PATH), config, now)
    else:
        changed = refresh(args.output, config, now)
    print("[+] Telegram posts updated" if changed else "[*] Telegram posts unchanged")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"[-] Telegram collection failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
