"""Focused offline checks for public Telegram channel collection."""

import json
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import collect_telegram_posts as telegram

NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
CHANNEL = {"handle": "RansomFeedNews", "label": "Ransomfeed News", "kind": "ransomware_feed"}


def message(number, date, body, handle="RansomFeedNews"):
    return (f'<div class="tgme_widget_message" data-post="{handle}/{number}">'
            f'<div class="tgme_widget_message_text">{body}</div>'
            f'<time datetime="{date}"></time></div>')


class TelegramCollectorTests(unittest.TestCase):
    def test_parse_keeps_recent_claims_and_source_permalink(self):
        html = (message(3, "2026-11-13T10:00:00+00:00", "🥷 Group X 🎯 Example Corp, USA")
                + message(2, "2026-10-01T10:00:00+00:00", "Old victim")
                + message(1, "2026-11-13T10:00:00+00:00", "Wrong channel", "OtherChannel"))
        posts = telegram.parse_page(html, CHANNEL, NOW)
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]["url"], "https://t.me/RansomFeedNews/3")
        self.assertEqual(posts[0]["source_type"], "집계 채널")
        self.assertEqual(posts[0]["excerpt"], "Group X · Example Corp, USA")

    def test_plain_channel_requires_claim_signal(self):
        channel = {"handle": "PublicClaims", "label": "Claims", "kind": "claims"}
        html = (message(2, "2026-11-13T10:00:00+00:00", "Routine hello", "PublicClaims")
                + message(3, "2026-11-13T11:00:00+00:00", "We leaked data", "PublicClaims"))
        posts = telegram.parse_page(html, channel, NOW)
        self.assertEqual([p["url"] for p in posts], ["https://t.me/PublicClaims/3"])

    def test_public_excerpt_removes_links_and_contacts(self):
        excerpt = telegram.safe_excerpt("Leak at https://bad.example/path user@example.com +82 10-1234-5678")
        self.assertNotIn("bad.example", excerpt)
        self.assertNotIn("user@example.com", excerpt)
        self.assertNotIn("1234-5678", excerpt)

    def test_failed_source_keeps_recent_post_but_expires_old_one(self):
        recent = {"channel": "RansomFeedNews", "published_at": (NOW - timedelta(days=1)).isoformat(), "url": "https://t.me/RansomFeedNews/1"}
        old = {"channel": "RansomFeedNews", "published_at": (NOW - timedelta(days=8)).isoformat(), "url": "https://t.me/RansomFeedNews/2"}
        merged = telegram.merge({"posts": [recent, old]}, {}, [CHANNEL], NOW)
        self.assertEqual(merged["posts"], [recent])

    def test_merge_selects_newest_posts_before_channel_limit(self):
        older = {"channel": "RansomFeedNews", "published_at": (NOW - timedelta(days=2)).isoformat()}
        newer = {"channel": "RansomFeedNews", "published_at": (NOW - timedelta(days=1)).isoformat()}
        merged = telegram.merge({}, {"RansomFeedNews": [older, newer]}, [CHANNEL], NOW, per_channel=1)
        self.assertEqual(merged["posts"], [newer])

    def test_total_fetch_failure_never_overwrites_previous_output(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "telegram-posts.json"
            original = {"updated_at": "2026-11-12T00:00:00+00:00", "posts": []}
            output.write_text(json.dumps(original), encoding="utf-8")

            def fail(_handle):
                raise OSError("network down")

            with self.assertRaises(RuntimeError):
                telegram.refresh(output, [CHANNEL], NOW, fetch=fail)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), original)


if __name__ == "__main__":
    unittest.main()
