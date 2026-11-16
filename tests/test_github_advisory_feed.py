import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import github_advisory_feed


class GithubAdvisoryFeedTests(unittest.TestCase):
    def test_snapshot_keeps_recent_public_advisories_only(self):
        events = [
            {"source": "github_advisory", "id": "github_advisory:GHSA-2p2h-g9qq-v2wx",
             "published_at": "2026-11-15T12:00:00+00:00", "severity": "HIGH",
             "title": "Package issue", "cves": ["CVE-2026-12345"], "matched_assets": ["private-host"]},
            {"source": "github_advisory", "id": "github_advisory:GHSA-2p2h-g9qq-v2wx",
             "published_at": "2026-11-15T12:00:00+00:00", "severity": "HIGH", "title": "Package issue",
             "cves": ["CVE-2026-12345"]},
            {"source": "github_advisory", "id": "github_advisory:GHSA-3p2h-g9qq-v2wx",
             "published_at": "2026-10-01T12:00:00+00:00", "severity": "CRITICAL", "title": "Old issue"},
            {"source": "nvd", "id": "CVE-2026-12345", "published_at": "2026-11-15T12:00:00+00:00"},
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "events.jsonl"
            source.write_text("\n".join(json.dumps(row) for row in events), encoding="utf-8")
            snapshot = github_advisory_feed.build_snapshot(source, datetime(2026, 11, 16, tzinfo=timezone.utc))
        self.assertEqual(len(snapshot["items"]), 1)
        self.assertEqual(snapshot["items"][0]["url"], "https://github.com/advisories/GHSA-2P2H-G9QQ-V2WX")
        self.assertEqual(snapshot["items"][0]["cve"], "CVE-2026-12345")
        self.assertNotIn("private-host", json.dumps(snapshot))
        self.assertEqual(snapshot["last_published_at"], "2026-11-15T12:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
