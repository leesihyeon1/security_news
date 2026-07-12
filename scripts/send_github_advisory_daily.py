import html
import json
import os
import smtplib
import urllib.parse
import urllib.request
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
import common_utils


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name.lower() == "scripts" else SCRIPT_DIR
TO_EMAIL = common_utils.DEFAULT_TO_EMAIL

SMTP_SERVER = common_utils.SMTP_SERVER
SMTP_PORT = common_utils.SMTP_PORT

GITHUB_ADVISORY_URL = "https://api.github.com/advisories"
STATE_FILE = common_utils.STATE_DIR / "github_advisory_sent_state.json"

MAX_ITEMS_PER_EMAIL = int(os.environ.get("MAX_GITHUB_ADVISORY_ITEMS_PER_EMAIL", "15"))
MIN_SEVERITIES = set(
    value.strip().lower()
    for value in os.environ.get("GITHUB_ADVISORY_SEVERITIES", "high,critical").split(",")
    if value.strip()
)
MAX_STORED_SENT_IDS = 1000


def clean_text(value):
    return common_utils.clean_text(value)


def request_json(url):
    headers = {
        "User-Agent": "daily-github-advisory-mailer/1.0",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer {}".format(token)

    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=45) as response:
        raw_data = response.read()
        charset = response.headers.get_content_charset() or "utf-8"
    return json.loads(raw_data.decode(charset, errors="replace"))


def load_state():
    return common_utils.load_json_state(STATE_FILE, lambda: {"sent_ids": []})


def save_state(sent_ids):
    common_utils.save_json_state(STATE_FILE, {"sent_ids": sent_ids}, max_items=MAX_STORED_SENT_IDS, keys_to_trim=["sent_ids"])


def advisory_link(ghsa_id):
    return "https://github.com/advisories/{}".format(urllib.parse.quote(ghsa_id))


def extract_cvss(advisory):
    cvss = advisory.get("cvss") or {}
    if not isinstance(cvss, dict):
        return {"score": "", "vector": ""}
    score = cvss.get("score")
    return {
        "score": "" if score is None else str(score),
        "vector": clean_text(cvss.get("vector_string")),
    }


def extract_identifiers(advisory):
    identifiers = advisory.get("identifiers") or []
    values = []
    for identifier in identifiers:
        if not isinstance(identifier, dict):
            continue
        value = clean_text(identifier.get("value"))
        if value:
            values.append(value)
    return values


def extract_vulnerabilities(advisory, limit=5):
    vulnerabilities = advisory.get("vulnerabilities") or []
    affected = []

    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue

        package = vulnerability.get("package") or {}
        if not isinstance(package, dict):
            package = {}

        affected.append(
            {
                "ecosystem": clean_text(package.get("ecosystem")),
                "package": clean_text(package.get("name")),
                "vulnerable_range": clean_text(vulnerability.get("vulnerable_version_range")),
                "patched_versions": clean_text(vulnerability.get("patched_versions")),
            }
        )

        if len(affected) == limit:
            break

    return affected


def fetch_github_advisories():
    query = urllib.parse.urlencode(
        {
            "type": "reviewed",
            "sort": "published",
            "direction": "desc",
            "per_page": "100",
        }
    )
    data = request_json("{}?{}".format(GITHUB_ADVISORY_URL, query))

    items = []
    for advisory in data:
        severity = clean_text(advisory.get("severity")).lower()
        if MIN_SEVERITIES and severity not in MIN_SEVERITIES:
            continue

        ghsa_id = clean_text(advisory.get("ghsa_id"))
        if not ghsa_id:
            continue

        cvss = extract_cvss(advisory)
        items.append(
            {
                "id": ghsa_id,
                "ghsa_id": ghsa_id,
                "cve_id": clean_text(advisory.get("cve_id")),
                "title": clean_text(advisory.get("summary")),
                "description": clean_text(advisory.get("description")),
                "severity": severity.upper(),
                "published": clean_text(advisory.get("published_at")),
                "updated": clean_text(advisory.get("updated_at")),
                "withdrawn": clean_text(advisory.get("withdrawn_at")),
                "cvss_score": cvss["score"],
                "cvss_vector": cvss["vector"],
                "identifiers": extract_identifiers(advisory),
                "affected": extract_vulnerabilities(advisory),
                "link": advisory_link(ghsa_id),
            }
        )

    return items


def filter_new_items(items, sent_ids):
    new_items = []
    for item in items:
        if item["id"] not in sent_ids:
            new_items.append(item)
        if len(new_items) == MAX_ITEMS_PER_EMAIL:
            break
    return new_items


def display_id(item):
    if item["severity"] == "CRITICAL":
        return "[CRITICAL] {}".format(item["ghsa_id"])
    return item["ghsa_id"]


def build_email_body(items):
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    text_body = "GitHub Security Advisory Alert\nChecked at: {}\n\n".format(checked_at)
    html_body = """
    <html>
    <body>
        <h2>GitHub Security Advisory Alert</h2>
        <p>Checked at: {checked_at}</p>
    """.format(checked_at=html.escape(checked_at))

    for idx, item in enumerate(items, start=1):
        affected_text = "\n".join(
            "- {ecosystem}/{package}, vulnerable: {vulnerable_range}, patched: {patched_versions}".format(**affected)
            for affected in item["affected"]
        )

        text_body += "{}. {}\n".format(idx, display_id(item))
        text_body += "Title: {}\n".format(item["title"])
        text_body += "Severity: {}\n".format(item["severity"])
        text_body += "CVE: {}\n".format(item["cve_id"])
        text_body += "CVSS: {}\n".format(item["cvss_score"])
        text_body += "Published: {}\n".format(item["published"])
        text_body += "Summary: {}\n".format(item["description"])
        if affected_text:
            text_body += "Affected packages:\n{}\n".format(affected_text)
        text_body += "GitHub link: {}\n\n".format(item["link"])

        html_body += """
        <hr>
        <h3>{idx}. {ghsa_id}</h3>
        <p><b>Title:</b> {title}</p>
        <p><b>Severity:</b> {severity}</p>
        <p><b>CVE:</b> {cve_id}</p>
        <p><b>CVSS:</b> {cvss_score}</p>
        <p><b>Published:</b> {published}</p>
        <p><b>Summary:</b> {description}</p>
        <p><b>GitHub link:</b> <a href="{link}">{link}</a></p>
        """.format(
            idx=idx,
            ghsa_id=html.escape(display_id(item)),
            title=html.escape(item["title"]),
            severity=html.escape(item["severity"]),
            cve_id=html.escape(item["cve_id"]),
            cvss_score=html.escape(item["cvss_score"]),
            published=html.escape(item["published"]),
            description=html.escape(item["description"]),
            link=html.escape(item["link"]),
        )

        if item["affected"]:
            html_body += "<p><b>Affected packages:</b></p><ul>"
            for affected in item["affected"]:
                html_body += "<li>{}/{}; vulnerable: {}; patched: {}</li>".format(
                    html.escape(affected["ecosystem"]),
                    html.escape(affected["package"]),
                    html.escape(affected["vulnerable_range"]),
                    html.escape(affected["patched_versions"]),
                )
            html_body += "</ul>"

    html_body += "</body></html>"
    return text_body, html_body


def build_subject(items):
    has_critical = any(item["severity"] == "CRITICAL" for item in items)
    if has_critical:
        return "[URGENT] GitHub advisory - {} item(s)".format(len(items))
    return "GitHub advisory - {} item(s)".format(len(items))


def send_email(items):
    subject = build_subject(items)
    text_body, html_body = build_email_body(items)
    common_utils.send_email_message(subject, text_body, html_body)

def send_to_slack(items):
    """메일과 동일한 데이터(items)를 받아 동일한 내용을 슬랙으로 전송"""
    if not items:
        return

    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    # 이메일 내용과 일치하도록 블록 구성
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🤖 GitHub Advisory 신규 알림", "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"🕒 {checked_at}"}]},
        {"type": "divider"}
    ]

    for item in items:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"• *{item.get('title', '제목 없음')}*\n> Severity: `{item.get('severity', 'N/A')}`\n> Link: <{item.get('link', '#')}|GitHub advisory>"
            }
        })

    payload = {"text": f"GitHub Advisory {len(items)}건이 발견되었습니다.", "blocks": blocks}
    webhook_url, _ = common_utils.select_slack_webhook(os.environ.get("SLACK_WEBHOOK_GITHUB"), items)
    common_utils.send_slack_webhook(payload, webhook_url)

def main():
    state = load_state()
    sent_ids = set(state["sent_ids"])
    items = fetch_github_advisories()
    new_items = filter_new_items(items, sent_ids)

    if not new_items:
        print("No new GitHub high/critical advisories. Email skipped.")
        return

    # [변경] 기존 이메일 대신 슬랙 발송 함수를 호출합니다.
    send_to_slack(new_items)
    send_email(new_items)
    save_state(state["sent_ids"] + [item["id"] for item in new_items])
    print("Email sent: GitHub advisories {}".format(len(new_items)))


if __name__ == "__main__":
    main()
