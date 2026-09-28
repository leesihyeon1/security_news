import html
import json
import os
import smtplib
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
import common_utils

# Windows 콘솔(cp949)에서 특수문자 출력이 죽지 않도록 UTF-8로 강제
for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")


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
                "patched_versions": clean_text(vulnerability.get("first_patched_version")),
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


def affected_product_names(item):
    """[{ecosystem, package, ...}] → ["npm/lodash", ...]"""
    names = []
    for entry in item.get("affected") or []:
        package = entry.get("package")
        if not package:
            continue
        ecosystem = entry.get("ecosystem")
        names.append("{}/{}".format(ecosystem, package) if ecosystem else package)
    return names


def has_patched_version(item):
    """패치 버전이 하나라도 명시되어 있으면 True, 전부 없으면 False, 패키지 정보 자체가 없으면 None"""
    affected = item.get("affected") or []
    if not affected:
        return None
    return any(entry.get("patched_versions") for entry in affected)


def build_remediation(item):
    """패키지별 패치 버전을 조치 지침 텍스트로 변환"""
    lines = []
    for entry in item.get("affected") or []:
        if entry.get("package") and entry.get("patched_versions"):
            lines.append("{} {} 이상으로 업데이트".format(entry["package"], entry["patched_versions"]))
    return "; ".join(lines)


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
        tracked_link = common_utils.tracking_url("github_advisory:{}".format(item["id"]), item["link"])
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
        text_body += "GitHub link: {}\n\n".format(tracked_link)

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
            link=html.escape(tracked_link),
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
    has_p1 = any((item.get("triage") or {}).get("level") == "P1" for item in items)
    has_critical = any(item["severity"] == "CRITICAL" for item in items)
    if has_p1:
        return "[P1] GitHub advisory - {} item(s)".format(len(items))
    if has_critical:
        return "[URGENT] GitHub advisory - {} item(s)".format(len(items))
    return "GitHub advisory - {} item(s)".format(len(items))


def send_email(items):
    subject = build_subject(items)
    text_body, html_body = build_email_body(items)
    return common_utils.send_email_message(subject, text_body, html_body)

def send_to_slack(items):
    """메일과 동일한 데이터(items)를 받아 동일한 내용을 슬랙으로 전송"""
    if not items:
        return False

    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    # 이메일 내용과 일치하도록 블록 구성
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🤖 GitHub Advisory 신규 알림", "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"🕒 {checked_at}"}]},
        {"type": "divider"}
    ]

    for item in items:
        triage = item.get("triage")
        marker = common_utils.triage_marker(triage) or "• "
        tracked_link = common_utils.tracking_url("github_advisory:{}".format(item.get("id", "")), item.get("link", "#"))
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{marker}*{item.get('title', '제목 없음')}*\n> Severity: `{item.get('severity', 'N/A')}`\n> Link: <{tracked_link}|GitHub advisory>{common_utils.triage_note(triage)}"
            }
        })

    payload = {"text": f"GitHub Advisory {len(items)}건이 발견되었습니다.", "blocks": blocks}
    webhook_url = common_utils.pick_webhook(
        os.environ.get("SLACK_WEBHOOK_GITHUB"),
        [item.get("triage") for item in items],
    )
    return common_utils.send_slack_webhook(payload, webhook_url)

def main():
    state = load_state()
    sent_ids = set(state["sent_ids"])
    items = fetch_github_advisories()
    new_items = filter_new_items(items, sent_ids)

    if not new_items:
        print("No new GitHub high/critical advisories. Email skipped.")
        return

    # 긴급도 분류 (P1/P2/P3)
    epss_scores = common_utils.fetch_epss_scores([item["cve_id"] for item in new_items if item["cve_id"]])
    for item in new_items:
        item["triage"] = common_utils.classify_urgency(
            [item["title"], item["description"]] + item["identifiers"],
            cvss_score=item["cvss_score"],
            epss=epss_scores.get(item["cve_id"]),
        )

    slack_sent = send_to_slack(new_items)
    email_sent = send_email(new_items)

    # 두 채널 모두 실패하면 상태를 저장하지 않고 다음 실행에서 재시도합니다.
    if not slack_sent and not email_sent:
        print("Slack/email delivery failed. State not saved; will retry on next run.")
        return

    save_state(state["sent_ids"] + [item["id"] for item in new_items])

    # 일간/주간 리포트용 통합 이벤트 로그 적재
    events = []
    for item in new_items:
        try:
            score = float(item["cvss_score"]) if item["cvss_score"] else None
        except ValueError:
            score = None
        events.append(
            common_utils.make_event(
                "github_advisory",
                item["id"],
                item["title"],
                url=item["link"],
                summary=item["description"],
                severity=item["severity"],
                score=score,
                cves=[item["cve_id"]],
                affected_products=affected_product_names(item),
                affected_packages=[{
                    "product": entry["package"],
                    "affected": entry["vulnerable_range"],
                    "fixed": entry["patched_versions"],
                } for entry in item["affected"] if entry["package"]],
                fix_available=has_patched_version(item),
                remediation=build_remediation(item),
                published_at=item["published"],
                email_sent=email_sent,
                slack_sent=slack_sent,
                triage=item.get("triage"),
            )
        )
    common_utils.append_events(events)
    print("Sent: GitHub advisories {}".format(len(new_items)))


if __name__ == "__main__":
    main()
