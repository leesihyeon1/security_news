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
from bs4 import BeautifulSoup
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

MSRC_CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{}"
STATE_FILE = common_utils.STATE_DIR / "microsoft_patch_sent_state.json"

MAX_ITEMS_PER_EMAIL = int(os.environ.get("MAX_MICROSOFT_ITEMS_PER_EMAIL", "20"))
MIN_CVSS_SCORE = float(os.environ.get("MIN_MICROSOFT_CVSS_SCORE", "7.0"))
CRITICAL_CVSS_SCORE = float(os.environ.get("CRITICAL_MICROSOFT_CVSS_SCORE", "9.0"))
# 2개월 조회 창의 CVSS>=7.0 대상만으로도 1,000건을 넘길 수 있어(실측 1,023건),
# 이 카운트 캡이 1차 방어선이 되면 안 된다 — 진짜 방어선은 main()의 조회창 기반 pruning.
# 이 값은 그 pruning이 실패했을 때를 대비한 여유 있는 백업 한도일 뿐이다.
MAX_STORED_SENT_IDS = 5000

MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def clean_text(value):
    return common_utils.clean_text(value)


def request_json(url):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "daily-msrc-mailer/1.0",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        raw_data = response.read()
        charset = response.headers.get_content_charset() or "utf-8"
    return json.loads(raw_data.decode(charset, errors="replace"))


def normalize_sent_id(entry):
    # 과거 id 형식("문서|CVE|점수")이 남아있으면 CVE ID만 추려서 새 형식과 맞춘다.
    # (점수가 바뀌거나 어느 달 문서가 이겼는지에 따라 id가 흔들리던 문제를 없앤 것)
    parts = entry.split("|")
    return parts[1] if len(parts) == 3 else entry


def load_state():
    state = common_utils.load_json_state(STATE_FILE, lambda: {"sent_ids": []})
    state["sent_ids"] = [normalize_sent_id(entry) for entry in state.get("sent_ids", [])]
    return state


def save_state(sent_ids):
    common_utils.save_json_state(STATE_FILE, {"sent_ids": sent_ids}, max_items=MAX_STORED_SENT_IDS, keys_to_trim=["sent_ids"])


def month_id(year, month):
    return "{}-{}".format(year, MONTH_NAMES[month - 1])


def recent_month_ids():
    now = datetime.utcnow()
    months = [(now.year, now.month)]

    if now.month == 1:
        months.append((now.year - 1, 12))
    else:
        months.append((now.year, now.month - 1))

    return [month_id(year, month) for year, month in months]


def as_list(value):
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def strip_html(value):
    if not value:
        return ""
    return BeautifulSoup(str(value), "html.parser").get_text(" ", strip=True)


def get_note(vulnerability, note_type=None):
    # MSRC CVRF의 Notes[].Type은 숫자 코드(예: 2)라 "Description" 같은 문자열과
    # 절대 안 맞는다 — 대신 사람이 읽는 라벨인 Title 필드로 매칭한다(표본 확인 결과
    # "Description" 노트는 항상 Title == "Description"으로 일관되게 라벨링됨).
    # Value는 HTML(<p> 등)로 오는 경우가 있어 태그를 벗겨낸 뒤 반환한다.
    notes = vulnerability.get("Notes", [])
    for note in as_list(notes):
        if not isinstance(note, dict):
            continue
        if note_type and clean_text(note.get("Title")) != note_type:
            continue
        value = note.get("Value") or note.get("Title")
        if value:
            return clean_text(strip_html(value))
    return ""


# MSRC CVRF의 Threats[].Type 숫자 코드(문서화된 CVRF 스키마 기준, 표본 데이터로 확인됨)
MSRC_THREAT_TYPE_CODES = {"Impact": 0, "Exploit Status": 1, "Severity": 3}


def get_threat(vulnerability, threat_type=None):
    threats = vulnerability.get("Threats", [])
    target_code = MSRC_THREAT_TYPE_CODES.get(threat_type) if threat_type else None
    for threat in as_list(threats):
        if not isinstance(threat, dict):
            continue
        if target_code is not None and threat.get("Type") != target_code:
            continue
        value = threat.get("Description")
        if isinstance(value, dict):
            value = value.get("Value")
        if not value:
            value = threat.get("ProductID")
        if value:
            return clean_text(value)
    return ""


def get_score(vulnerability):
    score_sets = vulnerability.get("CVSSScoreSets", [])
    for score_set in as_list(score_sets):
        if not isinstance(score_set, dict):
            continue
        for key in ["BaseScore", "BaseScoreV3", "BaseScoreV2"]:
            value = score_set.get(key)
            if value in (None, ""):
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                pass
    return 0.0


def msrc_cve_link(cve_id):
    return "https://msrc.microsoft.com/update-guide/vulnerability/{}".format(urllib.parse.quote(cve_id))


def parse_document(document_id, data):
    vulnerabilities = data.get("Vulnerability", [])
    items = []

    # CVRF의 CVE별 ReleaseDate는 MSRC가 채워주지 않는 경우가 많아(ReleaseDateSpecified=False,
    # 0001-01-01 더미값) 문서 단위 최초 공개일로 대체한다 — CVE별 정밀도는 아니지만
    # 문서 ID 문자열("2026-Jul")보다는 실제 날짜라 정렬·기간 필터에 쓸 수 있다.
    published_at = clean_text((data.get("DocumentTracking") or {}).get("InitialReleaseDate"))

    for vulnerability in as_list(vulnerabilities):
        if not isinstance(vulnerability, dict):
            continue

        cve_id = clean_text(vulnerability.get("CVE"))
        if not cve_id:
            continue

        score = get_score(vulnerability)
        if score < MIN_CVSS_SCORE:
            continue

        title_raw = vulnerability.get("Title")
        if isinstance(title_raw, dict):
            title_raw = title_raw.get("Value")
        title = get_note(vulnerability, "Title") or clean_text(title_raw) or cve_id
        description = get_note(vulnerability, "Description")
        severity = get_threat(vulnerability, "Severity")
        exploited = get_threat(vulnerability, "Exploit Status")
        impact = get_threat(vulnerability, "Impact")

        items.append(
            {
                "id": cve_id,
                "document_id": document_id,
                "published_at": published_at,
                "cve_id": cve_id,
                "title": title,
                "description": description,
                "severity": severity,
                "score": score,
                "impact": impact,
                "exploited": exploited,
                "link": msrc_cve_link(cve_id),
            }
        )

    items.sort(key=lambda item: item["score"], reverse=True)
    return items


def fetch_microsoft_items():
    """(items, complete)를 반환. complete는 조회창의 월 문서를 전부 받아왔는지 여부다.

    MSRC는 503을 자주 낸다(실측: 로그에 818회). 일부만 받아온 결과를 "조회창 전체"로
    착각하면 못 받아온 달의 CVE가 발송 기록에서 통째로 지워지고, 다음 실행에서 전부
    신규로 판정돼 재발송된다 — 실제로 이 때문에 같은 CVE가 2~4일에 걸쳐 반복 발송됐다.
    """
    all_items = []
    complete = True
    for document_id in recent_month_ids():
        try:
            data = request_json(MSRC_CVRF_URL.format(document_id))
        except Exception as error:
            print("Failed to fetch MSRC document {}: {}".format(document_id, error))
            complete = False
            continue
        all_items.extend(parse_document(document_id, data))

    deduped = {}
    for item in all_items:
        deduped[item["cve_id"]] = item

    return sorted(deduped.values(), key=lambda item: item["score"], reverse=True), complete


def filter_new_items(items, sent_ids):
    new_items = []
    for item in items:
        if item["id"] not in sent_ids:
            new_items.append(item)
        if len(new_items) == MAX_ITEMS_PER_EMAIL:
            break
    return new_items


def display_cve_id(item):
    if item["score"] >= CRITICAL_CVSS_SCORE:
        return "[CRITICAL] {}".format(item["cve_id"])
    return item["cve_id"]


def build_email_body(items):
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    text_body = "Microsoft Security Update Alert\nChecked at: {}\n\n".format(checked_at)
    html_body = """
    <html>
    <body>
        <h2>Microsoft Security Update Alert</h2>
        <p>Checked at: {checked_at}</p>
    """.format(checked_at=html.escape(checked_at))

    for idx, item in enumerate(items, start=1):
        tracked_link = common_utils.tracking_url("msrc:{}".format(item["id"]), item["link"])
        text_body += "{}. {}\n".format(idx, display_cve_id(item))
        text_body += "Title: {}\n".format(item["title"])
        text_body += "Severity: {}\n".format(item["severity"])
        text_body += "CVSS: {}\n".format(item["score"])
        text_body += "Impact: {}\n".format(item["impact"])
        text_body += "Exploit status: {}\n".format(item["exploited"])
        text_body += "Document: {}\n".format(item["document_id"])
        text_body += "Summary: {}\n".format(item["description"])
        text_body += "MSRC link: {}\n\n".format(tracked_link)

        html_body += """
        <hr>
        <h3>{idx}. {cve_id}</h3>
        <p><b>Title:</b> {title}</p>
        <p><b>Severity:</b> {severity}</p>
        <p><b>CVSS:</b> {score}</p>
        <p><b>Impact:</b> {impact}</p>
        <p><b>Exploit status:</b> {exploited}</p>
        <p><b>Document:</b> {document_id}</p>
        <p><b>Summary:</b> {description}</p>
        <p><b>MSRC link:</b> <a href="{link}">{link}</a></p>
        """.format(
            idx=idx,
            cve_id=html.escape(display_cve_id(item)),
            title=html.escape(item["title"]),
            severity=html.escape(item["severity"]),
            score=html.escape(str(item["score"])),
            impact=html.escape(item["impact"]),
            exploited=html.escape(item["exploited"]),
            document_id=html.escape(item["document_id"]),
            description=html.escape(item["description"]),
            link=html.escape(tracked_link),
        )

    html_body += "</body></html>"
    return text_body, html_body


def build_subject(items):
    has_p1 = any((item.get("triage") or {}).get("level") == "P1" for item in items)
    has_critical = any(item["score"] >= CRITICAL_CVSS_SCORE for item in items)
    if has_p1:
        return "[P1] Microsoft security update - {} item(s)".format(len(items))
    if has_critical:
        return "[URGENT] Microsoft security update - {} item(s)".format(len(items))
    return "Microsoft security update - {} item(s)".format(len(items))


def send_email(items):
    subject = build_subject(items)
    text_body, html_body = build_email_body(items)
    return common_utils.send_email_message(subject, text_body, html_body)

def send_to_slack(items):
    """메일과 동일한 데이터를 받아 슬랙으로 전송"""
    if not items:
        return False

    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    # 메일 발송 내용과 일치하도록 블록 구성
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🤖 Microsoft 보안 패치 알림", "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"🕒 {checked_at}"}]},
        {"type": "divider"}
    ]

    for item in items:
        # Microsoft 패치 데이터 구조에 맞춘 출력
        triage = item.get("triage")
        marker = common_utils.triage_marker(triage) or "• "
        tracked_link = common_utils.tracking_url("msrc:{}".format(item.get("id", "")), item.get("link", "#"))
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{marker}*{item.get('title', '제목 없음')}*\n> CVSS Score: `{item.get('score', 'N/A')}`\n> <{tracked_link}|패치 상세 보기>{common_utils.triage_note(triage)}"
            }
        })

    payload = {"text": f"Microsoft 보안 패치 {len(items)}건이 발견되었습니다.", "blocks": blocks}
    webhook_url = common_utils.pick_webhook(
        os.environ.get("SLACK_WEBHOOK_MS"),
        [item.get("triage") for item in items],
    )
    return common_utils.send_slack_webhook(payload, webhook_url)


def main():
    state = load_state()
    sent_ids = set(state["sent_ids"])
    items, complete = fetch_microsoft_items()
    new_items = filter_new_items(items, sent_ids)

    # 조회창(최근 2개월)을 벗어난 CVE는 앞으로 다시 조회될 일이 없으므로 memory에서 정리한다.
    # 카운트 캡에만 의존하면 아직 조회 대상인 CVE가 먼저 밀려나 재발송되는 문제가 생긴다
    # (실측: 2개월 창의 CVSS>=7.0 CVE가 1,023건으로 과거 캡 1,000건을 이미 초과했었다).
    #
    # 단, 이 정리는 조회가 "완전"할 때만 안전하다. 월 문서를 하나라도 못 받아온 실행에서
    # 정리하면 그 달 CVE가 전부 미발송 상태로 되돌아가 대량 재발송된다.
    if complete and items:
        valid_ids = {item["cve_id"] for item in items}
        retained_ids = [cve for cve in state["sent_ids"] if cve in valid_ids]
    else:
        print("[!] MSRC 조회가 불완전하여 발송 기록 정리를 건너뜁니다(재발송 방지).")
        retained_ids = list(state["sent_ids"])

    if not new_items:
        if len(retained_ids) != len(state["sent_ids"]):
            save_state(retained_ids)
        print("No new Microsoft high/critical security update items. Email skipped.")
        return

    # 긴급도 분류 (P1/P2/P3): MSRC Exploit Status(악용 탐지/공개/가능성) + EPSS 반영
    epss_scores = common_utils.fetch_epss_scores([item["cve_id"] for item in new_items])
    for item in new_items:
        status = (item["exploited"] or "").lower()
        item["triage"] = common_utils.classify_urgency(
            [item["cve_id"], item["title"], item["description"], item["impact"]],
            cvss_score=item["score"],
            exploited="exploited:yes" in status,
            poc_public="publicly disclosed:yes" in status or "exploitation more likely" in status,
            epss=epss_scores.get(item["cve_id"]),
        )

    slack_sent = send_to_slack(new_items)
    email_sent = send_email(new_items)

    # 두 채널 모두 실패하면 상태를 저장하지 않고 다음 실행에서 재시도합니다.
    if not slack_sent and not email_sent:
        print("Slack/email delivery failed. State not saved; will retry on next run.")
        return

    save_state(retained_ids + [item["id"] for item in new_items])

    # 일간/주간 리포트용 통합 이벤트 로그 적재
    common_utils.append_events(
        [
            common_utils.make_event(
                "msrc",
                item["id"],
                item["title"],
                url=item["link"],
                summary=item["description"],
                severity=item["severity"],
                score=item["score"],
                cves=[item["cve_id"]],
                published_at=item["published_at"],
                email_sent=email_sent,
                slack_sent=slack_sent,
                triage=item.get("triage"),
                category="취약점",
                category_reason="MSRC API 소스 — 보안 패치/취약점 공지이므로 카테고리 고정(LLM 판단 아님)",
            )
            for item in new_items
        ]
    )
    print("Sent: Microsoft items {}".format(len(new_items)))


if __name__ == "__main__":
    main()
