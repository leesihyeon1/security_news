import html
import json
import os
import smtplib
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
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

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]

STATE_FILE = common_utils.STATE_DIR / "cve_sent_state.json"

LOOKBACK_HOURS = int(os.environ.get("CVE_LOOKBACK_HOURS", "48"))
KEV_LOOKBACK_DAYS = int(os.environ.get("KEV_LOOKBACK_DAYS", "7"))
MAX_NVD_ITEMS_PER_EMAIL = int(os.environ.get("MAX_NVD_ITEMS_PER_EMAIL", "10"))
MAX_KEV_ITEMS_PER_EMAIL = int(os.environ.get("MAX_KEV_ITEMS_PER_EMAIL", "10"))
MIN_NVD_CVSS_SCORE = float(os.environ.get("MIN_NVD_CVSS_SCORE", "7.0"))
CRITICAL_CVSS_SCORE = float(os.environ.get("CRITICAL_CVSS_SCORE", "9.0"))
# NVD는 lastModified가 갱신되기만 해도(오래된 CVE의 메타데이터 보정 등) "modified" 조회창에
# 다시 걸린다. 오래된 CVE의 단순 보정까지 발송 후보로 삼으면 노이즈가 커지므로, modified
# 조회로만 걸린(= published 조회에는 없는) CVE는 최근 RECENT_PUBLISH_DAYS_FOR_MODIFIED일
# 이내에 발행된 것만 인정한다 — 오래된 CVE가 최근 재수정됐다는 이유만으로는 발송하지 않는다.
# published 조회로 걸린 CVE는 이 제한 없이 그대로 유지한다.
RECENT_PUBLISH_DAYS_FOR_MODIFIED = int(os.environ.get("RECENT_PUBLISH_DAYS_FOR_MODIFIED", "7"))
# 실측 수요(48시간에 CVSS>=7.0 후보 2,070건, 그중 순수 신규 발행분만도 415건 — 연간 수만
# 건 규모)보다 캡(기존 1,000)이 훨씬 작아서 sent_nvd_ids가 며칠 만에 밀려나 CVE가 실제로
# 중복 발송됐다(events.jsonl에서 591건 확인, 492건은 이메일도 실제로 두 번 발송됨). 연간
# 발생량 대비 여유 있게 크게 잡아 사실상 영구 기억에 가깝게 만든다.
MAX_STORED_SENT_IDS = 50000


def clean_text(value):
    return common_utils.clean_text(value)


def request_json(url, headers=None, timeout=30):
    request_headers = {
        "User-Agent": "daily-cve-mailer/1.0",
        "Accept": "application/json",
    }
    if headers:
        request_headers.update(headers)

    request = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw_data = response.read()
        charset = response.headers.get_content_charset() or "utf-8"
    return json.loads(raw_data.decode(charset, errors="replace"))


def load_state():
    return common_utils.load_json_state(STATE_FILE, lambda: {"sent_nvd_ids": [], "sent_kev_ids": []})


def save_state(sent_nvd_ids, sent_kev_ids):
    state = {
        "sent_nvd_ids": sent_nvd_ids,
        "sent_kev_ids": sent_kev_ids,
    }
    common_utils.save_json_state(STATE_FILE, state, max_items=MAX_STORED_SENT_IDS, keys_to_trim=["sent_nvd_ids", "sent_kev_ids"])


def nvd_datetime(value):
    return value.strftime("%Y-%m-%dT%H:%M:%S.000")


def nvd_link(cve_id):
    return "https://nvd.nist.gov/vuln/detail/{}".format(urllib.parse.quote(cve_id))


def extract_cvss(metrics):
    if not isinstance(metrics, dict):
        return {"score": "", "severity": "N/A", "vector": ""}

    metric_names = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

    for metric_name in metric_names:
        entries = metrics.get(metric_name) or []
        if not entries:
            continue

        metric = entries[0]
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity")
        vector = cvss_data.get("vectorString")

        return {
            "score": "" if score is None else str(score),
            "severity": clean_text(severity),
            "vector": clean_text(vector),
        }

    return {"score": "", "severity": "N/A", "vector": ""}


def cvss_score_value(item):
    try:
        return float(item.get("score") or 0)
    except (TypeError, ValueError):
        return 0.0


def is_high_or_critical_nvd(item):
    return cvss_score_value(item) >= MIN_NVD_CVSS_SCORE


def is_critical_nvd(item):
    return cvss_score_value(item) >= CRITICAL_CVSS_SCORE


def cve_display_id(item):
    if is_critical_nvd(item):
        return "[CRITICAL] {}".format(item["id"])
    return item["id"]


def extract_description(cve):
    descriptions = cve.get("descriptions", [])

    for description in descriptions:
        if description.get("lang") == "en":
            return clean_text(description.get("value"))

    if descriptions:
        return clean_text(descriptions[0].get("value"))

    return ""


def extract_references(cve, limit=3):
    raw_references = cve.get("references", [])

    if isinstance(raw_references, dict):
        references = raw_references.get("referenceData", [])
    elif isinstance(raw_references, list):
        references = raw_references
    else:
        references = []

    links = []
    for reference in references:
        if not isinstance(reference, dict):
            continue

        url = clean_text(reference.get("url"))
        if url:
            links.append(url)
        if len(links) == limit:
            break

    return links


def fetch_nvd_cves_by_date(start_param, end_param):
    now = datetime.utcnow()
    start = now - timedelta(hours=LOOKBACK_HOURS)

    query = urllib.parse.urlencode(
        {
            start_param: nvd_datetime(start),
            end_param: nvd_datetime(now),
            "resultsPerPage": "2000",
        }
    )

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    data = request_json("{}?{}".format(NVD_API_URL, query), headers=headers)
    return data.get("vulnerabilities", [])


def parse_nvd_vulnerabilities(vulnerabilities):
    cves = {}

    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = clean_text(cve.get("id"))
        if not cve_id:
            continue

        cvss = extract_cvss(cve.get("metrics", {}))
        cves[cve_id] = {
            "id": cve_id,
            "published": clean_text(cve.get("published")),
            "last_modified": clean_text(cve.get("lastModified")),
            "status": clean_text(cve.get("vulnStatus")),
            "severity": cvss["severity"],
            "score": cvss["score"],
            "vector": cvss["vector"],
            "description": extract_description(cve),
            "link": nvd_link(cve_id),
            "references": extract_references(cve),
        }

    return list(cves.values())


def fetch_new_nvd_cves():
    try:
        published_raw = fetch_nvd_cves_by_date("pubStartDate", "pubEndDate")
    except Exception as error:
        print("Failed to fetch NVD published CVEs: {}".format(error))
        published_raw = []

    try:
        modified_raw = fetch_nvd_cves_by_date("lastModStartDate", "lastModEndDate")
    except Exception as error:
        print("Failed to fetch NVD modified CVEs: {}".format(error))
        modified_raw = []

    published_cves = parse_nvd_vulnerabilities(published_raw)
    modified_cves = parse_nvd_vulnerabilities(modified_raw)
    published_ids = {item["id"] for item in published_cves}

    now = datetime.utcnow()
    recent_publish_cutoff = now - timedelta(days=RECENT_PUBLISH_DAYS_FOR_MODIFIED)

    combined_cves = {item["id"]: item for item in published_cves}
    for item in modified_cves:
        if item["id"] in published_ids:
            continue
        # modified 조회로만 걸린 CVE는 최근에 발행된 것만 인정 (오래된 CVE의 단순 메타데이터
        # 보정은 제외) — "완전 신규" 위주로 발송량을 줄이기 위한 필터.
        try:
            published_at = datetime.fromisoformat(item["published"].replace("Z", "+00:00")).replace(tzinfo=None)
        except (AttributeError, TypeError, ValueError):
            continue
        if published_at < recent_publish_cutoff:
            continue
        combined_cves[item["id"]] = item

    all_raw_cves = list(combined_cves.values())

    # NVD가 조회 구간 밖의 데이터를 섞어 주는 경우가 있어 날짜 필터링을 한 번 더 수행합니다.
    # 최근 수정된 과거 CVE도 유지되도록 published/last_modified 중 최신 시각으로 비교합니다.
    limit_time = now - timedelta(hours=LOOKBACK_HOURS)

    filtered_cves = []
    for item in all_raw_cves:
        item_time = None
        for field in ("published", "last_modified"):
            try:
                parsed = datetime.fromisoformat(item[field].replace("Z", "+00:00")).replace(tzinfo=None)
            except (AttributeError, TypeError, ValueError):
                continue
            if item_time is None or parsed > item_time:
                item_time = parsed
        if item_time is not None and item_time >= limit_time:
            filtered_cves.append(item)


    filtered_cves.sort(key=lambda item: item["published"], reverse=True)
    return filtered_cves


def fetch_cisa_kev():
    last_error = None

    for url in CISA_KEV_URLS:
        try:
            data = request_json(url)
            vulnerabilities = data.get("vulnerabilities", [])
            break
        except Exception as error:
            last_error = error
    else:
        raise RuntimeError("Failed to fetch CISA KEV data: {}".format(last_error))

    kev_items = []
    for item in vulnerabilities:
        cve_id = clean_text(item.get("cveID"))
        date_added = clean_text(item.get("dateAdded"))
        if not cve_id:
            continue

        kev_items.append(
            {
                "id": "{}|{}".format(cve_id, date_added),
                "cve_id": cve_id,
                "date_added": date_added,
                "vendor": clean_text(item.get("vendorProject")),
                "product": clean_text(item.get("product")),
                "name": clean_text(item.get("vulnerabilityName")),
                "description": clean_text(item.get("shortDescription")),
                "action": clean_text(item.get("requiredAction")),
                "due_date": clean_text(item.get("dueDate")),
                "ransomware": clean_text(item.get("knownRansomwareCampaignUse")),
                "notes": clean_text(item.get("notes")),
                "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
        )

    # 전체 카탈로그(1,600건+)가 상태 상한(MAX_STORED_SENT_IDS)보다 커서 오래된 항목이
    # 이력에서 밀려나 재발송되는 루프를 막기 위해, 최근 등재분만 발송 후보로 삼는다.
    cutoff = (datetime.utcnow() - timedelta(days=KEV_LOOKBACK_DAYS)).strftime("%Y-%m-%d")
    recent_items = [item for item in kev_items if item["date_added"] >= cutoff]

    recent_items.sort(key=lambda item: item["date_added"], reverse=True)
    return recent_items


def kev_ransomware_flag(value):
    """KEV knownRansomwareCampaignUse("Known"/"Unknown") → True/False/None"""
    normalized = (value or "").strip().lower()
    if normalized == "known":
        return True
    if normalized == "unknown":
        return False
    return None


def filter_new_items(items, sent_ids, limit=None):
    new_items = [item for item in items if item["id"] not in sent_ids]
    if limit is not None:
        new_items = new_items[:limit]
    return new_items


def filter_important_nvd_items(items):
    return [item for item in items if is_high_or_critical_nvd(item)]


def build_email_body(nvd_items, kev_items):
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    text_body = "Daily CVE Alert\nChecked at: {}\n\n".format(checked_at)
    html_body = """
    <html>
    <body>
        <h2>Daily CVE Alert</h2>
        <p>Checked at: {checked_at}</p>
    """.format(checked_at=html.escape(checked_at))

    if kev_items:
        text_body += "[CISA KEV - Known Exploited Vulnerabilities]\n"
        html_body += "<h3>CISA KEV - Known Exploited Vulnerabilities</h3>"

        for idx, item in enumerate(kev_items, start=1):
            tracked_link = common_utils.tracking_url("cisa_kev:{}".format(item["id"]), item["link"])
            text_body += "{}. {}\n".format(idx, item["cve_id"])
            text_body += "Product: {} {}\n".format(item["vendor"], item["product"])
            text_body += "Name: {}\n".format(item["name"])
            text_body += "Date added: {}\n".format(item["date_added"])
            text_body += "Summary: {}\n".format(item["description"])
            text_body += "Required action: {}\n".format(item["action"])
            text_body += "Due date: {}\n".format(item["due_date"])
            text_body += "CISA KEV link: {}\n\n".format(tracked_link)

            html_body += """
            <hr>
            <h4>{idx}. {cve_id}</h4>
            <p><b>Product:</b> {vendor} {product}</p>
            <p><b>Name:</b> {name}</p>
            <p><b>Date added:</b> {date_added}</p>
            <p><b>Summary:</b> {description}</p>
            <p><b>Required action:</b> {action}</p>
            <p><b>Due date:</b> {due_date}</p>
            <p><b>CISA KEV link:</b> <a href="{link}">{link}</a></p>
            """.format(
                idx=idx,
                cve_id=html.escape(item["cve_id"]),
                vendor=html.escape(item["vendor"]),
                product=html.escape(item["product"]),
                name=html.escape(item["name"]),
                date_added=html.escape(item["date_added"]),
                description=html.escape(item["description"]),
                action=html.escape(item["action"]),
                due_date=html.escape(item["due_date"]),
                link=html.escape(tracked_link),
            )

    if nvd_items:
        text_body += "[NVD High/Critical CVE - CVSS >= {}]\n".format(MIN_NVD_CVSS_SCORE)
        html_body += "<h3>NVD High/Critical CVE - CVSS &gt;= {}</h3>".format(MIN_NVD_CVSS_SCORE)

        for idx, item in enumerate(nvd_items, start=1):
            tracked_link = common_utils.tracking_url("nvd:{}".format(item["id"]), item["link"])
            references = "\n".join(["- {}".format(link) for link in item["references"]])
            display_id = cve_display_id(item)

            text_body += "{}. {}\n".format(idx, display_id)
            text_body += "Severity: {} {}\n".format(item["severity"], item["score"])
            text_body += "Status: {}\n".format(item["status"])
            text_body += "Published: {}\n".format(item["published"])
            text_body += "Last modified: {}\n".format(item["last_modified"])
            text_body += "Summary: {}\n".format(item["description"])
            text_body += "NVD link: {}\n".format(tracked_link)
            if references:
                text_body += "References:\n{}\n".format(references)
            text_body += "\n"

            html_body += """
            <hr>
            <h4>{idx}. {cve_id}</h4>
            <p><b>Severity:</b> {severity} {score}</p>
            <p><b>Status:</b> {status}</p>
            <p><b>Published:</b> {published}</p>
            <p><b>Last modified:</b> {last_modified}</p>
            <p><b>Summary:</b> {description}</p>
            <p><b>NVD link:</b> <a href="{link}">{link}</a></p>
            """.format(
                idx=idx,
                cve_id=html.escape(display_id),
                severity=html.escape(item["severity"]),
                score=html.escape(item["score"]),
                status=html.escape(item["status"]),
                published=html.escape(item["published"]),
                last_modified=html.escape(item["last_modified"]),
                description=html.escape(item["description"]),
                link=html.escape(tracked_link),
            )

            if item["references"]:
                html_body += "<p><b>References:</b></p><ul>"
                for link in item["references"]:
                    escaped_link = html.escape(link)
                    html_body += '<li><a href="{0}">{0}</a></li>'.format(escaped_link)
                html_body += "</ul>"

    html_body += """
    </body>
    </html>
    """

    return text_body, html_body


def build_subject(nvd_items, kev_items):
    total_count = len(nvd_items) + len(kev_items)
    has_p1 = any((item.get("triage") or {}).get("level") == "P1" for item in nvd_items + kev_items)
    has_critical = any(is_critical_nvd(item) for item in nvd_items)

    if has_p1:
        return "[P1] CVE alert - {} item(s)".format(total_count)
    if kev_items or has_critical:
        return "[URGENT] CVE alert - {} item(s)".format(total_count)

    return "CVE alert - {} item(s)".format(total_count)


def send_email(nvd_items, kev_items):
    subject = build_subject(nvd_items, kev_items)
    text_body, html_body = build_email_body(nvd_items, kev_items)
    return common_utils.send_email_message(subject, text_body, html_body)


def send_to_slack(nvd_items, kev_items):
    """추가: 기본 urllib 라이브러리를 활용해 슬랙 단일 채널로 가독성 높은 카드 메시지를 보내는 함수"""
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    # 슬랙 메시지 최상단 헤더
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🤖 [NVD] 실시간 위협 인텔리전스 수신",
                "emoji": True
            }
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"🕒 분석 완료 시각: {checked_at}"}
            ]
        },
        {"type": "divider"}
    ]

    # 1. CISA KEV (실제 악용 중인 취약점) 블록 생성
    if kev_items:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "🔥 *CISA KEV (실제 악용 중인 취약점)*"}
        })
        for item in kev_items:
            cve_id = item.get("cve_id", "Unknown")
            vendor = item.get("vendor", "")
            product = item.get("product", "")
            name = item.get("name", "")
            date_added = item.get("date_added", "-")
            desc = item.get("description", "설명 없음")
            action = item.get("action", "설명 없음")
            link = common_utils.tracking_url(
                "cisa_kev:{}".format(item.get("id", "")), item.get("link", "https://www.cisa.gov")
            )

            triage = item.get("triage")
            marker = common_utils.triage_marker(triage) or "• "
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{marker}*{cve_id}* ({date_added})\n> *대상 자산:* {vendor} {product} ({name})\n> *조치* ({action})\n> *요약:* {desc}{common_utils.triage_note(triage)}"
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "CISA KEV 링크", "emoji": True},
                    "url": link,
                    "action_id": f"btn_{cve_id.replace('-', '_')}"
                }
            })
        blocks.append({"type": "divider"})

    # 2. NVD High/Critical 취약점 블록 생성
    if nvd_items:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"⚠️ *NVD High/Critical 취약점 (CVSS >= {MIN_NVD_CVSS_SCORE})*"}
        })
        for item in nvd_items:
            cve_id = item.get("id", "CVE-Unknown")
            score = item.get("score", "N/A")
            severity = item.get("severity", "N/A")
            desc = item.get("description", "설명 없음")
            link = common_utils.tracking_url(
                "nvd:{}".format(item.get("id", "")), item.get("link", "https://nvd.nist.gov")
            )

            # 슬랙 글자수 초과 방지 가공
            if len(desc) > 150: 
                desc = desc[:150] + "..."

            triage = item.get("triage")
            marker = common_utils.triage_marker(triage) or "• "
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{marker}*{cve_id}* | 점수: `{score}` [{severity}]\n> {desc}{common_utils.triage_note(triage)}"
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "NVD 링크", "emoji": True},
                    "url": link,
                    "action_id": f"btn_{cve_id.replace('-', '_')}"
                }
            })

    # HTTP POST 데이터 빌드
    payload = {"blocks": blocks}
    webhook_url = common_utils.pick_webhook(
        os.environ.get("SLACK_WEBHOOK_CVE"),
        [item.get("triage") for item in nvd_items + kev_items],
    )
    return common_utils.send_slack_webhook(payload, webhook_url)


def main():
    state = load_state()
    sent_nvd_ids = set(state["sent_nvd_ids"])
    sent_kev_ids = set(state["sent_kev_ids"])

    nvd_items = filter_important_nvd_items(fetch_new_nvd_cves())
    kev_items = fetch_cisa_kev()

    # 이메일/슬랙(상위 N건, 알림 스팸 방지용 캡)과 이벤트 로그(대시보드 CVE 탭이
    # 그 기간 CVE를 빠짐없이 보여줘야 하므로 캡 없이 전체)를 분리한다 — 예전엔
    # 이메일에 실리는 상위 N건만 이벤트로도 남겨서, 캡에 걸려 이메일엔 안 실린
    # CVE가 대시보드에서도 통째로 사라졌었다.
    all_new_nvd_items = filter_new_items(nvd_items, sent_nvd_ids)
    all_new_kev_items = filter_new_items(kev_items, sent_kev_ids)

    if not all_new_nvd_items and not all_new_kev_items:
        print("No new high/critical NVD CVEs or new CISA KEV entries. Slack/Email skipped.")
        return

    # 긴급도 분류 (P1/P2/P3): KEV는 악용 확인, NVD는 EPSS 확률 조회 후 판정 — 로그에
    # 남는 전체 목록 기준으로 계산해야 대시보드 통계(P1/P2 건수 등)가 정확하다.
    epss_scores = common_utils.fetch_epss_scores([item["id"] for item in all_new_nvd_items])
    for item in all_new_nvd_items:
        item["triage"] = common_utils.classify_urgency(
            [item["id"], item["description"]],
            cvss_score=item["score"],
            epss=epss_scores.get(item["id"]),
        )
    for item in all_new_kev_items:
        item["triage"] = common_utils.classify_urgency(
            [item["cve_id"], item["vendor"], item["product"], item["name"], item["description"]],
            kev=True,
        )

    new_nvd_items = all_new_nvd_items[:MAX_NVD_ITEMS_PER_EMAIL]
    new_kev_items = all_new_kev_items[:MAX_KEV_ITEMS_PER_EMAIL]
    emailed_nvd_ids = {item["id"] for item in new_nvd_items}
    emailed_kev_ids = {item["id"] for item in new_kev_items}

    slack_sent = send_to_slack(new_nvd_items, new_kev_items)
    email_sent = send_email(new_nvd_items, new_kev_items)

    # 두 채널 모두 실패하면 상태를 저장하지 않고 다음 실행에서 재시도합니다.
    if not slack_sent and not email_sent:
        print("Slack/email delivery failed. State not saved; will retry on next run.")
        return

    # 이메일 캡에 안 든 나머지도 이번에 "확인함" 처리 — 안 그러면 다음 실행에서
    # 다시 새 항목으로 잡혀 이벤트가 중복 기록되고, 캡 안에 들면 뒤늦게 이메일도 나간다.
    updated_nvd_ids = state["sent_nvd_ids"] + [item["id"] for item in all_new_nvd_items]
    updated_kev_ids = state["sent_kev_ids"] + [item["id"] for item in all_new_kev_items]
    save_state(updated_nvd_ids, updated_kev_ids)

    # 일간/주간 리포트용 통합 이벤트 로그 적재 — 이메일 캡과 무관하게 전체를 남긴다.
    # email_sent/slack_sent는 실제로 그 채널에 실린 항목에만 True.
    common_utils.append_events(
        [
            common_utils.make_event(
                "nvd",
                item["id"],
                item["id"],
                url=item["link"],
                summary=item["description"],
                severity=item["severity"],
                score=cvss_score_value(item),
                cves=[item["id"]],
                references=item.get("references"),
                published_at=item["published"],
                email_sent=email_sent and item["id"] in emailed_nvd_ids,
                slack_sent=slack_sent and item["id"] in emailed_nvd_ids,
                triage=item.get("triage"),
                category="취약점",
                category_reason="NVD API 소스 — CVE 취약점 정보이므로 카테고리 고정(LLM 판단 아님)",
            )
            for item in all_new_nvd_items
        ]
        + [
            common_utils.make_event(
                "cisa_kev",
                item["id"],
                "{} - {}".format(item["cve_id"], item["name"]),
                url=item["link"],
                summary=item["description"],
                severity="KEV",
                cves=[item["cve_id"]],
                affected_products=["{} {}".format(item["vendor"], item["product"]).strip()],
                remediation=item["action"],
                due_date=item["due_date"],
                ransomware_use=kev_ransomware_flag(item["ransomware"]),
                published_at=item["date_added"],
                email_sent=email_sent and item["id"] in emailed_kev_ids,
                slack_sent=slack_sent and item["id"] in emailed_kev_ids,
                triage=item.get("triage"),
                category="취약점",
                category_reason="CISA KEV API 소스 — 실제 악용 확인된 취약점이므로 카테고리 고정(LLM 판단 아님)",
            )
            for item in all_new_kev_items
        ]
    )

    print(
        "Process finished: NVD high/critical CVEs {} (emailed {}), CISA KEV entries {} (emailed {})".format(
            len(all_new_nvd_items),
            len(new_nvd_items),
            len(all_new_kev_items),
            len(new_kev_items),
        )
    )


if __name__ == "__main__":
    main()
