import html
import json
import os
import re
import smtplib
import sys
import urllib.request
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
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

FEEDS = [
    {
        "name": "KrCERT Security Notice",
        "url": "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133",
    },
    {
        "name": "KrCERT Vulnerability Info",
        "url": "https://www.boho.or.kr/kr/rss.do?bbsId=B0000302",
    },
]

STATE_FILE = common_utils.STATE_DIR / "kisa_sent_state.json"
MAX_ITEMS_PER_EMAIL = int(os.environ.get("MAX_KISA_ITEMS_PER_EMAIL", "10"))
MAX_STORED_SENT_IDS = 500
XML_DECLARATION_RE = re.compile(r"^\s*<\?xml[^>]*\?>", re.IGNORECASE)


def clean_text(value):
    return common_utils.clean_text(value)


def decode_xml(xml_data, charset):
    encodings = []
    if charset:
        encodings.append(charset)
    encodings.extend(["utf-8-sig", "utf-8", "cp949", "euc-kr"])

    for encoding in encodings:
        try:
            xml_text = xml_data.decode(encoding)
            return XML_DECLARATION_RE.sub("", xml_text, count=1)
        except UnicodeDecodeError:
            pass

    xml_text = xml_data.decode("utf-8", errors="replace")
    return XML_DECLARATION_RE.sub("", xml_text, count=1)


def request_xml(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "daily-kisa-mailer/1.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        xml_data = response.read()
        charset = response.headers.get_content_charset()
    return ET.fromstring(decode_xml(xml_data, charset))


def load_state():
    return common_utils.load_json_state(STATE_FILE, lambda: {"sent_ids": []})


def save_state(sent_ids):
    common_utils.save_json_state(STATE_FILE, {"sent_ids": sent_ids}, max_items=MAX_STORED_SENT_IDS, keys_to_trim=["sent_ids"])


def article_id(source_name, item):
    guid = clean_text(item.findtext("guid"))
    link = clean_text(item.findtext("link"))
    title = clean_text(item.findtext("title"))
    pub_date = clean_text(item.findtext("pubDate"))
    return guid or link or "{}|{}|{}".format(source_name, title, pub_date)


def fetch_feed(feed):
    root = request_xml(feed["url"])
    channel = root.find("channel")
    if channel is None:
        return []

    items = []
    for item in channel.findall("item"):
        link = clean_text(item.findtext("link"))
        items.append(
            {
                "id": article_id(feed["name"], item),
                "source": feed["name"],
                "title": clean_text(item.findtext("title")),
                "summary": clean_text(item.findtext("description")),
                "link": link,
                "published": clean_text(item.findtext("pubDate")),
            }
        )
    return items


def fetch_kisa_items():
    items = []
    for feed in FEEDS:
        items.extend(fetch_feed(feed))
    return items

def get_article_content(url):

    try:

        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        r = requests.get(
            url,
            headers=headers,
            timeout=15
        )

        r.raise_for_status()

        soup = BeautifulSoup(
            r.text,
            "html.parser"
        )

        selectors = [
            "div.fl-grow1.p12.pt6.w100.s-prose",
            "div.s-prose",
            "div.board_view",
            "div.view_cont",
            "div.view_con",
            "div.bbsView"
        ]

        for selector in selectors:

            content_div = soup.select_one(selector)

            if content_div:

                text = content_div.get_text(
                    separator="\n",
                    strip=True
                )

                if len(text) > 100:

                    print(
                        f"본문 추출 성공 ({len(text)} bytes)"
                    )

                    return text[:6000]

        print("본문 영역 찾기 실패")
        return ""

    except Exception as e:

        print(f"본문 수집 실패: {e}")
        return ""

def ai_summarize(title, content):

    prompt = f"""
당신은 SOC 보안관제 분석가이다.

아래 KISA 보안 공지를 분석하라.

출력 형식:

[핵심요약]
- 3줄 이내

[영향제품]
- 제품명
- 영향 버전

[관제포인트]
- IDS/IPS
- WAF
- 로그 분석 시 확인 사항

[권고조치]
- 패치
- 임시 완화조치

본문:
{content}
"""

    return common_utils.llm_generate(prompt, timeout=180) or "AI 분석 실패"

def filter_new_items(items, sent_ids):
    new_items = []
    for item in items:
        if item["id"] not in sent_ids:
            new_items.append(item)
        if len(new_items) == MAX_ITEMS_PER_EMAIL:
            break
    return new_items


def build_email_body(items):
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    text_body = "KISA/KrCERT Daily Alert\nChecked at: {}\n\n".format(checked_at)
    html_body = """
    <html>
    <body>
        <h2>KISA/KrCERT Daily Alert</h2>
        <p>Checked at: {checked_at}</p>
    """.format(checked_at=html.escape(checked_at))

    for idx, item in enumerate(items, start=1):
        text_body += "{}. {}\n".format(idx, item["title"])
        text_body += "Source: {}\n".format(item["source"])
        text_body += "Published: {}\n".format(item["published"])
        text_body += "Summary: {}\n".format(item["summary"])
        text_body += "Link: {}\n\n".format(item["link"])

        html_body += """
        <hr>
        <h3>{idx}. {title}</h3>
        <p><b>Source:</b> {source}</p>
        <p><b>Published:</b> {published}</p>
        <p><b>Summary:</b> {summary}</p>
        <p><b>Link:</b> <a href="{link}">{link}</a></p>
        """.format(
            idx=idx,
            title=html.escape(item["title"]),
            source=html.escape(item["source"]),
            published=html.escape(item["published"]),
            summary=html.escape(item["summary"]),
            link=html.escape(item["link"]),
        )

    html_body += "</body></html>"
    return text_body, html_body


def send_email(items):
    subject = "KISA/KrCERT alert - {} item(s)".format(len(items))
    text_body, html_body = build_email_body(items)
    return common_utils.send_email_message(subject, text_body, html_body)

def send_to_slack(items):
    """메일과 동일한 데이터를 받아 슬랙으로 전송"""
    if not items:
        return False

    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    # 메일 발송 내용과 일치하도록 블록 구성
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🤖 KISA/KrCERT 신규 알림", "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"🕒 {checked_at}"}]},
        {"type": "divider"}
    ]

    for item in items:

        print(f"본문 수집중: {item['title']}")

        content = get_article_content(
            item["link"]
        )

        if content:
            # 본문에서 발견된 CVE를 병합 (이벤트 로그에 반영됨)
            item["extracted_cves"] = sorted(
                set(item.get("extracted_cves") or []) | set(common_utils.extract_cves(content))
            )

            print(f"AI 분석중: {item['title']}")

            ai_result = ai_summarize(
                item["title"],
                content
             )

            # Slack 알림 문구(ai_result)와는 별도로, 리포트용 통합 enrichment(category/
            # severity/pirs 등)를 채워 이벤트 로그에 저장한다 — 없으면 이 소스 기사는
            # 카테고리별/PIR 집계에서 빠지게 된다.
            item["enrichment"] = common_utils.ai_enrich_article(item["title"], content) or {}
            item["iocs"] = common_utils.extract_iocs(content)
            item["attack_techniques"] = common_utils.extract_attack_techniques(item["title"], content)
            item["body_chars"] = len(content)

        else:
             ai_result = "본문을 가져오지 못했습니다."
             item["enrichment"] = {}
             item["iocs"] = []
             item["attack_techniques"] = []
             item["body_chars"] = 0

        triage = item.get("triage")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text":
                    f"{common_utils.triage_marker(triage)}📌 *{item['title']}*\n"
                    f"> 출처: {item['source']}{common_utils.triage_note(triage)}\n\n"
                    f"🤖 *AI 분석 결과*\n"
                    f"{ai_result[:2500]}\n\n"
                    f"🔗 <{item['link']}|기사 바로가기>"
            }
        })

    blocks.append({
        "type": "divider"
    })

    payload = {"text": f"KISA 신규 알림 {len(items)}건이 발견되었습니다.", "blocks": blocks}
    default_webhook_url = os.environ.get("SLACK_WEBHOOK_KISA") or os.environ.get("SLACK_WEBHOOK_BOANNEWS")
    webhook_url = common_utils.pick_webhook(default_webhook_url, [item.get("triage") for item in items])
    return common_utils.send_slack_webhook(payload, webhook_url)


def main():
    state = load_state()
    sent_ids = set(state["sent_ids"])
    items = fetch_kisa_items()
    new_items = filter_new_items(items, sent_ids)

    if not new_items:
        print("No new KISA/KrCERT items. Email skipped.")
        return

    # 제목·요약에서 CVE 번호 추출 후 EPSS(악용 확률)와 연계하여 긴급도 분류 (P1/P2/P3)
    # 본문 크롤링 시점(send_to_slack)에 본문 내 CVE가 추가로 병합됩니다.
    for item in new_items:
        item["extracted_cves"] = common_utils.extract_cves(item["title"], item["summary"])
    epss_scores = common_utils.fetch_epss_scores(
        [cve for item in new_items for cve in item["extracted_cves"]]
    )
    for item in new_items:
        epss_values = [epss_scores[cve] for cve in item["extracted_cves"] if cve in epss_scores]
        item["triage"] = common_utils.classify_urgency(
            [item["title"], item["summary"]],
            epss=max(epss_values) if epss_values else None,
        )

    slack_sent = send_to_slack(new_items)
    email_sent = send_email(new_items)

    # 두 채널 모두 실패하면 상태를 저장하지 않고 다음 실행에서 재시도합니다.
    if not slack_sent and not email_sent:
        print("Slack/email delivery failed. State not saved; will retry on next run.")
        return

    save_state(state["sent_ids"] + [item["id"] for item in new_items])

    # 일간/주간 리포트용 통합 이벤트 로그 적재 — send_to_slack()에서 채운 enrichment를
    # category/severity/pirs 등 공통 스키마 필드로 반영한다 (asec_notifier.py와 동일 패턴)
    events_to_append = []
    for item in new_items:
        enrichment = item.get("enrichment") or {}
        # KISA/KrCERT는 정부기관 1차 공지 — feeds.json 기준 "A: 당국·당사자 1차 소스"와 동일 등급
        related = common_utils.find_related_events(
            item.get("extracted_cves"), item["title"], exclude_source="kisa",
        )
        cluster = common_utils.build_cluster_context(related, triage=item.get("triage"))
        importance = common_utils.score_importance(
            triage=item.get("triage"), enrichment=enrichment,
            cves=item.get("extracted_cves"), reliability="A",
        )
        events_to_append.append(
            common_utils.make_event(
                "kisa",
                item["id"],
                item["title"],
                url=item["link"],
                summary=item["summary"],
                severity=enrichment.get("severity") or "",
                cves=item.get("extracted_cves"),
                category=enrichment.get("category") or "",
                category_reason=enrichment.get("category_reason") or "",
                affected_products=enrichment.get("affected_products"),
                threat_actor=enrichment.get("threat_actor") or "",
                malware_family=enrichment.get("malware_family") or "",
                relevance=enrichment.get("relevance") or "",
                confidence=enrichment.get("confidence") or "",
                iocs=item.get("iocs"),
                attack_techniques=item.get("attack_techniques"),
                pirs=enrichment.get("pirs"),
                published_at=item["published"],
                ai_summary=enrichment.get("summary"),
                email_sent=email_sent,
                slack_sent=slack_sent,
                triage=item.get("triage"),
                importance=importance,
                cluster=cluster,
                content_depth=enrichment.get("content_depth") or "",
                novelty=enrichment.get("novelty") or "",
                body_chars=item.get("body_chars"),
                recommended_actions=enrichment.get("recommended_actions"),
                affected_versions=enrichment.get("affected_versions"),
                fix_available=enrichment.get("fix_available"),
                remediation=enrichment.get("patch_info") or "",
            )
        )
    common_utils.append_events(events_to_append)
    print("Sent: KISA/KrCERT items {}".format(len(new_items)))


if __name__ == "__main__":
    main()
