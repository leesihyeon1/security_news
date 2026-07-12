import html
import json
import os
import re
import smtplib
import urllib.request
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
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

    try:

        response = requests.post(
            common_utils.OLLAMA_URL,
            json={
                "model": common_utils.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=180
        )

        if response.status_code == 200:
            return response.json().get(
                "response",
                "AI 분석 실패"
            )

    except Exception as e:
        print("Ollama 오류:", e)

    return "AI 분석 실패"

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
    common_utils.send_email_message(subject, text_body, html_body)

def send_to_slack(items):
    """메일과 동일한 데이터를 받아 슬랙으로 전송"""
    if not items:
        return

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

            print(f"AI 분석중: {item['title']}")

            ai_result = ai_summarize(
                item["title"],
                content
             )

        else:
             ai_result = "본문을 가져오지 못했습니다."

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text":
                    f"📌 *{item['title']}*\n"
                    f"> 출처: {item['source']}\n\n"
                    f"🤖 *AI 분석 결과*\n"
                    f"{ai_result[:2500]}\n\n"
                    f"🔗 <{item['link']}|기사 바로가기>"
            }
        })

    blocks.append({
        "type": "divider"
    })

    payload = {"text": f"KISA 신규 알림 {len(items)}건이 발견되었습니다.", "blocks": blocks}
    default_webhook_url = os.environ.get("SLACK_WEBHOOK_BOANNEWS") or os.environ.get("SLACK_WEBHOOK_KISA")
    webhook_url, _ = common_utils.select_slack_webhook(default_webhook_url, items)
    common_utils.send_slack_webhook(payload, webhook_url)


def main():
    state = load_state()
    sent_ids = set(state["sent_ids"])
    items = fetch_kisa_items()
    new_items = filter_new_items(items, sent_ids)

    if not new_items:
        print("No new KISA/KrCERT items. Email skipped.")
        return

    # [변경] 기존 이메일 대신 슬랙 발송 함수를 호출합니다.
    send_to_slack(new_items)
    send_email(new_items)
    save_state(state["sent_ids"] + [item["id"] for item in new_items])
    print("Email sent: KISA/KrCERT items {}".format(len(new_items)))


if __name__ == "__main__":
    main()
