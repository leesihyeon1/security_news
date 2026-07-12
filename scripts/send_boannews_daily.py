import html
import hashlib
import json
import os
import re
import smtplib
import urllib.request
import xml.etree.ElementTree as ET
import requests
from datetime import datetime
from email.utils import parsedate_to_datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
import common_utils


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name.lower() == "scripts" else SCRIPT_DIR
RSS_URL = "https://www.boannews.com/media/news_rss.xml"
TO_EMAIL = common_utils.DEFAULT_TO_EMAIL

SMTP_SERVER = common_utils.SMTP_SERVER
SMTP_PORT = common_utils.SMTP_PORT

STATE_FILE = common_utils.STATE_DIR / "boannews_sent_state.json"
DATA_DIR = PROJECT_ROOT / "data"
EVENTS_FILE = DATA_DIR / "boannews_events.jsonl"
MAX_STORED_SENT_IDS = 200
XML_DECLARATION_RE = re.compile(r"^\s*<\?xml[^>]*\?>", re.IGNORECASE)


def clean_text(text):
    return common_utils.clean_text(text)


def utc_now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def parse_rss_datetime(value):
    if not value:
        return None

    try:
        return parsedate_to_datetime(value).isoformat()
    except (TypeError, ValueError, IndexError):
        return None


def event_id(source, source_id):
    digest = hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:16]
    return "{}:{}".format(source, digest)


def normalize_boannews_event(news, fetched_at, email_sent=False, slack_sent=False):
    source_id = news["id"]

    return {
        "id": event_id("boannews", source_id),
        "source": "boannews",
        "source_type": "rss",
        "title": news["title"],
        "url": news["link"],
        "summary": news["summary"],
        "published_at": parse_rss_datetime(news["pub_date"]),
        "fetched_at": fetched_at,
        "raw": {
            "source_id": source_id,
            "pub_date": news["pub_date"],
            "rss_url": RSS_URL,
        },
        "analysis": {
            "severity": None,
            "category": None,
            "affected_products": [],
            "recommended_actions": [],
            "iocs": [],
            "cves": [],
            "llm_summary": None,
        },
        "delivery": {
            "email_sent": email_sent,
            "slack_sent": slack_sent,
        },
    }


def append_events(events):
    if not events:
        return

    DATA_DIR.mkdir(exist_ok=True)

    with EVENTS_FILE.open("a", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def load_state():
    return common_utils.load_json_state(STATE_FILE, lambda: {"sent_ids": []})


def save_state(sent_ids):
    common_utils.save_json_state(STATE_FILE, {"sent_ids": sent_ids}, max_items=MAX_STORED_SENT_IDS, keys_to_trim=["sent_ids"])


def article_id(item):
    guid = clean_text(item.findtext("guid"))
    link = clean_text(item.findtext("link"))
    title = clean_text(item.findtext("title"))
    pub_date = clean_text(item.findtext("pubDate"))
    return guid or link or "{}|{}".format(title, pub_date)


def decode_xml(xml_data, charset):
    encodings = []

    if charset:
        encodings.append(charset)

    encodings.extend(["utf-8-sig", "cp949", "euc-kr"])

    for encoding in encodings:
        try:
            xml_text = xml_data.decode(encoding)
            return XML_DECLARATION_RE.sub("", xml_text, count=1)
        except UnicodeDecodeError:
            pass

    xml_text = xml_data.decode("utf-8", errors="replace")
    return XML_DECLARATION_RE.sub("", xml_text, count=1)


def fetch_latest_security_news(limit=10):
    request = urllib.request.Request(
        RSS_URL,
        headers={"User-Agent": "Mozilla/5.0 boannews-daily-mailer/1.0"},
    )

    with urllib.request.urlopen(request, timeout=15) as response:
        xml_data = response.read()
        charset = response.headers.get_content_charset()

    root = ET.fromstring(decode_xml(xml_data, charset))
    channel = root.find("channel")

    if channel is None:
        raise RuntimeError("RSS channel을 찾을 수 없습니다.")

    news_items = []

    for item in channel.findall("item")[:limit]:
        news_items.append(
            {
                "id": article_id(item),
                "title": clean_text(item.findtext("title")),
                "summary": clean_text(item.findtext("description")),
                "link": clean_text(item.findtext("link")),
                "pub_date": clean_text(item.findtext("pubDate")),
            }
        )

    return news_items


def select_new_articles(news_items, sent_ids, limit=3):
    new_articles = []

    for news in news_items:
        if news["id"] not in sent_ids:
            new_articles.append(news)

        if len(new_articles) == limit:
            break

    return new_articles


def build_email_body(news_items):
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    text_body = "보안뉴스 신규 뉴스 {}개\n체크 시간: {}\n\n".format(len(news_items), checked_at)

    html_body = """
    <html>
    <body>
        <h2>보안뉴스 신규 뉴스 {count}개</h2>
        <p>체크 시간: {checked_at}</p>
    """.format(count=len(news_items), checked_at=checked_at)

    for idx, news in enumerate(news_items, start=1):
        text_body += "{}. {}\n".format(idx, news["title"])
        text_body += "요약: {}\n".format(news["summary"])
        text_body += "기사 링크: {}\n".format(news["link"])
        text_body += "발행일: {}\n\n".format(news["pub_date"])

        html_body += """
        <hr>
        <h3>{idx}. {title}</h3>
        <p><b>요약:</b> {summary}</p>
        <p><b>발행일:</b> {pub_date}</p>
        <p><b>기사 링크:</b> <a href="{link}">{link}</a></p>
        """.format(
            idx=idx,
            title=html.escape(news["title"]),
            summary=html.escape(news["summary"]),
            pub_date=html.escape(news["pub_date"]),
            link=html.escape(news["link"]),
        )

    html_body += """
    </body>
    </html>
    """

    return text_body, html_body


def send_email(news_items):
    subject = "보안뉴스 신규 뉴스 {}개".format(len(news_items))
    text_body, html_body = build_email_body(news_items)
    common_utils.send_email_message(subject, text_body, html_body)

def ai_summarize(title, summary):

    prompt = f"""
당신은 10년 경력의 보안관제 분석가이다.

다음 보안뉴스를 읽고 아래 형식으로 답변하라.

[핵심요약]
- 3줄 이내

[영향]
- 영향받는 시스템 또는 제품

[권고조치]
- 보안담당자가 해야할 일

제목:
{title}

내용:
{summary}
"""

    try:
        response = requests.post(
            common_utils.OLLAMA_URL,
            json={
                "model": common_utils.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )

        return response.json()["response"]

    except Exception as e:
        print(f"Ollama 요약 실패: {e}")
        return summary[:300]
    
def send_to_slack(news_items):
    """보안뉴스 메일 내용과 동일한 데이터를 슬랙으로 전송"""
    if not news_items:
        return False

    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🤖 보안뉴스 신규 알림", "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"🕒 {checked_at}"}]},
        {"type": "divider"}
    ]

    for news in news_items:
        # Ollama LLM 요약은 JSON/ELK 연동 안정화 후 다시 활성화합니다.
        # print(f"AI 요약 생성 중: {news['title']}")
        # ai_summary = ai_summarize(
        #     news["title"],
        #     news["summary"]
        # )
        ai_summary = news["summary"]

        blocks.append({
            "type": "section",
             "text": {
                "type": "mrkdwn",
                "text":
                    f"📰 *{news['title']}*\n\n"
                    f"{ai_summary}\n\n"
                    f"<{news['link']}|기사 보기>"
                }
    })

    blocks.append({
        "type": "divider"
    })

    payload = {"text": f"보안뉴스 신규 기사 {len(news_items)}건이 등록되었습니다.", "blocks": blocks}
    webhook_url, _ = common_utils.select_slack_webhook(os.environ.get("SLACK_WEBHOOK_BOANNEWS"), news_items)
    return common_utils.send_slack_webhook(payload, webhook_url)

def main():
    state = load_state()
    sent_ids = set(state["sent_ids"])

    latest_news = fetch_latest_security_news(limit=10)
    new_articles = select_new_articles(latest_news, sent_ids, limit=3)

    if not new_articles:
        print("신규 기사가 없어 메일을 보내지 않았습니다.")
        return

    # [변경] 기존 이메일 대신 슬랙 발송 함수를 호출합니다.
    fetched_at = utc_now_iso()
    slack_sent = send_to_slack(new_articles)
    send_email(new_articles)
    new_events = [
        normalize_boannews_event(
            article,
            fetched_at,
            email_sent=True,
            slack_sent=slack_sent,
        )
        for article in new_articles
    ]
    append_events(new_events)

    updated_sent_ids = state["sent_ids"] + [article["id"] for article in new_articles]
    save_state(updated_sent_ids)

    print("메일 발송 완료: 신규 기사 {}개".format(len(new_articles)))


if __name__ == "__main__":
    main()
