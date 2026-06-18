import html
import json
import os
import re
import smtplib
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path


RSS_URL = "https://www.boannews.com/media/news_rss.xml"
TO_EMAIL = "user@example.com"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

STATE_FILE = Path(__file__).with_name("boannews_sent_state.json")
MAX_STORED_SENT_IDS = 200
XML_DECLARATION_RE = re.compile(r"^\s*<\?xml[^>]*\?>", re.IGNORECASE)


def clean_text(text):
    if not text:
        return ""
    return " ".join(html.unescape(text).split())


def load_state():
    if not STATE_FILE.exists():
        return {"sent_ids": []}

    try:
        with STATE_FILE.open("r", encoding="utf-8") as file:
            state = json.load(file)
    except (json.JSONDecodeError, OSError):
        return {"sent_ids": []}

    sent_ids = state.get("sent_ids", [])
    if not isinstance(sent_ids, list):
        sent_ids = []

    return {"sent_ids": sent_ids}


def save_state(sent_ids):
    trimmed_ids = sent_ids[-MAX_STORED_SENT_IDS:]
    with STATE_FILE.open("w", encoding="utf-8") as file:
        json.dump({"sent_ids": trimmed_ids}, file, ensure_ascii=False, indent=2)


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
    sender_email = os.environ["EMAIL_ADDRESS"]
    sender_password = os.environ["EMAIL_APP_PASSWORD"]

    subject = "보안뉴스 신규 뉴스 {}개".format(len(news_items))
    text_body, html_body = build_email_body(news_items)

    message = MIMEMultipart("alternative")
    message["From"] = sender_email
    message["To"] = TO_EMAIL
    message["Subject"] = subject

    message.attach(MIMEText(text_body, "plain", "utf-8"))
    message.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, TO_EMAIL, message.as_string())

def send_to_slack(news_items):
    """보안뉴스 메일 내용과 동일한 데이터를 슬랙으로 전송"""
    slack_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not slack_url or not news_items:
        return

    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": "🤖 보안뉴스 신규 알림", "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"🕒 {checked_at}"}]},
        {"type": "divider"}
    ]

    for news in news_items:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"• *{news.get('title', '제목 없음')}*\n> {news.get('summary', '')}\n> <{news.get('link', '#')}|기사 바로가기>"
            }
        })

    payload = {"text": f"보안뉴스 신규 기사 {len(news_items)}건이 등록되었습니다.", "blocks": blocks}
    
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(slack_url, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                print("슬랙으로 동일한 내용이 전송되었습니다.")
    except Exception as e:
        print(f"슬랙 발송 오류: {e}")

def main():
    state = load_state()
    sent_ids = set(state["sent_ids"])

    latest_news = fetch_latest_security_news(limit=10)
    new_articles = select_new_articles(latest_news, sent_ids, limit=3)

    if not new_articles:
        print("신규 기사가 없어 메일을 보내지 않았습니다.")
        return

    # [변경] 기존 이메일 대신 슬랙 발송 함수를 호출합니다.
    send_to_slack(new_articles)
    send_email(new_articles)

    updated_sent_ids = state["sent_ids"] + [article["id"] for article in new_articles]
    save_state(updated_sent_ids)

    print("메일 발송 완료: 신규 기사 {}개".format(len(new_articles)))


if __name__ == "__main__":
    main()
