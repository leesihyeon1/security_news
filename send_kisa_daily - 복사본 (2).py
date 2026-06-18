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


TO_EMAIL = "user@example.com"

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

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

STATE_FILE = Path(__file__).with_name("kisa_sent_state.json")
MAX_ITEMS_PER_EMAIL = int(os.environ.get("MAX_KISA_ITEMS_PER_EMAIL", "10"))
MAX_STORED_SENT_IDS = 500
XML_DECLARATION_RE = re.compile(r"^\s*<\?xml[^>]*\?>", re.IGNORECASE)


def clean_text(value):
    if value is None:
        return ""
    return " ".join(html.unescape(str(value)).split())


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
    with STATE_FILE.open("w", encoding="utf-8") as file:
        json.dump({"sent_ids": sent_ids[-MAX_STORED_SENT_IDS:]}, file, ensure_ascii=False, indent=2)


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

        soup = BeautifulSoup(r.text, "html.parser")

        content_div = soup.find("div", class_="board_view")

        if not content_div:
            content_div = soup.find("div", class_="view_cont")

        if not content_div:
            return ""

        text = content_div.get_text(
            separator="\n",
            strip=True
        )

        return text[:6000]

    except Exception as e:
        print(f"본문 수집 실패: {url}")
        print(e)
        return ""

def ai_summarize(title, content):

    prompt = f"""
당신은 보안관제 전문가이다.

다음 KISA 보안 공지를 분석하라.

[핵심요약]
- 3줄 이내

[영향]
- 영향받는 제품 또는 시스템

[권고조치]
- 보안담당자가 해야 할 일

제목:
{title}

본문:
{content}
"""

    try:

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "qwen3:8b",
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
    sender_email = os.environ["EMAIL_ADDRESS"]
    sender_password = os.environ["EMAIL_APP_PASSWORD"]
    text_body, html_body = build_email_body(items)

    message = MIMEMultipart("alternative")
    message["From"] = sender_email
    message["To"] = TO_EMAIL
    message["Subject"] = "KISA/KrCERT alert - {} item(s)".format(len(items))
    message.attach(MIMEText(text_body, "plain", "utf-8"))
    message.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, TO_EMAIL, message.as_string())

def send_to_slack(items):
    """메일과 동일한 데이터를 받아 슬랙으로 전송"""
    slack_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not slack_url or not items:
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
    
    try:
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(slack_url, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                print("슬랙으로 알림이 전송되었습니다.")
    except Exception as e:
        print(f"슬랙 발송 오류: {e}")


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
