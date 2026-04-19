"""
보안뉴스 상위 3개 기사를 크롤링하여 Outlook으로 발송하는 스크립트
"""

import sys
import smtplib
import getpass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
from bs4 import BeautifulSoup
from datetime import datetime

BASE_URL = "https://www.boannews.com"
LIST_URL = f"{BASE_URL}/media/t_list.asp"
SENDER = "user@example.com"
RECIPIENT = "user@example.com"
SMTP_SERVER = "smtp.naver.com"
SMTP_PORT = 465

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )
}


def _parse_page(url: str) -> BeautifulSoup:
    resp = requests.get(url, headers=HEADERS, timeout=15)
    text = resp.content.decode("cp949", errors="replace")
    return BeautifulSoup(text, "html.parser")


def _get_summary(article_url: str) -> str:
    """개별 기사 페이지에서 메타 description 또는 첫 본문 단락을 반환."""
    try:
        soup = _parse_page(article_url)
        for attr in ({"property": "og:description"}, {"name": "description"}):
            tag = soup.find("meta", attrs=attr)
            if tag and tag.get("content", "").strip():
                return tag["content"].strip()[:200]
        # 메타 없으면 본문 첫 문단
        for el in soup.find_all(["p", "div", "td"]):
            text = el.get_text(strip=True)
            if len(text) > 50:
                return text[:200]
    except Exception:
        pass
    return "요약을 가져올 수 없습니다."


def fetch_articles(count: int = 3) -> list[dict]:
    soup = _parse_page(LIST_URL)
    articles = []
    seen_idx: set[str] = set()

    for a in soup.find_all("a", href=True):
        href: str = a["href"]
        if "view.asp" not in href or "idx=" not in href:
            continue

        idx = href.split("idx=")[1].split("&")[0]
        if idx in seen_idx:
            continue
        seen_idx.add(idx)

        title = a.get_text(strip=True)
        if not title or len(title) < 5:
            continue

        # URL 정규화
        if href.startswith("http"):
            full_url = href
        elif href.startswith("/"):
            full_url = BASE_URL + href
        else:
            full_url = BASE_URL + "/media/" + href

        print(f"  [{len(articles)+1}] {title[:45]}...")
        summary = _get_summary(full_url)

        articles.append({"title": title, "summary": summary, "url": full_url})
        if len(articles) >= count:
            break

    return articles


def build_html_body(articles: list[dict]) -> str:
    today = datetime.now().strftime("%Y년 %m월 %d일")
    rows = ""
    for i, art in enumerate(articles, 1):
        rows += f"""
        <tr>
          <td style="padding:16px 0; border-bottom:1px solid #e8e8e8;">
            <div style="font-size:13px; color:#888; margin-bottom:4px;">#{i}</div>
            <div style="font-size:16px; font-weight:bold; margin-bottom:6px;">
              <a href="{art['url']}" style="color:#1a73e8; text-decoration:none;">{art['title']}</a>
            </div>
            <div style="font-size:13px; color:#555; margin-bottom:8px; line-height:1.5;">
              {art['summary']}
            </div>
            <a href="{art['url']}" style="font-size:12px; color:#1a73e8;">기사 전문 보기 →</a>
          </td>
        </tr>"""

    return f"""
<html>
<body style="font-family: 'Malgun Gothic', Arial, sans-serif; background:#f5f5f5; margin:0; padding:20px;">
  <table width="600" cellpadding="0" cellspacing="0" style="background:#fff; border-radius:8px;
         box-shadow:0 2px 8px rgba(0,0,0,0.08); margin:0 auto; padding:24px;">
    <tr>
      <td style="border-bottom:2px solid #1a73e8; padding-bottom:12px; margin-bottom:16px;">
        <h2 style="margin:0; color:#1a1a1a; font-size:20px;">🔐 보안뉴스 오늘의 TOP 3 기사</h2>
        <div style="font-size:12px; color:#888; margin-top:4px;">{today}</div>
      </td>
    </tr>
    {rows}
    <tr>
      <td style="padding-top:16px; font-size:11px; color:#aaa; text-align:center;">
        출처: <a href="{LIST_URL}" style="color:#aaa;">{LIST_URL}</a>
      </td>
    </tr>
  </table>
</body>
</html>
"""


def send_via_naver(subject: str, html_body: str) -> None:
    password = getpass.getpass("네이버 메일 비밀번호 입력: ")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SENDER
    msg["To"] = RECIPIENT
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
        server.login(SENDER, password)
        server.sendmail(SENDER, RECIPIENT, msg.as_string())

    print(f"메일 발송 완료 → {RECIPIENT}")


def main() -> None:
    print("보안뉴스 기사 수집 중...")
    articles = fetch_articles(count=3)

    if not articles:
        print("기사를 가져오지 못했습니다. 사이트 구조가 변경되었을 수 있습니다.")
        sys.exit(1)

    for i, art in enumerate(articles, 1):
        print(f"\n[{i}] {art['title']}")
        print(f"    요약: {art['summary'][:60]}...")
        print(f"    링크: {art['url']}")

    today = datetime.now().strftime("%Y.%m.%d")
    subject = f"[보안뉴스] 오늘의 TOP 3 기사 ({today})"
    html_body = build_html_body(articles)

    print(f"\nOutlook으로 메일 발송 중...")
    send_via_naver(subject, html_body)


if __name__ == "__main__":
    main()
