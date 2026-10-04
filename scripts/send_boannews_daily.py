import html
import os
import re
import smtplib
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from email.utils import parsedate_to_datetime
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
# 보안뉴스가 2026-08에 media/news_rss.xml을 폐기했다(404 -> 이후 홈페이지 HTML 응답).
# 한쪽이 또 사라져도 메일러가 멈추지 않도록 순서대로 시도한다.
# cdn 쪽을 우선하는 이유: guid를 주고 pubDate가 RFC822라 article_id/날짜 파싱이 안정적이다.
RSS_URLS = [
    "https://cdn.boannews.com/rss/gn_rss_allArticle.xml",
    "https://www.boannews.com/rss/allArticle.xml",
]
TO_EMAIL = common_utils.DEFAULT_TO_EMAIL

SMTP_SERVER = common_utils.SMTP_SERVER
SMTP_PORT = common_utils.SMTP_PORT

# Admiralty 소스 신뢰도: 2차 전달 매체 (feeds.json의 thehackernews 등과 동일 기준)
BOANNEWS_RELIABILITY = "C"

STATE_FILE = common_utils.STATE_DIR / "boannews_sent_state.json"
MAX_STORED_SENT_IDS = 200
XML_DECLARATION_RE = re.compile(r"^\s*<\?xml[^>]*\?>", re.IGNORECASE)

ARTICLE_BODY_MAX_CHARS = 4000
# 개편 후 레이아웃은 "등록 · 2026.08.30 13:05", 구 레이아웃은 "입력 : 2026-08-30 13:05"
ARTICLE_DATE_RE = re.compile(r"(?:입력|등록)\s*[·:]?\s*(\d{4}[.\-]\d{2}[.\-]\d{2}\s+\d{2}:\d{2})")


def clean_text(text):
    return common_utils.clean_text(text)


def parse_rss_datetime(value):
    if not value:
        return None

    try:
        return parsedate_to_datetime(value).isoformat()
    except (TypeError, ValueError, IndexError):
        return None


def decode_page(raw):
    """개편 페이지(utf-8)와 구 페이지(cp949)를 모두 읽을 수 있도록 순서대로 시도."""
    for encoding in ("utf-8", "cp949"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            pass
    return raw.decode("utf-8", errors="replace")


def fetch_article_body(url, article=None):
    """기사 페이지에서 본문 텍스트와 입력 일시(KST)를 추출. 실패 시 ("", None)."""
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 boannews-daily-mailer/1.0"},
            timeout=15,
        )
        # 개편된 기사 페이지는 utf-8, 구 media/view.asp 페이지는 cp949다
        page_text = decode_page(resp.content)
    except Exception as error:
        print("[-] 기사 본문 수집 실패({}): {}".format(url, error))
        return "", None

    soup = BeautifulSoup(page_text, "html.parser")
    if article is not None:
        from live_news import article_image
        article["image_url"] = article_image(soup, url)

    # 개편 레이아웃은 ISO8601(+09:00)을 메타로 그대로 준다 — 화면 표기 파싱보다 안정적
    published_at = None
    meta_published = soup.find("meta", attrs={"property": "article:published_time"})
    if meta_published and meta_published.get("content"):
        published_at = meta_published["content"].strip()

    if not published_at:
        date_match = ARTICLE_DATE_RE.search(soup.get_text(" ", strip=True))
        if date_match:
            try:
                published_at = datetime.strptime(
                    date_match.group(1).replace(".", "-"), "%Y-%m-%d %H:%M"
                ).isoformat() + "+09:00"
            except ValueError:
                pass

    container = None
    for container_id in ("article-view-content-div", "news_content", "news_contents", "con_Article"):
        container = soup.find(id=container_id)
        if container is not None:
            break

    if container is not None:
        body = container.get_text(" ", strip=True)
    else:
        print("[-] 본문 컨테이너를 찾지 못했습니다: {}".format(url))
        body = ""

    return clean_text(body)[:ARTICLE_BODY_MAX_CHARS], published_at


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


def looks_like_xml(xml_data):
    """피드가 내려가면 200 + HTML 홈페이지가 돌아온다 — 그걸 파싱하려다 ParseError로
    죽는 대신 다음 후보로 넘어가기 위한 선검사."""
    head = xml_data[:512].lstrip().lower()
    return head.startswith(b"<?xml") or head.startswith(b"<rss") or head.startswith(b"<feed")


def fetch_rss_channel():
    """RSS_URLS를 순서대로 시도해 첫 번째로 성공한 channel 엘리먼트를 반환."""
    failures = []

    for url in RSS_URLS:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 boannews-daily-mailer/1.0"},
        )

        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                xml_data = response.read()
                charset = response.headers.get_content_charset()
        except (urllib.error.URLError, TimeoutError) as error:
            failures.append("{} -> 요청 실패: {}".format(url, error))
            continue

        if not looks_like_xml(xml_data):
            failures.append("{} -> XML이 아닌 응답({}바이트)".format(url, len(xml_data)))
            continue

        try:
            root = ET.fromstring(decode_xml(xml_data, charset))
        except ET.ParseError as error:
            failures.append("{} -> XML 파싱 실패: {}".format(url, error))
            continue

        channel = root.find("channel")
        if channel is None:
            failures.append("{} -> RSS channel을 찾을 수 없습니다".format(url))
            continue

        if failures:
            print("[!] 폴백 피드로 수집합니다: {}".format(url))
            for failure in failures:
                print("    - {}".format(failure))
        return channel

    raise RuntimeError("보안뉴스 RSS를 읽지 못했습니다:\n  " + "\n  ".join(failures))


def fetch_latest_security_news(limit=10):
    channel = fetch_rss_channel()

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
        summary = (news.get("enrichment") or {}).get("summary") or news["summary"]
        score = (news.get("importance") or {}).get("score")
        response = " · ".join(common_utils.enrichment_response_bits(news.get("enrichment")))
        tracked_link = common_utils.tracking_url("boannews:{}".format(news["id"]), news["link"])

        text_body += "{}. {}\n".format(idx, news["title"])
        text_body += "요약: {}\n".format(summary)
        if response:
            text_body += "대응: {}\n".format(response)
        if score is not None:
            text_body += "중요도: {}점\n".format(score)
        text_body += "기사 링크: {}\n".format(tracked_link)
        text_body += "발행일: {}\n\n".format(news["pub_date"])

        html_body += """
        <hr>
        <h3>{idx}. {title}</h3>
        <p><b>요약:</b> {summary}</p>
        {score_row}
        <p><b>발행일:</b> {pub_date}</p>
        <p><b>기사 링크:</b> <a href="{link}">{link}</a></p>
        """.format(
            idx=idx,
            title=html.escape(news["title"]),
            summary=html.escape(summary),
            score_row="<p><b>중요도:</b> {}점</p>".format(score) if score is not None else "",
            pub_date=html.escape(news["pub_date"]),
            link=html.escape(tracked_link),
        )

    html_body += """
    </body>
    </html>
    """

    return text_body, html_body


def send_email(news_items):
    subject = "보안뉴스 신규 뉴스 {}개".format(len(news_items))
    text_body, html_body = build_email_body(news_items)
    return common_utils.send_email_message(subject, text_body, html_body)

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
        ai_summary = (news.get("enrichment") or {}).get("summary") or news["summary"]
        response = " · ".join(common_utils.enrichment_response_bits(news.get("enrichment")))
        response_line = f"\n🔧 {response}" if response else ""
        tracked_link = common_utils.tracking_url("boannews:{}".format(news["id"]), news["link"])

        triage = news.get("triage")
        blocks.append({
            "type": "section",
             "text": {
                "type": "mrkdwn",
                "text":
                    f"{common_utils.triage_marker(triage)}📰 *{news['title']}*\n\n"
                    f"{ai_summary}{common_utils.triage_note(triage)}{response_line}\n\n"
                    f"<{tracked_link}|기사 보기> · 중요도 {(news.get('importance') or {}).get('score', '-')}점"
                }
    })
        # 피드백 참조 해시 — 슬랙 폴러가 반응(👍/👎)을 이벤트로 역매핑한다
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": "`ref:{}` · 👍 유용 / 👎 노이즈 반응으로 피드백".format(
                    common_utils.event_ref("boannews:{}".format(news["id"]))
                ),
            }],
        })

    blocks.append({
        "type": "divider"
    })

    payload = {"text": f"보안뉴스 신규 기사 {len(news_items)}건이 등록되었습니다.", "blocks": blocks}
    webhook_url = common_utils.pick_webhook(
        os.environ.get("SLACK_WEBHOOK_BOANNEWS"),
        [news.get("triage") for news in news_items],
    )
    return common_utils.send_slack_webhook(payload, webhook_url)

def main():
    state = load_state()
    sent_ids = set(state["sent_ids"])

    latest_news = fetch_latest_security_news(limit=10)
    new_articles = select_new_articles(latest_news, sent_ids, limit=3)

    if not new_articles:
        print("신규 기사가 없어 메일을 보내지 않았습니다.")
        return

    # 기사 본문까지 수집해 CVE 추출·EPSS 연계 긴급도 분류(P1/P2/P3)의 정확도를 높인다
    for news in new_articles:
        news["body"], news["article_published_at"] = fetch_article_body(news["link"], news)
        news["extracted_cves"] = common_utils.extract_cves(news["title"], news["summary"], news["body"])
        news["iocs"] = common_utils.extract_iocs(news["body"])
        news["attack_techniques"] = common_utils.extract_attack_techniques(news["title"], news["summary"], news["body"])
    epss_scores = common_utils.fetch_epss_scores(
        [cve for news in new_articles for cve in news["extracted_cves"]]
    )
    for news in new_articles:
        epss_values = [epss_scores[cve] for cve in news["extracted_cves"] if cve in epss_scores]
        news["triage"] = common_utils.classify_urgency(
            [news["title"], news["summary"], news["body"]],
            epss=max(epss_values) if epss_values else None,
        )

        # LLM enrichment를 발송 전에 수행해 중요도 스코어링(카테고리·심각도·PIR)에 반영한다
        print("[*] AI enrichment 생성 중: {}".format(news["title"][:50]))
        news["enrichment"] = common_utils.ai_enrich_article(news["title"], news["body"] or news["summary"]) or {}
        # 정규식 추출(명시된 ID) + LLM 매핑(서술형, 공식 카탈로그로 검증됨) 병합
        for technique in news["enrichment"].get("attack_techniques") or []:
            if technique not in news["attack_techniques"]:
                news["attack_techniques"].append(technique)
        # LLM 악용 판정으로 키워드 기반 트리아지를 보정 (회고성 기사 하향, 표현 변형 상향)
        news["triage"] = common_utils.refine_triage_with_enrichment(news["triage"], news["enrichment"])
        news["importance"] = common_utils.score_importance(
            triage=news["triage"], enrichment=news["enrichment"],
            cves=news["extracted_cves"], reliability=BOANNEWS_RELIABILITY,
        )

    # 크로스소스 클러스터링(교차 보도 가점 / 중복 알림 억제) + 중요도 알림 게이트.
    # 임계값 미달·중복 기사도 이벤트로는 적재되어 일간 리포트에서 다룬다.
    for news in new_articles:
        related = common_utils.find_related_events(
            news["extracted_cves"], news["title"], exclude_source="boannews",
        )
        news["cluster"] = common_utils.build_cluster_context(related, triage=news.get("triage"))
        if news["cluster"]["bonus"]:
            news["importance"]["score"] = min(100, news["importance"]["score"] + news["cluster"]["bonus"])
            news["importance"]["reasons"].append(
                "교차 보도 {}곳(+{})".format(len(news["cluster"]["corroborating_sources"]), news["cluster"]["bonus"])
            )
        news["alert"] = common_utils.should_alert(news["importance"], triage=news["triage"])
        news["cluster"]["suppressed"] = bool(
            news["alert"] and news["cluster"]["already_alerted"] and not news["cluster"]["escalated"]
        )
        if news["cluster"]["suppressed"]:
            news["alert"] = False
            print("[*] 중복 알림 억제: {} (기존 알림 소스: {})".format(
                news["title"][:50], ", ".join(news["cluster"]["corroborating_sources"])
            ))
        elif news["cluster"]["escalated"]:
            news["importance"]["reasons"].append("기존 알림 대비 위험도 승격 — 재알림")
        elif not news["alert"]:
            print("[*] 중요도 임계값 미달: {} ({}점) — 알림 생략, 리포트용으로만 적재".format(
                news["title"][:50], news["importance"]["score"]
            ))

    alert_articles = [news for news in new_articles if news["alert"]]

    if alert_articles:
        slack_sent = send_to_slack(alert_articles)
        email_sent = send_email(alert_articles)

        # 두 채널 모두 실패하면 상태를 저장하지 않고 다음 실행에서 재시도합니다.
        if not slack_sent and not email_sent:
            print("슬랙/메일 발송이 모두 실패하여 상태를 저장하지 않았습니다. 다음 실행 시 재시도합니다.")
            return
    else:
        slack_sent = email_sent = False
        print("[*] 신규 기사 {}건 모두 알림 기준 미달 또는 중복 억제 — 이벤트만 적재합니다.".format(len(new_articles)))

    # 일간/주간 리포트용 통합 이벤트 로그 적재
    unified_events = []
    for article in new_articles:
        enrichment = article.get("enrichment") or {}
        unified_events.append(
            common_utils.make_event(
                "boannews",
                article["id"],
                article["title"],
                url=article["link"],
                image_url=article.get("image_url", ""),
                summary=article["summary"],
                severity=enrichment.get("severity") or "",
                cves=article.get("extracted_cves"),
                category=enrichment.get("category") or "",
                category_reason=enrichment.get("category_reason") or "",
                affected_products=enrichment.get("affected_products"),
                threat_actor=enrichment.get("threat_actor") or "",
                malware_family=enrichment.get("malware_family") or "",
                relevance=enrichment.get("relevance") or "",
                confidence=enrichment.get("confidence") or "",
                iocs=article.get("iocs"),
                attack_techniques=article.get("attack_techniques"),
                pirs=enrichment.get("pirs"),
                published_at=parse_rss_datetime(article["pub_date"]) or article.get("article_published_at") or "",
                ai_summary=enrichment.get("summary"),
                email_sent=email_sent and article["alert"],
                slack_sent=slack_sent and article["alert"],
                triage=article.get("triage"),
                importance=article.get("importance"),
                cluster=article["cluster"],
                content_depth=enrichment.get("content_depth") or "",
                analyst_review=enrichment.get("analyst_review"),
                novelty=enrichment.get("novelty") or "",
                body_chars=len(article.get("body") or ""),
                recommended_actions=enrichment.get("recommended_actions"),
                affected_versions=enrichment.get("affected_versions"),
                fix_available=enrichment.get("fix_available"),
                remediation=enrichment.get("patch_info") or "",
            )
        )
    common_utils.append_events(unified_events)

    updated_sent_ids = state["sent_ids"] + [article["id"] for article in new_articles]
    save_state(updated_sent_ids)

    print("처리 완료: 신규 기사 {}건 (알림 {}건, 리포트만 {}건)".format(
        len(new_articles), len(alert_articles), len(new_articles) - len(alert_articles)
    ))


if __name__ == "__main__":
    main()
