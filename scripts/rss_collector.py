"""범용 RSS 수집기 — assets/feeds.json에 정의된 기사형 RSS 소스를 일괄 수집한다.

소스마다 다른 것(RSS URL, 본문 셀렉터, 웹훅)은 설정으로 두고, 공통 파이프라인
(신규 선별 → 본문 수집 → CVE·IOC·ATT&CK 추출 → EPSS 트리아지 → LLM enrichment
→ 중요도 스코어링 → 메일·슬랙 발송 → events.jsonl 적재)은 이 스크립트 하나가 담당한다.

중요도 스코어(0~100)가 임계값(NEWS_ALERT_MIN_SCORE, 기본 50) 미만인 기사는
즉시 알림을 생략하고 events.jsonl에만 적재해 일간 리포트에서 다룬다.
P1/P2 트리아지는 점수와 무관하게 항상 알림된다. 피드별 min_score로 조정 가능.
RSS 2.0과 Atom 피드를 모두 지원한다.

구조가 다른 소스(API 기반, 인증 필요, 비RSS)는 여기에 우겨넣지 말고
NVD/MSRC처럼 전용 수집기를 만든다. 통합 스키마(make_event)만 지키면 된다.

사용법:
    python rss_collector.py --all
    python rss_collector.py --feed thehackernews --feed sans_isc
    python rss_collector.py --feed thehackernews --dry-run --no-enrich --limit 2
    python rss_collector.py --list
"""

import argparse
import html
import json
import os
import sys
from datetime import datetime
from email.utils import parsedate_to_datetime

import requests
from bs4 import BeautifulSoup

import common_utils

# Windows 콘솔(cp949)에서 기사 제목의 특수문자(— 등) 출력이 죽지 않도록 UTF-8로 강제
for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

FEEDS_FILE = common_utils.ASSETS_DIR / "feeds.json"
MAX_STORED_SENT_IDS = 500
BODY_MAX_CHARS = 20000
DEFAULT_MAX_ITEMS = 5
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
}


def load_feeds():
    with FEEDS_FILE.open("r", encoding="utf-8") as file:
        feeds = json.load(file)

    valid = []
    for feed in feeds:
        if not all(feed.get(key) for key in ("name", "label", "rss_url")):
            print("[-] feeds.json 항목에 name/label/rss_url이 없어 건너뜁니다: {}".format(feed))
            continue
        valid.append(feed)
    return valid


def state_file(feed):
    return common_utils.STATE_DIR / "rss_{}_sent_state.json".format(feed["name"])


def item_text(item, tag):
    found = item.find(tag)
    return found.text.strip() if found is not None and found.text else ""


def parse_rss_datetime(value):
    if not value:
        return ""
    try:
        return parsedate_to_datetime(value).isoformat()
    except (TypeError, ValueError, IndexError):
        pass
    # Atom(ISO 8601) 날짜 폴백
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return ""


def html_to_text(raw_html):
    if not raw_html:
        return ""
    return common_utils.clean_text(BeautifulSoup(raw_html, "html.parser").get_text(" ", strip=True))


def fetch_feed_items(feed):
    resp = requests.get(feed["rss_url"], headers=REQUEST_HEADERS, timeout=20)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.content, "xml")

    items = []
    for item in soup.find_all("item"):
        link = item_text(item, "link")
        guid = item_text(item, "guid")
        title = common_utils.clean_text(item_text(item, "title"))
        if not (link or guid) or not title:
            continue
        items.append(
            {
                "id": guid or link,
                "title": title,
                "link": link or guid,
                "summary_html": item_text(item, "description"),
                "content_html": item_text(item, "encoded"),
                "pub_date": item_text(item, "pubDate"),
            }
        )
    if items:
        return items

    # Atom 피드 폴백 (<entry> 기반 — Google 보안 블로그 등)
    for entry in soup.find_all("entry"):
        link_el = entry.find("link", rel="alternate") or entry.find("link")
        link = (link_el.get("href") or "").strip() if link_el is not None else ""
        entry_id = item_text(entry, "id")
        title = common_utils.clean_text(item_text(entry, "title"))
        if not (link or entry_id) or not title:
            continue
        items.append(
            {
                "id": entry_id or link,
                "title": title,
                "link": link or entry_id,
                "summary_html": item_text(entry, "summary"),
                "content_html": item_text(entry, "content"),
                "pub_date": item_text(entry, "published") or item_text(entry, "updated"),
            }
        )
    return items


def fetch_article_body(feed, url):
    """기사 페이지에서 본문 텍스트 추출. 실패 시 ""(RSS 내용으로 대체)."""
    try:
        resp = requests.get(url, headers=REQUEST_HEADERS, timeout=20)
        resp.raise_for_status()
    except Exception as error:
        print("[-] 본문 페이지 수집 실패({}): {}".format(url, error))
        return ""

    soup = BeautifulSoup(resp.content, "html.parser")

    container = None
    if feed.get("body_selector"):
        container = soup.select_one(feed["body_selector"])
    if container is None:
        container = soup.find("article")
    if container is not None:
        return common_utils.clean_text(container.get_text(" ", strip=True))[:BODY_MAX_CHARS]

    # 최후 수단: 문단 텍스트 이어붙이기
    text = " ".join(
        paragraph for el in soup.find_all("p")
        if len(paragraph := el.get_text(" ", strip=True)) > 30
    )
    return common_utils.clean_text(text)[:BODY_MAX_CHARS]


def resolve_body(feed, article):
    """본문 우선순위: 기사 페이지(설정 시) → RSS 전문(content:encoded) → RSS 요약"""
    if feed.get("fetch_body"):
        body = fetch_article_body(feed, article["link"])
        if body:
            return body
    return html_to_text(article["content_html"] or article["summary_html"])[:BODY_MAX_CHARS]


def alert_summary(article):
    """알림용 요약: enrichment 한국어 요약 우선, 없으면 원문 발췌"""
    enrichment = article.get("enrichment") or {}
    if enrichment.get("summary"):
        return enrichment["summary"]
    return (html_to_text(article["summary_html"]) or article["body"])[:300]


def send_email(feed, articles):
    subject = "[{}] 신규 보안 기사 {}건".format(feed["label"], len(articles))
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    text_lines = [subject, "체크 시간: {}".format(checked_at), ""]
    html_parts = [
        "<html><body>",
        "<h2>{}</h2>".format(html.escape(subject)),
        "<p>체크 시간: {}</p>".format(checked_at),
    ]

    for idx, article in enumerate(articles, start=1):
        summary = alert_summary(article)
        text_lines.append("{}. {}".format(idx, article["title"]))
        text_lines.append("요약: {}".format(summary))
        text_lines.append("링크: {}".format(article["link"]))
        text_lines.append("")

        html_parts.append("<hr>")
        html_parts.append("<h3>{}. {}</h3>".format(idx, html.escape(article["title"])))
        html_parts.append("<p>{}</p>".format(html.escape(summary)))
        html_parts.append(
            '<p><a href="{0}">{0}</a></p>'.format(html.escape(article["link"]))
        )

    html_parts.append("</body></html>")
    return common_utils.send_email_message(subject, "\n".join(text_lines), "".join(html_parts))


def send_to_slack(feed, articles):
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "📰 {} 신규 기사".format(feed["label"]), "emoji": True},
        },
        {"type": "context", "elements": [{"type": "mrkdwn", "text": "🕒 {}".format(checked_at)}]},
        {"type": "divider"},
    ]

    for article in articles:
        triage = article.get("triage")
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "{}*{}*{}\n\n{}\n\n<{}|기사 보기> · 중요도 {}점".format(
                            common_utils.triage_marker(triage),
                            article["title"],
                            common_utils.triage_note(triage),
                            alert_summary(article),
                            article["link"],
                            (article.get("importance") or {}).get("score", "-"),
                        )
                    ),
                },
            }
        )

    payload = {
        "text": "{} 신규 기사 {}건이 수집되었습니다.".format(feed["label"], len(articles)),
        "blocks": blocks,
    }
    webhook_url = common_utils.pick_webhook(
        os.environ.get(feed.get("slack_webhook_env") or "") or None,
        [article.get("triage") for article in articles],
    )
    return common_utils.send_slack_webhook(payload, webhook_url)


def print_dry_run(feed, articles):
    print("===== DRY RUN: {} — 발송·저장 생략 =====".format(feed["label"]))
    for article in articles:
        enrichment = article.get("enrichment") or {}
        print("- {}".format(article["title"]))
        print("  링크: {}".format(article["link"]))
        print("  published_at: {} | 본문 {}자".format(article["published_at"], len(article["body"])))
        print("  트리아지: {} | CVE: {} | IOC: {}건 | ATT&CK: {}".format(
            (article.get("triage") or {}).get("level"),
            article["cves"], len(article["iocs"]), article["attack_techniques"],
        ))
        importance = article.get("importance") or {}
        print("  중요도: {}점 ({}) → {}".format(
            importance.get("score"),
            ", ".join(importance.get("reasons") or []) or "가점 없음",
            "알림" if article.get("alert") else "리포트만",
        ))
        if enrichment:
            print("  enrichment: {}".format(json.dumps(enrichment, ensure_ascii=False)))


def process_feed(feed, dry_run=False, enrich_enabled=True, limit=None):
    print("[*] {} 수집 시작...".format(feed["label"]))
    state = common_utils.load_json_state(state_file(feed), lambda: {"sent_ids": []})
    sent_ids = set(state["sent_ids"])

    items = fetch_feed_items(feed)
    max_items = limit or int(feed.get("max_items_per_run", DEFAULT_MAX_ITEMS))
    new_articles = [item for item in items if item["id"] not in sent_ids][:max_items]

    if not new_articles:
        print("[-] {}: 신규 기사가 없습니다.".format(feed["label"]))
        return

    print("[!] {}: 신규 기사 {}건".format(feed["label"], len(new_articles)))

    for article in new_articles:
        article["body"] = resolve_body(feed, article)
        article["published_at"] = parse_rss_datetime(article["pub_date"])
        article["cves"] = common_utils.extract_cves(article["title"], article["body"])
        article["iocs"] = common_utils.extract_iocs(article["body"])
        article["attack_techniques"] = common_utils.extract_attack_techniques(article["title"], article["body"])

    epss_scores = common_utils.fetch_epss_scores(
        [cve for article in new_articles for cve in article["cves"]]
    )
    for article in new_articles:
        epss_values = [epss_scores[cve] for cve in article["cves"] if cve in epss_scores]
        article["triage"] = common_utils.classify_urgency(
            [article["title"], article["body"]],
            epss=max(epss_values) if epss_values else None,
            exclude_assets=feed.get("ignore_asset_terms"),
        )
        if enrich_enabled and feed.get("enrich", True):
            print("[*] AI enrichment 생성 중: {}".format(article["title"][:60]))
            article["enrichment"] = common_utils.ai_enrich_article(article["title"], article["body"]) or {}
        else:
            article["enrichment"] = {}
        article["importance"] = common_utils.score_importance(
            triage=article["triage"], enrichment=article["enrichment"], cves=article["cves"],
        )
        article["alert"] = common_utils.should_alert(
            article["importance"], triage=article["triage"], min_score=feed.get("min_score"),
        )

    if dry_run:
        print_dry_run(feed, new_articles)
        return

    # 중요도 미달 기사는 알림 없이 events.jsonl에만 적재한다 (일간 리포트에서 확인).
    alerts = [article for article in new_articles if article["alert"]]
    if alerts:
        email_sent = send_email(feed, alerts)
        slack_sent = send_to_slack(feed, alerts)

        # 두 채널 모두 실패하면 상태를 저장하지 않고 다음 실행에서 재시도합니다.
        if not email_sent and not slack_sent:
            print("[-] {}: 메일/슬랙 발송이 모두 실패하여 상태를 저장하지 않습니다.".format(feed["label"]))
            return
    else:
        email_sent = slack_sent = False
        print("[*] {}: 중요도 임계값 미달 {}건 — 알림 생략, 리포트용으로만 적재".format(
            feed["label"], len(new_articles)
        ))

    events = []
    for article in new_articles:
        enrichment = article["enrichment"]
        events.append(
            common_utils.make_event(
                feed["name"],
                article["id"],
                article["title"],
                url=article["link"],
                summary=(html_to_text(article["summary_html"]) or article["body"])[:500],
                severity=enrichment.get("severity") or "",
                cves=article["cves"],
                category=enrichment.get("category") or "",
                affected_products=enrichment.get("affected_products"),
                threat_actor=enrichment.get("threat_actor") or "",
                malware_family=enrichment.get("malware_family") or "",
                relevance=enrichment.get("relevance") or "",
                confidence=enrichment.get("confidence") or "",
                iocs=article["iocs"],
                attack_techniques=article["attack_techniques"],
                published_at=article["published_at"],
                ai_summary=enrichment.get("summary"),
                email_sent=email_sent and article["alert"],
                slack_sent=slack_sent and article["alert"],
                triage=article["triage"],
                importance=article["importance"],
            )
        )
    common_utils.append_events(events)

    updated_ids = state["sent_ids"] + [article["id"] for article in new_articles]
    common_utils.save_json_state(
        state_file(feed), {"sent_ids": updated_ids},
        max_items=MAX_STORED_SENT_IDS, keys_to_trim=["sent_ids"],
    )
    print("[+] {}: 신규 기사 {}건 처리 완료 (알림 {}건, 리포트만 {}건)".format(
        feed["label"], len(new_articles), len(alerts), len(new_articles) - len(alerts)
    ))


def main():
    parser = argparse.ArgumentParser(description="범용 RSS 보안 기사 수집기")
    parser.add_argument("--feed", action="append", help="수집할 피드 이름 (복수 지정 가능)")
    parser.add_argument("--all", action="store_true", help="enabled된 모든 피드 수집")
    parser.add_argument("--list", action="store_true", help="설정된 피드 목록 출력")
    parser.add_argument("--dry-run", action="store_true", help="발송·저장 없이 결과만 출력")
    parser.add_argument("--no-enrich", action="store_true", help="LLM enrichment 생략 (테스트용)")
    parser.add_argument("--limit", type=int, default=None, help="피드당 처리 건수 상한 (테스트용)")
    args = parser.parse_args()

    feeds = load_feeds()

    if args.list:
        for feed in feeds:
            print("- {} ({}) enabled={} enrich={}".format(
                feed["name"], feed["label"], feed.get("enabled", True), feed.get("enrich", True)
            ))
        return

    if args.feed:
        requested = set(args.feed)
        selected = [feed for feed in feeds if feed["name"] in requested]
        missing = requested - {feed["name"] for feed in selected}
        if missing:
            print("[-] feeds.json에 없는 피드: {}".format(", ".join(sorted(missing))))
    elif args.all:
        selected = [feed for feed in feeds if feed.get("enabled", True)]
    else:
        parser.error("--all 또는 --feed <name>을 지정하세요.")
        return

    for feed in selected:
        # 피드 하나가 죽어도 나머지는 계속 수집한다
        try:
            process_feed(feed, dry_run=args.dry_run, enrich_enabled=not args.no_enrich, limit=args.limit)
        except Exception as error:
            print("[-] {} 처리 중 오류: {}".format(feed.get("label") or feed.get("name"), error))


if __name__ == "__main__":
    main()
