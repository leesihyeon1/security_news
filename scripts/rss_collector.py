"""범용 RSS 수집기 — assets/feeds.json에 정의된 기사형 RSS 소스를 일괄 수집한다.

소스마다 다른 것(RSS URL, 본문 셀렉터, 웹훅)은 설정으로 두고, 공통 파이프라인
(신규 선별 → 본문 수집 → CVE·IOC·ATT&CK 추출 → EPSS 트리아지 → LLM enrichment
→ 중요도 스코어링 → 메일·슬랙 발송 → events.jsonl 적재)은 이 스크립트 하나가 담당한다.

중요도 스코어(0~100)가 임계값(NEWS_ALERT_MIN_SCORE, 기본 45) 미만인 기사는
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
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import requests
from bs4 import BeautifulSoup

import common_utils
from live_news import article_image

# Windows 콘솔(cp949)에서 기사 제목의 특수문자(— 등) 출력이 죽지 않도록 UTF-8로 강제
for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

FEEDS_FILE = common_utils.ASSETS_DIR / "feeds.json"
# 기사 1건당 식별 키를 여러 개(link/guid) 기억하므로, 기존과 같은 "기사 수"를
# 기억하려면 그만큼 여유가 필요하다 (article_identity_keys 참고).
MAX_STORED_SENT_IDS = 1500
# AI 분석 실패 시 같은 기사를 몇 번까지 재시도할지. 수집 주기가 5분이라 3회면
# 약 15분 안에 결론이 난다 — 그 안에 NVIDIA가 복구되면 정상 분석되고, 아니면
# 분석 없이 적재하되 알림은 보류한다.
ENRICH_MAX_ATTEMPTS = 3
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


# 발행된 지 이보다 오래된 항목은 새로 보이더라도 수집하지 않는다. 피드가 따로
# max_age_days를 지정하면 그 값이 우선한다(0이면 나이 제한 없음).
DEFAULT_MAX_AGE_DAYS = 14


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


class FeedNotServedError(RuntimeError):
    """HTTP 200인데 돌아온 것이 피드가 아닐 때.

    왜 예외로 올리나
        조용한 실패가 제일 찾기 어렵다. 실측(2026-09-16): Google Security Blog 요청에
        피드 대신 가로채기 페이지가 200으로 돌아왔다 — meta refresh로 feedburner를
        가리키고 iframe이 IP 리터럴을 열도록 되어 있었다(재시도하면 정상 XML 513KB가
        온다). 파서는 항목 0건을 돌려주고, 수집기는 그것을 "신규 기사가 없습니다"로
        찍고 넘어갔다. 새 글이 없는 것과 피드를 못 받은 것이 화면에서 구별되지 않았다.

        항목이 0건인 것 자체는 정상일 수 있다(그날 글이 없는 피드). 그래서 항목 수가
        아니라 문서의 뿌리를 본다 — rss·feed·channel·RDF 중 아무것도 없으면 피드가
        아니다.
    """


# 피드 문서의 뿌리. 이 중 하나라도 있으면 항목이 0건이어도 "빈 피드"로 본다.
FEED_ROOT_TAGS = ("rss", "feed", "channel", "RDF")
# 실패 메시지에 본문 앞부분을 조금 남긴다 — 차단 페이지인지 리다이렉트인지 바로 보인다.
NOT_FEED_SNIPPET_CHARS = 160


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
                "guid": guid,
                "title": title,
                "link": link or guid,
                "summary_html": item_text(item, "description"),
                "content_html": item_text(item, "encoded"),
                "pub_date": item_text(item, "pubDate"),
                "image_url": article_image(item, link or guid) or article_image(
                    item_text(item, "encoded") or item_text(item, "description"), link or guid),
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
                "guid": entry_id,
                "title": title,
                "link": link or entry_id,
                "summary_html": item_text(entry, "summary"),
                "content_html": item_text(entry, "content"),
                "pub_date": item_text(entry, "published") or item_text(entry, "updated"),
                "image_url": article_image(entry, link) or article_image(
                    item_text(entry, "content") or item_text(entry, "summary"), link),
            }
        )
    if not items and not any(soup.find(tag) for tag in FEED_ROOT_TAGS):
        snippet = " ".join((resp.text or "")[:NOT_FEED_SNIPPET_CHARS * 3].split())
        raise FeedNotServedError(
            "HTTP {}인데 피드가 아닙니다(최종 URL {}): {}".format(
                resp.status_code, resp.url[:80], snippet[:NOT_FEED_SNIPPET_CHARS]))
    return items


CVSS_SCORE_RE = re.compile(
    r"CVSS(?:\s*v?[23](?:\.\d)?)?\s*(?:base\s*)?(?:score)?\s*[:=]?\s*(\d{1,2}(?:\.\d)?)", re.I)
CVSS_OF_RE = re.compile(r"CVSS[^.\n]{0,20}?\bof\s+(\d{1,2}(?:\.\d)?)", re.I)
SEVERITY_LABEL_RE = re.compile(r"severity\s*[:=]\s*(critical|high|medium|moderate|low)", re.I)
# 벤더가 CVSS 수치 없이 등급만 줄 때 쓰는 대표값 — 밴드 하한이라 과대평가되지 않는다.
SEVERITY_TO_SCORE = {"critical": 9.0, "high": 7.5, "medium": 5.0, "moderate": 5.0, "low": 3.0}


def parse_cvss_score(*texts):
    """제목·본문에서 CVSS 점수를 뽑는다. 없으면 심각도 등급을 대표값으로 환산.

    벤더 PSIRT는 심각도가 CVSS로 표현되는데(Fortinet 본문 "CVSSv3 Score: 7.5",
    Palo Alto 제목 "(Severity: HIGH)"), 이걸 안 넘기면 classify_urgency가
    impact를 키워드로만 판단해 경미한 것과 심각한 것이 같은 점수를 받는다.
    """
    text = " ".join(t for t in texts if t)
    for pattern in (CVSS_SCORE_RE, CVSS_OF_RE):
        match = pattern.search(text)
        if match:
            try:
                value = float(match.group(1))
            except ValueError:
                continue
            if 0.0 <= value <= 10.0:
                return value
    match = SEVERITY_LABEL_RE.search(text)
    if match:
        return SEVERITY_TO_SCORE.get(match.group(1).lower())
    return None


def title_matches_any(title, patterns):
    return any(re.search(pattern, title or "", re.I) for pattern in (patterns or []))


def article_identity_keys(item):
    """이미 처리한 기사인지 판정할 때 쓸 후보 키 전부.

    어느 쪽이 안정적인지가 피드마다 다르다 — CrowdStrike는 guid가 조회할 때마다
    바뀌고(`?p=556469` -> `?p=516742`) link가 고정인 반면, 피드버너류는 그 반대다.
    guid만 믿었더니 같은 기사를 49번 수집·발송한 사례가 있어(2026-08 실측),
    둘 다 기억해두고 하나라도 맞으면 이미 본 기사로 취급한다.
    """
    keys = []
    for value in (item.get("link"), item.get("guid"), item.get("id")):
        value = (value or "").strip()
        if value and value not in keys:
            keys.append(value)
    return keys


ARTICLE_FETCH_RETRIES = 2
ARTICLE_FETCH_RETRY_DELAY_SECONDS = 3


def fetch_article_body(feed, url, article=None):
    """기사 페이지에서 본문 텍스트 추출. 실패 시 ""(RSS 내용으로 대체).

    일부 사이트(예: CrowdStrike)는 RSS에 본문 요약이 아예 없어 이 스크래핑이
    실패하면 대체할 텍스트가 없다 — 봇 차단 등 일시적 네트워크 실패가 흔하므로
    재시도 없이 바로 포기하지 않는다(선택자 불일치 등 구조적 실패는 재시도해도
    안 바뀌므로 대상이 아니다).
    """
    resp = None
    last_error = None
    for attempt in range(1, ARTICLE_FETCH_RETRIES + 1):
        try:
            resp = requests.get(url, headers=REQUEST_HEADERS, timeout=20)
            resp.raise_for_status()
            last_error = None
            break
        except Exception as error:
            last_error = error
            resp = None
            if attempt < ARTICLE_FETCH_RETRIES:
                print("[-] 본문 페이지 수집 실패({}, {}차 시도): {} — 재시도".format(url, attempt, error))
                time.sleep(ARTICLE_FETCH_RETRY_DELAY_SECONDS)

    if resp is None:
        print("[-] 본문 페이지 수집 실패({}): {}".format(url, last_error))
        return ""

    soup = BeautifulSoup(resp.content, "html.parser")
    if article is not None:
        article["image_url"] = article_image(soup, url) or article.get("image_url", "")

    # body_selector가 본문을 여러 조각(문단/섹션 div)으로 나눠 반환하는 사이트가 있다
    # (예: CrowdStrike 블로그 — 이미지·인용구 사이사이로 본문이 여러 div에 쪼개져 있음).
    # select_one으로 첫 조각만 가져오면 본문이 잘려버리므로 매칭되는 조각을 전부 합친다.
    containers = soup.select(feed["body_selector"]) if feed.get("body_selector") else []
    if not containers:
        article = soup.find("article")
        containers = [article] if article is not None else []
    if containers:
        text = " ".join(container.get_text(" ", strip=True) for container in containers)
        return common_utils.clean_text(text)[:BODY_MAX_CHARS]

    print("[-] 본문 컨테이너를 찾지 못해 RSS 내용으로 대체합니다: {}".format(url))
    return ""


def resolve_body(feed, article):
    """본문 우선순위: 기사 페이지(설정 시) → RSS 전문(content:encoded) → RSS 요약"""
    if feed.get("fetch_body"):
        body = fetch_article_body(feed, article["link"], article)
        if body:
            return body
    return html_to_text(article["content_html"] or article["summary_html"])[:BODY_MAX_CHARS]


def alert_summary(article):
    """알림용 요약: enrichment 한국어 요약 우선, 없으면 원문 발췌"""
    enrichment = article.get("enrichment") or {}
    if enrichment.get("summary"):
        return enrichment["summary"]
    return (html_to_text(article["summary_html"]) or article["body"])[:300]


def category_tag(article):
    """LLM 분류 카테고리 태그(예: "[취약점] "). 분류가 없으면 빈 문자열."""
    category = (article.get("enrichment") or {}).get("category")
    return "[{}] ".format(category) if category else ""


def send_combined_email(feed_alerts):
    """실행 전체(여러 피드)의 알림 대상 기사를 모아 이메일 한 통으로 발송.

    피드마다 따로 보내면(--all로 수십 개 피드를 처리할 때) Gmail 일일 발송 한도를
    금방 넘기므로, 한 번의 실행에서는 이메일을 항상 한 통으로 합쳐서 보낸다.
    슬랙은 피드별로 채널이 다르므로 이 함수와 무관하게 피드마다 그대로 보낸다.
    """
    total = sum(len(alerts) for _, alerts in feed_alerts)
    subject = "RSS 신규 보안 기사 {}건 ({}개 피드)".format(total, len(feed_alerts))
    checked_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    text_lines = [subject, "체크 시간: {}".format(checked_at), ""]
    html_parts = [
        "<html><body>",
        "<h2>{}</h2>".format(html.escape(subject)),
        "<p>체크 시간: {}</p>".format(checked_at),
    ]

    idx = 0
    for feed, alerts in feed_alerts:
        text_lines.append("== {} ==".format(feed["label"]))
        html_parts.append("<h3>{}</h3>".format(html.escape(feed["label"])))
        for article in alerts:
            idx += 1
            summary = alert_summary(article)
            tag = category_tag(article)
            response = " · ".join(common_utils.enrichment_response_bits(article.get("enrichment")))
            tracked_link = common_utils.tracking_url("{}:{}".format(feed["name"], article["id"]), article["link"])
            text_lines.append("{}. {}{}".format(idx, tag, article["title"]))
            text_lines.append("요약: {}".format(summary))
            if response:
                text_lines.append("대응: {}".format(response))
            text_lines.append("링크: {}".format(tracked_link))
            text_lines.append("")

            html_parts.append("<hr>")
            html_parts.append("<h4>{}. {}{}</h4>".format(idx, html.escape(tag), html.escape(article["title"])))
            html_parts.append("<p>{}</p>".format(html.escape(summary)))
            if response:
                html_parts.append("<p><b>대응:</b> {}</p>".format(html.escape(response)))
            html_parts.append(
                '<p><a href="{0}">{0}</a></p>'.format(html.escape(tracked_link))
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
        response = " · ".join(common_utils.enrichment_response_bits(article.get("enrichment")))
        tracked_link = common_utils.tracking_url("{}:{}".format(feed["name"], article["id"]), article["link"])
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "{}{}*{}*{}\n\n{}{}\n\n<{}|기사 보기> · 중요도 {}점".format(
                            common_utils.triage_marker(triage),
                            category_tag(article),
                            article["title"],
                            common_utils.triage_note(triage),
                            alert_summary(article),
                            "\n🔧 {}".format(response) if response else "",
                            tracked_link,
                            (article.get("importance") or {}).get("score", "-"),
                        )
                    ),
                },
            }
        )
        # 피드백 참조 해시 — 슬랙 폴러가 반응(👍/👎)을 이 ref로 이벤트에 역매핑한다
        blocks.append(
            {
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": "`ref:{}` · 👍 유용 / 👎 노이즈 반응으로 피드백".format(
                        common_utils.event_ref("{}:{}".format(feed["name"], article["id"]))
                    ),
                }],
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
        cluster = article.get("cluster") or {}
        if cluster.get("suppressed"):
            verdict = "중복 억제"
        elif article.get("alert"):
            verdict = "알림"
        else:
            verdict = "리포트만"
        print("  중요도: {}점 ({}) → {}".format(
            importance.get("score"),
            ", ".join(importance.get("reasons") or []) or "가점 없음",
            verdict,
        ))
        if cluster.get("related_ids"):
            print("  클러스터: 관련 {}건 | 교차 소스: {} | 기존 알림: {}{}".format(
                len(cluster["related_ids"]),
                ", ".join(cluster.get("corroborating_sources") or []) or "-",
                "예" if cluster.get("already_alerted") else "아니오",
                " | 승격 재알림" if cluster.get("escalated") else "",
            ))
        if enrichment:
            print("  enrichment: {}".format(json.dumps(enrichment, ensure_ascii=False)))


def collect_feed(feed, dry_run=False, enrich_enabled=True, limit=None):
    """기사 수집부터 중요도/클러스터링까지 처리하고, 피드별 채널로 슬랙까지 보낸다.

    이메일은 실행 전체(여러 피드)를 모아 한 통으로 보내야 하므로 여기서는 보내지
    않고, finalize_feed()가 쓸 결과(dict)만 반환한다. 새 기사가 없거나 dry-run이면
    None을 반환한다.
    """
    print("[*] {} 수집 시작...".format(feed["label"]))
    state = common_utils.load_json_state(state_file(feed), lambda: {"sent_ids": []})
    sent_ids = set(state["sent_ids"])

    items = fetch_feed_items(feed)

    # 벤더 PSIRT 피드는 몇 년 전 어드바이저리까지 그대로 들고 있다(Fortinet 실측: 2022년
    # 항목 포함). 나중에 걸러도 소용없다 — max_items 몫을 옛 항목이 먼저 차지해버리므로
    # 신규 판정 전에 잘라낸다. 날짜를 못 읽은 항목은 버리지 않는다(피드마다 형식이 달라서).
    # 기본값을 둔다. 예전에는 피드가 지정한 경우에만 걸러서, 아카이브를 통째로 들고
    # 있는 피드가 회차마다 옛 글을 새 글로 흘려보냈다(실측 2026-09-09: Elastic Security
    # Labs에서 2025-05까지의 글 38건이 하루에 신규로 수집돼 일간 리포트에 섞였다).
    # 발행일을 못 읽는 항목은 아래에서 그대로 남으므로, 형식이 특이한 피드가 통째로
    # 사라지지는 않는다.
    # 취약점·어드바이저리 피드는 기본 제한을 걸지 않는다 — 거기서 발행일은 "기사가
    # 나온 날"이 아니라 "취약점이 공개된 날"이고, 늦게 올라와도 대응 가치가 그대로다.
    default_age = 0 if feed["name"] in common_utils.NON_NEWS_SOURCES else DEFAULT_MAX_AGE_DAYS
    max_age_days = feed.get("max_age_days", default_age)
    if max_age_days:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=int(max_age_days))).isoformat()
        fresh = [item for item in items if (parse_rss_datetime(item["pub_date"]) or cutoff) >= cutoff]
        if len(fresh) != len(items):
            print("[*] {}: {}일 이전 항목 {}건 제외".format(
                feed["label"], max_age_days, len(items) - len(fresh)))
        items = fresh

    # 발행 예고 공지처럼 취약점 정보가 없는 항목은 아예 수집하지 않는다
    # (예: "Cisco Advance Notification for Publication of ...").
    skip_patterns = feed.get("skip_title_patterns")
    if skip_patterns:
        kept = [item for item in items if not title_matches_any(item["title"], skip_patterns)]
        if len(kept) != len(items):
            print("[*] {}: 제외 패턴에 걸린 항목 {}건 제외".format(feed["label"], len(items) - len(kept)))
        items = kept

    max_items = limit or int(feed.get("max_items_per_run", DEFAULT_MAX_ITEMS))
    new_articles = [
        item for item in items
        if not any(key in sent_ids for key in article_identity_keys(item))
    ][:max_items]

    if not new_articles:
        print("[-] {}: 신규 기사가 없습니다.".format(feed["label"]))
        return None

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
        # 벤더 PSIRT는 제목에 제품명이 없는 경우가 많다(Fortinet 실측: 제목만으로
        # 자산 매칭 0%). 소스 자체가 "그 벤더 제품"이라는 신호이므로, 피드가
        # implies_assets를 선언하면 그 용어를 매칭 대상 텍스트에 함께 넣어준다.
        match_values = [article["title"], article["body"]]
        if feed.get("implies_assets"):
            match_values.append(" ".join(feed["implies_assets"]))

        article["triage"] = common_utils.classify_urgency(
            match_values,
            cvss_score=parse_cvss_score(article["title"], article["body"]) if feed.get("parse_cvss") else None,
            epss=max(epss_values) if epss_values else None,
            exclude_assets=feed.get("ignore_asset_terms"),
        )
        if enrich_enabled and feed.get("enrich", True):
            print("[*] AI enrichment 생성 중: {}".format(article["title"][:60]))
            article["enrichment"] = common_utils.ai_enrich_article(article["title"], article["body"]) or {}
            # LLM 실패는 대개 일시적(NVIDIA 503)이다. 실패한 채로 진행하면 키워드
            # 트리아지를 LLM이 검증하지 못해 오히려 알림이 늘어난다(실측: 분석 실패
            # 기사의 알림 통과율 23.8% vs 정상 3.3%). 여기서는 표시만 하고,
            # 아래에서 이번 회차 처리를 보류해 다음 실행에서 다시 시도한다.
            article["enrichment_ok"] = bool(article["enrichment"])
        else:
            article["enrichment"] = {}
            article["enrichment_ok"] = True  # 애초에 분석을 안 하기로 한 피드
        # 정규식 추출(명시된 ID) + LLM 매핑(서술형, 공식 카탈로그로 검증됨) 병합
        for technique in article["enrichment"].get("attack_techniques") or []:
            if technique not in article["attack_techniques"]:
                article["attack_techniques"].append(technique)
        # LLM 악용 판정으로 키워드 기반 트리아지를 보정 (회고성 기사 하향, 표현 변형 상향)
        article["triage"] = common_utils.refine_triage_with_enrichment(article["triage"], article["enrichment"])
        article["importance"] = common_utils.score_importance(
            triage=article["triage"], enrichment=article["enrichment"], cves=article["cves"],
            reliability=feed.get("reliability"),
        )

        # 크로스소스 클러스터링: 최근 72시간 내 같은 사건 검색 → 교차 보도 가점 / 중복 알림 억제
        related = common_utils.find_related_events(
            article["cves"], article["title"], exclude_source=feed["name"],
        )
        cluster = common_utils.build_cluster_context(related, triage=article["triage"])
        if cluster["bonus"]:
            article["importance"]["score"] = min(100, article["importance"]["score"] + cluster["bonus"])
            article["importance"]["reasons"].append(
                "교차 보도 {}곳(+{})".format(len(cluster["corroborating_sources"]), cluster["bonus"])
            )

        article["alert"] = common_utils.should_alert(
            article["importance"], triage=article["triage"], min_score=feed.get("min_score"),
        )
        # 여러 CVE를 한 문서에 묶은 정기 릴리스·월간 업데이트는 키워드를 쓸어담아
        # 개별 취약점보다 높은 등급을 받는다(실측: "Security Hardening Release"가 P1 76점,
        # 실제 개별 취약점은 P3 33점). 리포트에는 남기고 즉시 알림만 막는다.
        # 벤더가 스스로 낮은 등급으로 매긴 취약점은 즉시 알림 대상이 아니다. 다만
        # 등급을 못 읽었을 때(cvss=None, 예: Cisco RSS는 CVSS를 안 실음) 억제하면
        # 정보 부족을 안전 신호로 착각하는 것이므로, 실제로 읽힌 경우에만 적용한다.
        min_cvss = feed.get("min_cvss_for_alert")
        if article["alert"] and min_cvss and article["triage"].get("exploitation") == "none":
            cvss = parse_cvss_score(article["title"], article["body"])
            if cvss is not None and cvss < float(min_cvss):
                article["alert"] = False
                article["importance"]["reasons"].append(
                    "벤더 등급 CVSS {} < {} 이고 악용 정황 없음 — 즉시 알림 제외(리포트만)".format(cvss, min_cvss)
                )
                print("[*] 벤더 등급 미달로 알림 제외(CVSS {}): {}".format(cvss, article["title"][:55]))

        if article["alert"] and title_matches_any(article["title"], feed.get("no_alert_title_patterns")):
            article["alert"] = False
            article["importance"]["reasons"].append("묶음/정기 공지 — 즉시 알림 제외(리포트만)")
            print("[*] 묶음 공지로 알림 제외: {}".format(article["title"][:60]))
        cluster["suppressed"] = bool(
            article["alert"] and cluster["already_alerted"] and not cluster["escalated"]
        )
        if cluster["suppressed"]:
            article["alert"] = False
            print("[*] 중복 알림 억제: {} (기존 알림 소스: {})".format(
                article["title"][:60], ", ".join(cluster["corroborating_sources"])
            ))
        elif cluster["escalated"]:
            article["importance"]["reasons"].append("기존 알림 대비 위험도 승격 — 재알림")
        article["cluster"] = cluster

    if dry_run:
        print_dry_run(feed, new_articles)
        return None

    # LLM 분석에 실패한 기사는 이번 회차 처리를 통째로 보류한다 — 알림도, 이벤트
    # 적재도, 발송 기록도 남기지 않으므로 다음 실행에서 신규 기사로 다시 잡힌다.
    # 다만 NVIDIA 장애가 길어질 때 같은 기사가 영원히 앞을 막지 않도록 시도 횟수를
    # 제한하고, 한도를 넘기면 분석 없이 진행하되 알림은 하지 않는다(리포트에는 적재).
    attempts = dict(state.get("enrich_attempts") or {})
    deferred = []
    kept = []
    for article in new_articles:
        if article.get("enrichment_ok", True):
            for key in article_identity_keys(article):
                attempts.pop(key, None)
            kept.append(article)
            continue

        key = article_identity_keys(article)[0]
        count = attempts.get(key, 0) + 1
        if count < ENRICH_MAX_ATTEMPTS:
            attempts[key] = count
            deferred.append((article, count))
        else:
            attempts.pop(key, None)
            article["alert"] = False
            article["importance"]["reasons"].append(
                "AI 분석 {}회 실패 — 검증 불가로 알림 보류(리포트만)".format(ENRICH_MAX_ATTEMPTS)
            )
            print("[-] {}: AI 분석 {}회 실패, 알림 없이 적재합니다: {}".format(
                feed["label"], ENRICH_MAX_ATTEMPTS, article["title"][:60]))
            kept.append(article)

    for article, count in deferred:
        print("[*] {}: AI 분석 실패({}/{}) — 다음 실행에서 재시도합니다: {}".format(
            feed["label"], count, ENRICH_MAX_ATTEMPTS, article["title"][:60]))

    if attempts != (state.get("enrich_attempts") or {}):
        state["enrich_attempts"] = attempts
        common_utils.save_json_state(
            state_file(feed), state,
            max_items=MAX_STORED_SENT_IDS, keys_to_trim=["sent_ids"],
        )

    new_articles = kept
    if not new_articles:
        print("[-] {}: 처리할 기사가 없습니다(전부 재시도 대기).".format(feed["label"]))
        return None

    # 중요도 미달 기사는 알림 없이 events.jsonl에만 적재한다 (일간 리포트에서 확인).
    alerts = [article for article in new_articles if article["alert"]]
    if alerts:
        slack_sent = send_to_slack(feed, alerts)
    else:
        slack_sent = False
        print("[*] {}: 중요도 임계값 미달 {}건 — 알림 생략, 리포트용으로만 적재".format(
            feed["label"], len(new_articles)
        ))

    return {
        "feed": feed,
        "state": state,
        "new_articles": new_articles,
        "alerts": alerts,
        "slack_sent": slack_sent,
    }


def finalize_feed(result, email_sent):
    """collect_feed() 결과를 이벤트 적재 + 상태 저장으로 마무리.

    email_sent는 이번 실행에서 보낸 단일 통합 이메일의 성공 여부(전체 피드 공통) —
    슬랙은 피드별로 이미 collect_feed()에서 보냈으므로 그 결과(slack_sent)를 그대로 쓴다.
    """
    feed = result["feed"]
    state = result["state"]
    new_articles = result["new_articles"]
    alerts = result["alerts"]
    slack_sent = result["slack_sent"]

    events = []
    for article in new_articles:
        enrichment = article["enrichment"]
        events.append(
            common_utils.make_event(
                feed["name"],
                article["id"],
                article["title"],
                url=article["link"],
                image_url=article.get("image_url", ""),
                summary=(html_to_text(article["summary_html"]) or article["body"])[:500],
                severity=enrichment.get("severity") or "",
                cves=article["cves"],
                category=enrichment.get("category") or "",
                category_reason=enrichment.get("category_reason") or "",
                affected_products=enrichment.get("affected_products"),
                threat_actor=enrichment.get("threat_actor") or "",
                malware_family=enrichment.get("malware_family") or "",
                relevance=enrichment.get("relevance") or "",
                confidence=enrichment.get("confidence") or "",
                iocs=article["iocs"],
                attack_techniques=article["attack_techniques"],
                pirs=enrichment.get("pirs"),
                published_at=article["published_at"],
                ai_summary=enrichment.get("summary"),
                email_sent=email_sent and article["alert"],
                slack_sent=slack_sent and article["alert"],
                triage=article["triage"],
                importance=article["importance"],
                cluster=article["cluster"],
                content_depth=enrichment.get("content_depth") or "",
                analyst_review=enrichment.get("analyst_review"),
                novelty=enrichment.get("novelty") or "",
                body_chars=len(article["body"] or ""),
                recommended_actions=enrichment.get("recommended_actions"),
                affected_versions=enrichment.get("affected_versions"),
                fix_available=enrichment.get("fix_available"),
                remediation=enrichment.get("patch_info") or "",
            )
        )
    common_utils.append_events(events)

    # 알림 대상이 있었는데 메일/슬랙이 둘 다 실패하면, 이벤트는 이미 위에서 적재했으니
    # 상태만 저장하지 않고 다음 실행에서 알림 재시도 (리포트 데이터 유실은 없음).
    if alerts and not email_sent and not slack_sent:
        print("[-] {}: 메일/슬랙 발송이 모두 실패하여 알림 상태를 저장하지 않습니다(이벤트는 적재됨, 다음 실행에서 재시도).".format(feed["label"]))
        return

    updated_ids = state["sent_ids"] + [
        key for article in new_articles for key in article_identity_keys(article)
    ]
    state["sent_ids"] = updated_ids  # enrich_attempts 등 다른 키를 덮어쓰지 않는다
    common_utils.save_json_state(
        state_file(feed), state,
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
            print("- {} ({}) enabled={} enrich={} reliability={}".format(
                feed["name"], feed["label"], feed.get("enabled", True), feed.get("enrich", True),
                feed.get("reliability") or "-",
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

    results = []
    for feed in selected:
        # 피드 하나가 죽어도 나머지는 계속 수집한다
        try:
            result = collect_feed(feed, dry_run=args.dry_run, enrich_enabled=not args.no_enrich, limit=args.limit)
            if result:
                results.append(result)
        except Exception as error:
            print("[-] {} 처리 중 오류: {}".format(feed.get("label") or feed.get("name"), error))

    if args.dry_run or not results:
        return

    # 이메일은 이번 실행에서 처리한 모든 피드를 모아 한 통으로 보낸다(Gmail 발송 한도 보호).
    feed_alerts = [(result["feed"], result["alerts"]) for result in results if result["alerts"]]
    email_sent = send_combined_email(feed_alerts) if feed_alerts else False

    for result in results:
        finalize_feed(result, email_sent)


if __name__ == "__main__":
    main()
