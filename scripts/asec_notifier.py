import os
import json
import sys
import requests
from bs4 import BeautifulSoup
from email.utils import parsedate_to_datetime
from pathlib import Path
import common_utils

# Windows 콘솔(cp949)에서 특수문자 출력이 죽지 않도록 UTF-8로 강제
for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

# ================= [ 설정 영역 ] =================
ASEC_RSS_URL = "https://asec.ahnlab.com/ko/feed/"
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name.lower() == "scripts" else SCRIPT_DIR
STATE_FILE = common_utils.STATE_DIR / "asec_sent_state.json"
LEGACY_DB_FILE = common_utils.STATE_DIR / "last_url.txt"
MAX_STORED_SENT_IDS = 200
TARGET_EMAIL = common_utils.DEFAULT_TO_EMAIL
# =================================================

def get_all_asec_posts():
    """모든 게시글을 가져오도록 수정"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    try:
        response = requests.get(ASEC_RSS_URL, headers=headers, timeout=10)
        response.raise_for_status()
        
        # RSS(XML) 파싱
        soup = BeautifulSoup(response.text, "xml")
        items = soup.find_all("item") # find가 아닌 find_all 사용
    except Exception as e:
        print(f"[-] ASEC 피드 수집 실패: {e}")
        return []
    return items

def send_email(subject, body):
    """지정된 수신자에게 메일을 발송합니다."""
    return common_utils.send_email_message(subject, body, to_email=TARGET_EMAIL)


def load_state():
    return common_utils.load_json_state(STATE_FILE, lambda: {"sent_ids": []})


def save_state(sent_ids):
    common_utils.save_json_state(STATE_FILE, {"sent_ids": sent_ids}, max_items=MAX_STORED_SENT_IDS, keys_to_trim=["sent_ids"])


def item_link(item):
    link_tag = item.find("link")
    if link_tag is None or not link_tag.text:
        return ""
    return link_tag.text.strip()


def migrate_legacy_state(items, sent_ids):
    """구버전 last_url.txt 상태를 sent_ids 목록으로 이관합니다."""
    if sent_ids or not LEGACY_DB_FILE.exists():
        return sent_ids

    try:
        with LEGACY_DB_FILE.open("r", encoding="utf-8") as f:
            last_url = f.read().strip()
    except OSError:
        return sent_ids

    if not last_url:
        return sent_ids

    links = [item_link(item) for item in items]
    if last_url in links:
        # last_url과 그보다 오래된 글은 이미 발송된 것으로 처리
        migrated = [link for link in links[links.index(last_url):] if link]
    else:
        # last_url이 피드에서 사라진 경우: 피드 전체 재발송을 막기 위해 현재 피드를 발송 완료로 간주
        print("[!] last_url을 피드에서 찾지 못했습니다. 현재 피드 전체를 발송 완료로 간주합니다.")
        migrated = [link for link in links if link]

    print("[*] last_url.txt 상태를 sent_ids {}건으로 이관했습니다.".format(len(migrated)))
    return migrated

def item_text(item, tag):
    found = item.find(tag)
    return found.text.strip() if found is not None and found.text else ""


def item_content_text(item):
    """RSS 항목의 본문 텍스트. 전문(content:encoded)이 있으면 우선, 없으면 description 사용."""
    raw_html = item_text(item, "encoded") or item_text(item, "description")
    if not raw_html:
        return ""
    return common_utils.clean_text(BeautifulSoup(raw_html, "html.parser").get_text(" ", strip=True))


POST_BODY_MAX_CHARS = 20000


def fetch_post_body(url):
    """블로그 글 페이지에서 본문 전체 텍스트를 추출. 실패 시 ""(피드 요약으로 대체).

    ASEC RSS는 짧은 발췌만 제공해 IOC 목록과 상세 분석이 누락되므로 페이지를 직접 수집한다.
    """
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            timeout=15,
        )
        resp.raise_for_status()
    except Exception as error:
        print(f"[-] 본문 페이지 수집 실패({url}): {error}")
        return ""

    soup = BeautifulSoup(resp.text, "html.parser")
    container = (
        soup.find("div", class_="entry-content")
        or soup.find("article")
        or soup.body
    )
    if container is None:
        return ""
    return common_utils.clean_text(container.get_text(" ", strip=True))[:POST_BODY_MAX_CHARS]


def parse_rss_datetime(value):
    if not value:
        return ""
    try:
        return parsedate_to_datetime(value).isoformat()
    except (TypeError, ValueError, IndexError):
        return ""


def send_to_slack(title, link, summary, triage=None):
    """슬랙으로 알림을 전송하는 함수"""
    payload = {
        "text": "🤖 안랩 ASEC 신규 리포트가 게시되었습니다.",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "🤖 *안랩 ASEC 신규 리포트가 게시되었습니다.*" # 이 부분이 채팅창에 보임
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text":
                        f"{common_utils.triage_marker(triage)}*📌 {title}*{common_utils.triage_note(triage)}\n\n"
                        f"{summary}\n\n"
                        f"🔗 <{link}|리포트 바로가기>"
                }
            },
            {
                # 피드백 참조 해시 — 슬랙 폴러가 반응(👍/👎)을 이벤트로 역매핑한다
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": "`ref:{}` · 👍 유용 / 👎 노이즈 반응으로 피드백".format(
                        common_utils.event_ref("asec:{}".format(link))
                    ),
                }],
            }
        ]
    }
    webhook_url = common_utils.pick_webhook(os.environ.get("SLACK_WEBHOOK_ASEC"), [triage])
    return common_utils.send_slack_webhook(payload, webhook_url)

def main():
    print("[*] ASEC 신규 게시글 체크 시작...")

    # 1. 모든 게시글 가져오기
    items = get_all_asec_posts()
    if not items:
        return

    # 2. 발송 이력 로드 (구버전 last_url.txt는 최초 1회 자동 이관)
    state = load_state()
    sent_list = migrate_legacy_state(items, state["sent_ids"])
    sent_ids = set(sent_list)

    # 3. 신규 글 수집 (발송 이력에 없는 글 전부 — 최신 글이 수정/삭제되어도 안전)
    new_posts = []
    for item in items:
        link = item_link(item)
        if not link or link in sent_ids:
            continue
        new_posts.append(item)

    if not new_posts:
        print("[-] 업데이트된 새로운 게시글이 없습니다.")
        if sent_list != state["sent_ids"]:
            save_state(sent_list)
        return

    print(f"[!] {len(new_posts)}개의 신규 게시글 포착")

    # 4. 오래된 순서대로 발송하고, 발송에 성공한 글만 즉시 상태에 반영
    #    (중간에 실패/중단되어도 성공분은 재발송되지 않고 실패분은 다음 실행에서 재시도)
    for post in reversed(new_posts):
        link = item_link(post)
        title = item_text(post, "title") or link

        email_subject = f"[ASEC 인텔리전스 알림] {title}"
        email_body = f"📌 제목: {title}\n🔗 링크: {link}"

        content_text = fetch_post_body(link) or item_content_text(post)
        published_at = parse_rss_datetime(item_text(post, "pubDate"))

        # 리포트 본문에서 CVE·IOC·ATT&CK 기법 추출 후 EPSS(악용 확률)와 연계하여 긴급도 분류 (P1/P2/P3)
        extracted_cves = common_utils.extract_cves(title, content_text)
        iocs = common_utils.extract_iocs(content_text)
        attack_techniques = common_utils.extract_attack_techniques(title, content_text)
        epss_scores = common_utils.fetch_epss_scores(extracted_cves)
        triage = common_utils.classify_urgency(
            [title, content_text],
            epss=max(epss_scores.values()) if epss_scores else None,
        )

        # 크로스소스 클러스터링: 관련 사건 정보를 이벤트에 기록만 한다.
        # ASEC은 1차 리서치 소스라 같은 사건의 뉴스 보도가 먼저 알림됐어도
        # 억제하지 않는다 — 상세 분석·IOC의 가치가 중복 보도와 다르다.
        related = common_utils.find_related_events(extracted_cves, title, exclude_source="asec")
        cluster = common_utils.build_cluster_context(related, triage=triage)
        cluster["suppressed"] = False

        # 알림은 원문 발췌로 즉시 발송 (보안뉴스와 동일 — LLM 대기로 알림을 지연시키지 않는다)
        alert_summary = (item_content_text(post) or content_text)[:300]

        email_sent = send_email(email_subject, email_body)
        slack_sent = send_to_slack(title, link, alert_summary, triage)

        if email_sent or slack_sent:
            sent_list.append(link)
            save_state(sent_list)

            # LLM enrichment는 발송 후 수행 — 알림에는 쓰지 않고 리포트용 이벤트 필드만 채운다
            print(f"AI 분석중: {title}")
            enrichment = common_utils.ai_enrich_article(title, content_text) or {}
            # ASEC은 자체 텔레메트리 기반 1차 리서치 소스 — feeds.json의 벤더 리서치 블로그와 동일 등급
            importance = common_utils.score_importance(
                triage=triage, enrichment=enrichment, cves=extracted_cves, reliability="B",
            )

            # 일간/주간 리포트용 통합 이벤트 로그 적재
            common_utils.append_events(
                [
                    common_utils.make_event(
                        "asec",
                        link,
                        title,
                        url=link,
                        summary=content_text[:500],
                        severity=enrichment.get("severity") or "",
                        cves=extracted_cves,
                        category=enrichment.get("category") or "",
                        category_reason=enrichment.get("category_reason") or "",
                        affected_products=enrichment.get("affected_products"),
                        threat_actor=enrichment.get("threat_actor") or "",
                        malware_family=enrichment.get("malware_family") or "",
                        relevance=enrichment.get("relevance") or "",
                        confidence=enrichment.get("confidence") or "",
                        iocs=iocs,
                        attack_techniques=attack_techniques,
                        pirs=enrichment.get("pirs"),
                        published_at=published_at,
                        ai_summary=enrichment.get("summary"),
                        email_sent=bool(email_sent),
                        slack_sent=bool(slack_sent),
                        triage=triage,
                        importance=importance,
                        cluster=cluster,
                        content_depth=enrichment.get("content_depth") or "",
                        novelty=enrichment.get("novelty") or "",
                        body_chars=len(content_text or ""),
                        recommended_actions=enrichment.get("recommended_actions"),
                        affected_versions=enrichment.get("affected_versions"),
                        fix_available=enrichment.get("fix_available"),
                        remediation=enrichment.get("patch_info") or "",
                    )
                ]
            )
        else:
            print(f"[-] 발송이 모두 실패하여 상태를 저장하지 않습니다: {title}")

if __name__ == "__main__":
    main()
