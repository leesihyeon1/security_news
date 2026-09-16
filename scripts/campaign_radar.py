"""신규 공격 캠페인·기법 탐지 (공격 동향 레이더).

무엇을 푸는가:
    추천기사(pick_trend_reads)는 "알림 문턱을 못 넘었지만 읽을 가치가 있는 기사"를
    뽑는다. 그래서 TerminalFix처럼 새로 등장한 기법·캠페인이 P1/P2로 알림된 경우엔
    애초에 후보군에 들어가지 않는다(실측: 신규 캠페인 구성 기사 60건 중 추천기사와
    겹친 것은 2건, 3%). 완전히 다른 축이라 별도로 뽑아야 한다.

판정 조건 (모두 AND):
    ① 최초 등장이 최근 WINDOW_DAYS 이내      — 처음 보는 이름인가
    ② novelty=new 판정이 MIN_NOVELTY_NEW건 이상 — LLM이 "최초 보도"로 본 기사가 여럿인가
    ③ 서로 다른 소스 MIN_SOURCES곳 이상       — 한 곳만 떠든 게 아닌가
    ④ PIR 매칭 또는 자산 매칭                 — 우리가 알아야 할 축에 걸리는가

    ④에서 자산 매칭만 쓰면 안 된다. 자산 인벤토리는 네트워크·보안 장비뿐이라
    TerminalFix 같은 엔드포인트 사회공학 기법은 구조적으로 못 잡는다(실측: 진짜
    TerminalFix 기사 4건 모두 자산매칭 0건, 매칭이 걸린 1건은 여러 주제를 섞은
    주간 요약 기사의 오탐). PIR-4가 "ClickFix·InstallFix·피싱 등 엔드포인트 초기
    침투"라 그 축을 정확히 담당한다.

이름이 다른 두 카드를 "서로를 언급하는가"로 합치는 방법은 시도했다가 뺐다. 제목·요약에서
상대 이름을 한 번이라도 부르는 그룹 쌍이 0개였다(실측: 병합 직전 21개 그룹). events.jsonl에
본문이 없어 제목·요약만 볼 수 있고, 캠페인 이름은 "ted backdoor"처럼 여러 낱말이라 기사의
"'ted' 백도어" 표기와 문자열이 안 맞는다. 같은 사건이 두 카드로 갈리는 문제는 남아 있지만
이 신호로는 못 잡는다.

두 가지 함정을 피한다:
    - 개체 필드(threat_actor/malware_family)만 믿으면 소스 수가 과소 집계된다.
      실측: TerminalFix는 제목에 실린 기사가 4건인데 필드가 채워진 건 1건뿐이어서
      "단독 보도"로 탈락했다. 이름은 필드에서 얻고, 코로보레이션은 제목·요약의
      이름 언급으로 센다.
    - 주간 요약·뉴스레터 기사는 한 이벤트에 여러 캠페인을 담고(malware_family=
      'StreamRat, TerminalFix') 무관한 자산까지 끌어온다 — 개체 추출에서 제외한다.
"""

import io
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta

import common_utils

WINDOW_DAYS = 14
MIN_SOURCES = 2
MIN_NOVELTY_NEW = 2
MAX_CAMPAIGNS = 8            # 대시보드 카드로 노출할 상한
MIN_NAME_CHARS = 4           # 이보다 짧은 이름은 언급 검색에서 오탐이 크다

SPLIT_RE = re.compile(r"\s*(?:,|/|·|;|\band\b|\bor\b)\s*", re.I)
PAREN_RE = re.compile(r"\(([^)]*)\)")
NOISE_SUFFIX_RE = re.compile(r"\b(operators?|group|gang|actors?|apt|team|crew)\b\s*$", re.I)
ALIAS_RE = re.compile(r"\b(aka|a\.k\.a\.?|alias)\b", re.I)
# 여러 캠페인을 한 기사에 몰아넣는 유형
ROUNDUP_RE = re.compile(
    r"weekly recap|week in security|week in review|newsletter|round\s*\d+|"
    r"threatsday|digest|roundup|주간\s*(요약|보안)|이번\s*주",
    re.I,
)
# LLM이 개체 필드를 채우려고 넣는 일반명사 — 캠페인 이름이 아니다
STOPNAMES = {
    "unknown", "n/a", "none", "various", "unattributed", "unspecified",
    "미확인", "불명", "해당 없음", "다수", "미상", "확인되지 않음",
    "chinese state-sponsored", "state-sponsored", "ransomware", "threat actor",
}


def is_roundup(event):
    return bool(ROUNDUP_RE.search(event.get("title") or ""))


def split_entities(raw):
    """뭉쳐 들어온 개체명을 개별 이름으로 쪼갠다.

    실측 80종이 이런 형태다: "SCATTERED SPIDER, BlackBasta, Royal (BlackSuit)",
    "BlackCat/ALPHV", "Astaroth (Guildma) operators". 괄호 안 별칭도 독립 이름으로 본다.
    """
    if not raw:
        return []
    pieces = []
    for alias in PAREN_RE.findall(raw):
        pieces.extend(SPLIT_RE.split(alias))
    pieces.extend(SPLIT_RE.split(PAREN_RE.sub(" ", raw)))

    names = []
    for piece in pieces:
        name = NOISE_SUFFIX_RE.sub("", ALIAS_RE.sub(" ", piece))
        name = common_utils.clean_text(name).strip(" .-–—'\"")
        if not name or len(name) < MIN_NAME_CHARS or len(name) > 40:
            continue
        if name.lower() in STOPNAMES or not re.search(r"[A-Za-z가-힣]", name):
            continue
        canonical = common_utils.normalize_threat_actor(name)
        if canonical not in names:
            names.append(canonical)
    return names


def _mention_blob(event):
    """이름 언급을 찾을 텍스트. 본문은 events.jsonl에 저장되지 않아 제목·요약만 본다."""
    return " ".join([
        event.get("title") or "",
        event.get("ai_summary") or "",
        event.get("summary") or "",
    ])


def _iter_events(events_file):
    for line in common_utils.iter_lines_reverse(events_file):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not str(event.get("fetched_at") or ""):
            continue
        yield event


KNOWN_NAMES_FILE = common_utils.ASSETS_DIR / "intel" / "known_names.json"
ACTOR_ALIASES_FILE = common_utils.ASSETS_DIR / "intel" / "threat_actor_aliases.json"
_known_cache = None


def known_names():
    """이미 알려진 행위자·랜섬웨어·악성코드 이름 집합(소문자).

    코퍼스가 두 달 남짓이라 "우리가 처음 본 이름"과 "세상에 처음 나온 이름"이 다르다.
    그 차이를 메우는 유일한 근거가 외부 목록이다(MISP Galaxy). 없으면 빈 집합을
    돌려주고 예전처럼 동작한다 — 목록을 못 받았다고 탐지를 멈추지는 않는다.
    """
    global _known_cache
    if _known_cache is not None:
        return _known_cache
    names = set()
    try:
        data = json.loads(KNOWN_NAMES_FILE.read_text(encoding="utf-8"))
        names.update((data.get("names") or {}).keys())
    except (OSError, ValueError):
        pass
    try:
        data = json.loads(ACTOR_ALIASES_FILE.read_text(encoding="utf-8"))
        names.update(key for key in (data.get("aliases") or {}) if len(key) >= MIN_NAME_CHARS)
    except (OSError, ValueError):
        pass
    _known_cache = names
    return names


def unknown_names(names):
    """그룹의 이름 중 외부 목록에 없는 것들. 하나라도 있으면 신규로 본다.

    모든 이름이 알려진 것이면 새 사건이 아니라 알려진 그룹의 새 소식이다. 반대로
    하나라도 처음 보는 이름이 섞여 있으면(알려진 그룹이 쓰는 신종 악성코드 등)
    신규로 남긴다 — 거르는 쪽으로 기울면 진짜 신규를 놓친다.
    """
    known = known_names()
    out = []
    for name in names:
        key = common_utils.clean_text(name).lower()
        # 외부 목록은 정식 명칭을 쓰고 기사는 줄여 쓴다("Lazarus" vs "Lazarus Group").
        # 흔한 꼬리말을 붙여 한 번 더 본다 — 이걸 안 하면 오래된 그룹이 신규로 남는다.
        variants = [key] + [key + suffix for suffix in
                            (" group", " gang", " team", " apt", " crew")]
        if not any(variant in known for variant in variants):
            out.append(name)
    return out


def corpus_start(events_file=None):
    """수집 로그에서 가장 오래된 날짜. "최초 확인"이 무엇을 기준으로 한 말인지 밝히는 데 쓴다.

    이 값이 화면에 없으면 "최초 확인 2026-08-30"이 세계 최초처럼 읽힌다. 실제로는
    우리 수집이 시작된 뒤 처음 본 날이라, 그 전부터 알려진 이름도 신규로 뜬다
    (실측: Rhysida·APT37처럼 오래된 그룹이 신규 캠페인으로 올라왔다).
    """
    path = events_file or common_utils.EVENTS_FILE
    try:
        with io.open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                stamp = (event.get("fetched_at") or "")[:10]
                if stamp:
                    return stamp
    except OSError:
        pass
    return ""


def detect(events_file=None, now=None):
    """신규 캠페인 후보를 반환. 대시보드 카드로 바로 쓸 수 있는 dict 목록."""
    events_file = events_file or common_utils.EVENTS_FILE
    now = now or datetime.utcnow()
    window_start = (now - timedelta(days=WINDOW_DAYS)).isoformat()

    # 최초 등장일을 알아야 하므로 코퍼스 전체를 본다(끝에서부터 읽되 조기 종료는 없다).
    events = [event for event in _iter_events(events_file) if not is_roundup(event)]

    names = {}
    for event in events:
        if str(event.get("fetched_at")) < window_start:
            continue  # 후보 이름은 최근 창에서만 얻는다
        for field in ("threat_actor", "malware_family"):
            for name in split_entities(event.get(field)):
                names.setdefault(name.lower(), name)
    if not names:
        return []

    matchers = {
        key: re.compile(r"(?<![0-9A-Za-z])" + re.escape(display) + r"(?![0-9A-Za-z])", re.I)
        for key, display in names.items()
    }

    first_seen = {}
    hits = defaultdict(list)
    for event in events:
        blob = _mention_blob(event)
        fetched = str(event.get("fetched_at"))
        for key, pattern in matchers.items():
            if not pattern.search(blob):
                continue
            if key not in first_seen or fetched < first_seen[key]:
                first_seen[key] = fetched
            if fetched >= window_start:
                hits[key].append(event)

    candidates = {}
    for key, matched in hits.items():
        if first_seen.get(key, "") < window_start:
            continue                                            # ①
        if sum(1 for e in matched if (e.get("novelty") or "") == "new") < MIN_NOVELTY_NEW:
            continue                                            # ②
        if len({e.get("source") or "?" for e in matched}) < MIN_SOURCES:
            continue                                            # ③
        candidates[key] = {"name": names[key], "events": matched, "first": first_seen[key][:10]}

    return _build_rows(_merge_by_story(candidates))


def _merge_by_story(candidates):
    """같은 기사에서 나온 개체들을 한 캠페인으로 합친다.

    개체명 단위로 두면 한 사건이 여러 줄로 쪼개진다 — 실측: QTFY/QScan/QTRouter,
    Gambling Goblin/DownPro/AlphaAgent/oRAT/3snake가 각각 같은 보고서에서 나왔다.
    """
    parent = {key: key for key in candidates}

    def find(node):
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    by_event = defaultdict(list)
    for key, info in candidates.items():
        for event in info["events"]:
            by_event[event.get("id")].append(key)
    for keys in by_event.values():
        root = find(keys[0])
        for other in keys[1:]:
            parent[find(other)] = root

    groups = defaultdict(lambda: {"names": [], "events": {}, "first": "9999"})
    for key, info in candidates.items():
        group = groups[find(key)]
        if info["name"] not in group["names"]:
            group["names"].append(info["name"])
        for event in info["events"]:
            group["events"][event.get("id")] = event
        group["first"] = min(group["first"], info["first"])
    return list(groups.values())


def _build_rows(groups):
    level_rank = {"P1": 0, "P2": 1}
    rows = []
    for group in groups:
        events = list(group["events"].values())
        pirs = sorted({p for e in events for p in (e.get("pirs") or [])})
        assets = common_utils.canonical_assets(
            [a for e in events for a in ((e.get("triage") or {}).get("matched_assets") or [])])
        if not pirs and not assets:
            continue                                            # ④
        levels = sorted({(e.get("triage") or {}).get("level") for e in events} - {None, ""})
        # 요약은 "캠페인 이름이 제목에 있는 기사"에서 가져온다. 아무거나 집으면 그
        # 캠페인을 지나가듯 언급한 기사(주간 위협 보고서 등)의 요약이 실려 엉뚱한
        # 내용이 카드에 나온다 — 실측: Gambling Goblin 카드에 Thomson Reuters
        # 유출 사고 요약이 붙었다.
        name_res = [re.compile(r"(?<![0-9A-Za-z])" + re.escape(n) + r"(?![0-9A-Za-z])", re.I)
                    for n in group["names"]]

        def summary_rank(event):
            title = event.get("title") or ""
            in_title = any(pattern.search(title) for pattern in name_res)
            return (0 if in_title else 1, 0 if event.get("ai_summary") else 1)

        # 같은 순서로 items도 정렬해 대표 기사가 맨 앞에 오게 한다 — 대시보드 카드가
        # items[0]을 "이 캠페인의 대표 기사"로 보고 심층분석 버튼을 붙인다.
        ordered = sorted(events, key=summary_rank)
        summary = ""
        for event in ordered:
            summary = (event.get("ai_summary") or event.get("summary") or "").strip()
            if summary:
                break
        rows.append({
            "names": group["names"][:6],
            "first_seen": group["first"],
            "level": min(levels, key=lambda l: level_rank.get(l, 2)) if levels else "",
            "sources": sorted({common_utils.source_label(e.get("source")) for e in events}),
            "pirs": pirs,
            "assets": assets,
            "categories": sorted({e.get("category") for e in events if e.get("category")}),
            "techniques": sorted({t for e in events for t in (e.get("attack_techniques") or [])}),
            "ioc_count": sum(len(e.get("iocs") or []) for e in events),
            "novelty_new": sum(1 for e in events if (e.get("novelty") or "") == "new"),
            "summary": summary[:400],
            "items": [
                {
                    "source_label": common_utils.source_label(e.get("source")),
                    "category": e.get("category") or "",
                    "title": e.get("title") or "",
                    "url": common_utils.tracking_url(e.get("id"), e.get("url") or "") or "",
                    "ref": common_utils.event_ref(e.get("id")),
                }
                for e in ordered
            ],
        })

    # 외부 목록에 이미 있는 이름만으로 이뤄진 것은 신규가 아니다. 몇 건을 왜 뺐는지
    # 남긴다 — 조용히 빠지면 탐지가 안 된 것과 구별되지 않는다.
    fresh, dropped = [], []
    for row in rows:
        new_names = unknown_names(row["names"])
        if new_names:
            row["new_names"] = new_names
            fresh.append(row)
        else:
            dropped.append(row["names"][0] if row["names"] else "?")
    if dropped:
        print("[*] 이미 알려진 이름이라 신규에서 제외: {}".format(", ".join(dropped)))
    rows = fresh

    rows.sort(key=lambda r: (level_rank.get(r["level"], 2), -len(r["sources"]), -len(r["items"])))
    rows = rows[:MAX_CAMPAIGNS]
    # 화면이 "최초 확인"의 기준을 밝힐 수 있게 코퍼스 시작일을 함께 싣는다.
    started = corpus_start()
    for row in rows:
        row["corpus_start"] = started
    return rows


# 새로 뜬 캠페인은 사람이 누르기를 기다리지 않고 바로 심층분석에 건다.
#
# 왜 자동인가
#     공격 동향에 오르는 것은 이미 "최근 14일 안에 처음 등장했고, 서로 다른 매체
#     두 곳 이상이 다뤘고, 우리 PIR이나 자산에 걸린" 것만 남은 목록이다. 거기까지
#     통과한 건을 놓고 다시 사람의 클릭을 기다릴 이유가 없다.
#
# 한 번만 건다
#     캠페인은 창 안에 있는 동안 매일 같은 카드로 다시 나온다(14일). 그때마다 큐에
#     넣으면 같은 기사를 열네 번 분석한다. 이름 집합을 상태 파일에 적어 두고, 이미
#     건 것은 건너뛴다. 분석 결과가 이미 캐시에 있는 경우도 건너뛴다 — 사람이 먼저
#     눌러서 분석된 건이 그렇다.
ANALYSIS_QUEUE_KEY = "analysis:queue"
ANALYSIS_CACHE_PREFIX = "analysis:"
QUEUE_STATE_FILE = common_utils.STATE_DIR / "campaign_analysis_state.json"
# 한 회차에 거는 최대 건수. 워커가 한 건에 2~3분을 쓰므로 한꺼번에 밀어 넣으면
# 그날 대기열이 다른 요청으로 막힌다.
MAX_QUEUED_PER_RUN = 3


def _queue_client():
    """Redis 클라이언트. 없으면 None — 큐잉은 부가 기능이라 리포트를 막지 않는다."""
    url = os.environ.get("REDIS_URL", "")
    if not url:
        return None
    try:
        import redis
    except ImportError:
        return None
    try:
        client = redis.from_url(url, decode_responses=True,
                                socket_connect_timeout=10, socket_timeout=15)
        client.ping()
        return client
    except Exception as error:
        print("[-] 심층분석 큐 연결 실패(리포트에는 영향 없음): {}".format(error))
        return None


def campaign_key(row):
    """같은 캠페인인지 가리는 열쇠. 이름 집합이 같으면 같은 것으로 본다."""
    return "|".join(sorted(name.lower() for name in (row.get("names") or [])))


def queue_deep_analysis(rows):
    """새로 뜬 캠페인의 대표 기사를 심층분석 큐에 넣는다. 넣은 건수를 돌려준다."""
    rows = [row for row in rows or [] if row.get("items")]
    if not rows:
        return 0
    client = _queue_client()
    if client is None:
        return 0
    state = common_utils.load_json_state(QUEUE_STATE_FILE, lambda: {"queued": []})
    already = set(state.get("queued") or [])

    queued = 0
    for row in rows:
        if queued >= MAX_QUEUED_PER_RUN:
            break
        key = campaign_key(row)
        if not key or key in already:
            continue
        # items[0]은 캠페인 이름이 제목에 있는 기사다(_build_rows에서 그렇게 정렬했다).
        item = row["items"][0]
        ref = item.get("ref") or ""
        if not ref or not item.get("url"):
            continue
        try:
            if client.exists(ANALYSIS_CACHE_PREFIX + ref):
                already.add(key)          # 이미 분석된 건 — 다시 걸지 않는다
                continue
            client.rpush(ANALYSIS_QUEUE_KEY, json.dumps(
                {"ref": ref, "title": item.get("title") or "", "url": item["url"]},
                ensure_ascii=False))
        except Exception as error:
            print("[-] 심층분석 큐 등록 실패({}): {}".format(row["names"][0][:24], error))
            continue
        already.add(key)
        queued += 1
        print("[+] 신규 캠페인 심층분석 큐 등록: {} — {}".format(
            " / ".join(row["names"][:2]), (item.get("title") or "")[:52]))

    if already != set(state.get("queued") or []):
        common_utils.save_json_state(QUEUE_STATE_FILE, {"queued": sorted(already)},
                                     max_items=500, keys_to_trim=["queued"])
    return queued


if __name__ == "__main__":
    import sys

    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    found = detect()
    print("신규 공격 캠페인 {}건 (창 {}일 / 소스 {}곳 이상 / new판정 {}건 이상 / PIR 또는 자산매칭)".format(
        len(found), WINDOW_DAYS, MIN_SOURCES, MIN_NOVELTY_NEW))
    for row in found:
        print()
        print("● {}  [{}]".format(" / ".join(row["names"]), row["level"] or "-"))
        print("   최초 {} | 소스 {}곳 | new판정 {}건 | IOC {}건".format(
            row["first_seen"], len(row["sources"]), row["novelty_new"], row["ioc_count"]))
        if row["pirs"]:
            print("   PIR {}".format(", ".join(row["pirs"])))
        if row["assets"]:
            print("   자산 {}".format(", ".join(row["assets"])))
        print("   {}".format(row["summary"][:120]))
