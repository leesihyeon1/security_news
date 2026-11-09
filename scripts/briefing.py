# -*- coding: utf-8 -*-
"""정보성 기사(정책·규제, 사업 발표, 기술 동향)의 심층분석 — 공격 조사 대신 배경 정리.

무엇이 잘못돼 있었나
    공격 사건이 아닌 기사도 공격 조사 파이프라인을 그대로 탔다. 실측(2026-09-30,
    "LG U+, IBCT와 국내 기업 유럽 공급망 규제 대응… 카테나-X 지원"): 제목의 "공급망"
    한 단어로 패키지 레지스트리 축이 섰고, 참여 기업 이름을 (malware OR APT …)로 감싼
    검색이 APT IOC 모음 저장소를 "기사가 인용한 1차 자료"로 읽었으며, 정상 기업
    도메인을 urlscan으로 조회하고 한글 브랜드명으로 명령줄을 뒤지는 KQL을 만들었다.
    판단은 "미확인", 선언한 성공기준(헌팅 쿼리·단말 명령·차단 목록)은 모두 "미달"이었다.
    targets.investigable=False가 있었지만 트랙이 0개일 때만 읽혀서 아무것도 막지 못했다.

무엇을 하나
    공격 조회(IOC·취약점·패키지 조회, 패턴 합성, 후속 조회, 과거 분석 연결)를 하나도
    돌리지 않는다. 대신 기사 주제의 개념 설명(위키백과)과 공식 문서·해설(보안 문맥 없는
    웹 검색)을 찾아 읽고, 기술 정보 담당자 관점의 정리(response_synth.synthesize_briefing)를
    받는다. 결과 블록은 공격 조사 블록과 같은 키를 쓴다 — 대시보드는 코드 변경 없이
    판단→조사→대응 흐름을 그대로 그린다(route.label·explain, 조사 결과·결론, 영향 확인,
    할 일, 읽은 자료 카드).

무엇을 하지 않나
    예외를 밖으로 던지지 않는다. 외부 단계 하나가 실패해도 나머지로 블록을 만들고, 실패는
    lookup_status와 조사 과정에 남긴다. 판단이 실패해도 블록은 돌려준다 — None을 주면
    워커가 조사&대응 카드를 통째로 비우고, 판단이 빈 블록은 synthesis_status로 표시돼
    resynthesize가 다시 채울 수 있다.
"""

import re
import analysis_trace
import urllib.parse

import analyst_workflow
import common_utils
import playbook
import primary_sources
import response_synth
import source_evidence
import web_search

INFORMATIONAL = "informational"
# 배경 조사 주제 수. 위키백과·웹 검색 모두 주제당 호출이 나가고, 웹 검색은 하루 한도를
# 공격 기사와 같이 쓴다 — 기사 하나가 한도를 다 쓰지 않게 묶는다.
MAX_SUBJECTS = 3
# [더 알아보기]와 reading_list 항목 수. 더 많으면 분석 카드가 자료 목록으로 채워진다.
MAX_READING = 5
# 검색으로 찾은 참고 원문을 직접 읽는 수. 기사가 인용한 원문(primary_sources 기본 2건)
# 다음 순서다.
MAX_SEARCH_SOURCES = 2
# 판단 재료 상한 — 원문 한 건이 프롬프트를 채우지 않게 조각마다 자른다.
MATERIAL_SUMMARY_CHARS = 1200
MATERIAL_SOURCE_CHARS = 3500
MAX_MATERIAL_CHARS = 12000
FINDING_CHARS = 150

DEFAULT_SUBTYPE = "일반"
DEFAULT_REASON = "공격 사건·취약점·악성코드 지표가 없어 정보성 기사로 판단했습니다."
# 판단 탭 "선정 근거"에 그대로 나간다(app.js route.explain). 왜 탐지 산출물이 없는지를
# 여기서 밝히지 않으면 빈 대응 탭이 "기능이 고장났다"로 읽힌다.
EXPLAIN_TAIL = (" 공격 사건이 아니어서 IOC·취약점·패키지 조회와 탐지 쿼리는 만들지 않고, "
                "기사 주제의 배경 자료와 공식 문서를 찾아 정리했습니다.")
# 판단 재료와 자료 목록에 붙일 출처 이름표. "기사가 인용한"과 "검색으로 찾은"을 섞으면
# 실측(카테나-X)처럼 검색 결과가 기사 인용 1차 자료로 둔갑한다.
ORIGIN_LABELS = {"article": "기사가 인용한 원문", "search": "검색으로 찾은 참고 원문(기사 미인용)",
                 "reference": "참고 자료"}
ORIGIN_NOTES = {"article": "기사가 인용한 원문", "search": "검색으로 찾은 참고 원문",
                "reference": "참고 자료"}

# analysis_worker.GLOSSARY_SECTION_RE와 같은 경계 — [선수 정보]는 다음 "[" 줄에서 끝난다.
GLOSSARY_SECTION_RE = re.compile(r"\[\s*선수\s*정보\s*\]\s*\n(.*?)(?=\n\s*\[|\Z)", re.S)
GLOSSARY_TERM_RE = re.compile(r"^\s*(?:[-•*]|\d+[.)])?\s*([^:：\n]{2,40}?)\s*[:：]", re.M)
# 괄호 안의 로마자 병기. 위키백과·웹 검색은 원문 표기로 찾아야 맞는 항목이 걸린다
# ("카테나-X"로는 없고 "Catena-X"로는 있다).
LATIN_ALIAS_RE = re.compile(r"[(（]\s*([^()（）]*[A-Za-z][^()（）]*?)\s*[)）]")
PAREN_RE = re.compile(r"[(（][^()（）]*[)）]")
PLACEHOLDER_RE = re.compile(r"^(?:없음|해당\s*없음|미상|미확인|n/?a|none)$", re.I)


def log(message):
    print(message)


def _now():
    return common_utils.utc_now_iso()


def _one_line(value):
    return " ".join(str(value or "").split())


def _bare(host):
    # str.lstrip("www.")는 접두어가 아니라 문자 집합을 지운다(www.wired.com → ired.com).
    host = _one_line(host).lower()
    return host[4:] if host.startswith("www.") else host


def _host(url):
    try:
        return _bare(urllib.parse.urlparse(str(url or "")).netloc)
    except Exception:
        return ""


# ── 조사 주제 ────────────────────────────────────────────────────────────────

def _has_latin(term):
    """로마자 표기가 있어 검색에 바로 쓸 수 있는가 — 괄호 병기이거나 로마자 이름 자체."""
    term = term or ""
    if LATIN_ALIAS_RE.search(term):
        return True
    return bool(re.search(r"[A-Za-z]{2,}", term)) and not re.search(r"[가-힣]", term)


def _norm_key(value):
    return re.sub(r"[\s\-_.·]", "", (value or "").lower())


def _keys(term):
    """같은 대상을 가리키는지 볼 열쇠 — 괄호 밖 이름과 괄호 안 병기를 따로 센다."""
    keys = {_norm_key(PAREN_RE.sub("", term))}
    for alias in LATIN_ALIAS_RE.findall(term):
        keys.add(_norm_key(alias))
    return {key for key in keys if key}


def _clean_term(raw):
    term = _one_line(raw).strip(" -•*·,.;:")
    if len(term) < 2 or len(term) > 60 or PLACEHOLDER_RE.match(term):
        return ""
    return term


def _with_alias(term, haystack):
    """본문에 "카테나-X(Catena-X)"처럼 병기가 있으면 붙인다. 없으면 그대로."""
    if _has_latin(term):
        return term
    match = re.search(re.escape(term) + r"\s*[(（]\s*([A-Za-z][^()（）\n]{0,40}?)\s*[)）]",
                      haystack or "")
    return "{}({})".format(term, match.group(1).strip()) if match else term


def _glossary_terms(text):
    match = GLOSSARY_SECTION_RE.search(text or "")
    if not match:
        return []
    return [term.strip() for term in GLOSSARY_TERM_RE.findall(match.group(1))]


def subjects(targets, text="", body=""):
    """배경 자료를 찾을 주제 — topics → [선수 정보] 용어 → 제품 순, 최대 MAX_SUBJECTS개.

    topics는 분석 단계가 "배경 자료를 찾을 표준·제도·기술 이름"으로 따로 뽑은 것이라
    맨 앞이다. 없으면(옛 레코드) [선수 정보]의 용어를, 그것도 없으면 제품 이름을 쓴다.
    행위자는 쓰지 않는다 — 실측(카테나-X): 협력사·완성차 회사 이름이 행위자 칸에 들어가
    있었고, 그 이름을 검색하면 회사 소개와 무관한 기사만 걸린다.

    같은 대상은 하나로 합치되 로마자 병기가 있는 쪽을 남기고, 같은 층에서는 병기가 있는
    것을 먼저 둔다 — 한글 표기만으로는 위키백과·검색이 맞는 항목을 못 찾는다.
    """
    targets = targets if isinstance(targets, dict) else {}
    haystack = "{}\n{}".format(text or "", body or "")
    tiers = (list(targets.get("topics") or []), _glossary_terms(text),
             list(targets.get("products") or []))
    picked = []
    for tier, values in enumerate(tiers):
        for raw in values:
            term = _clean_term(raw)
            if not term:
                continue
            term = _with_alias(term, haystack)
            keys = _keys(term)
            duplicate = next((index for index, item in enumerate(picked) if item[2] & keys), None)
            if duplicate is not None:
                old_tier, old_term, old_keys = picked[duplicate]
                if _has_latin(term) and not _has_latin(old_term):
                    picked[duplicate] = (old_tier, term, old_keys | keys)
                continue
            picked.append((tier, term, keys))
    picked.sort(key=lambda item: (item[0], 0 if _has_latin(item[1]) else 1))
    return [term for _, term, _ in picked[:MAX_SUBJECTS]]


# ── 조회 상태 ────────────────────────────────────────────────────────────────

def _start(block, key):
    entry = {"key": key, "started_at": _now()}
    block["lookup_status"].append(entry)
    return entry


def _finish(entry, status, detail):
    entry.update(status=status, detail=detail, completed_at=_now())


def _lookup_background(topics, block, steps):
    """위키백과 요약. 정확히 맞는 항목만 쓴다(reference_lookup이 거른다)."""
    status = _start(block, "reference")
    if not topics:
        _finish(status, "unavailable", "배경 조사할 주제어 없음")
        return []
    try:
        import reference_lookup
        found = [item for item in reference_lookup.lookup_many(topics) or []
                 if isinstance(item, dict) and item.get("url")]
    except Exception as error:
        _finish(status, "failed", "위키백과 조회 예외: " + type(error).__name__)
        steps.append({"track": "배경 자료",
                      "text": "위키백과 조회 실패({}) — 배경 정리는 기사와 검색 자료로만 합니다."
                              .format(str(error)[:70])})
        return []
    if not found:
        _finish(status, "unavailable", "맞는 위키백과 항목 없음; 개념이 없다는 뜻은 아님")
        steps.append({"track": "배경 자료",
                      "text": "위키백과에서 {}와 정확히 맞는 항목을 찾지 못했습니다 — 이름만 "
                              "비슷한 다른 항목은 쓰지 않습니다.".format(", ".join(topics))})
        return []
    _finish(status, "returned", "위키백과 요약 {}건".format(len(found)))
    for item in found:
        steps.append({"track": "배경 자료",
                      "text": "\"{}\" — 위키백과({}) \"{}\" 항목 요약을 배경 설명으로 씁니다.".format(
                          item.get("term") or item.get("title") or "", _host(item.get("url")),
                          item.get("title") or "")})
    return found


def _search_web(topics, block, steps):
    """보안 문맥 없이 주제 이름으로 공식 문서·해설을 찾는다(web_search.background)."""
    status = _start(block, "web")
    if not topics:
        _finish(status, "unavailable", "검색할 주제어 없음")
        steps.append({"track": "연구 자료 검색", "text": "검색할 주제어가 없어 웹 검색은 건너뛰었습니다."})
        return None
    try:
        result = web_search.background(topics)
    except Exception as error:
        _finish(status, "failed", "웹 검색 예외: " + type(error).__name__)
        steps.append({"track": "연구 자료 검색",
                      "text": "웹 검색 실패({}) — 공식 문서 검색 결과는 비어 있습니다.".format(
                          str(error)[:70])})
        return None
    if not result:
        _finish(status, "unavailable", "검색 키 없음·하루 한도 소진; 자료가 없다는 뜻은 아님")
        steps.append({"track": "연구 자료 검색",
                      "text": "웹 검색을 쓸 수 없어(검색 키 없음·하루 한도) 공식 문서 검색은 "
                              "건너뛰었습니다."})
        return None
    results = [row for row in result.get("results") or [] if isinstance(row, dict) and row.get("url")]
    _finish(status, "returned", "검색어가 제목·요약에 들어간 자료 {}건".format(len(results)))
    steps.extend({"track": "연구 자료 검색", "text": line} for line in result.get("steps") or [])
    return result


def _collect(links, article_url, limit, origin, block, steps):
    """primary_sources.collect 한 번. 실패는 lookup_status(primary)와 과정에 남긴다."""
    try:
        got = primary_sources.collect(links, article_url=article_url, limit=limit,
                                      origin=origin) or {}
    except Exception as error:
        block["lookup_status"].append({"key": "primary", "status": "failed",
                                       "detail": "원문 수집 예외: " + type(error).__name__,
                                       "completed_at": _now()})
        steps.append({"track": "원문 확인", "text": "{} 확인 실패: {}".format(
            ORIGIN_NOTES.get(origin, "원문"), str(error)[:70])})
        return []
    attempts = got.get("attempts") or []
    block["lookup_status"].extend(attempts)
    if origin == "search" and not attempts:
        # 고를 링크가 하나도 없을 때 collect가 남기는 문장은 "기사가 인용한 1차 자료가
        # 없어…"라서 검색 결과에는 맞지 않는다.
        steps.append({"track": "원문 확인",
                      "text": "검색 결과 중 직접 읽을 만한 참고 원문이 없었습니다(뉴스 매체·"
                              "목록 페이지 제외)."})
    else:
        steps.extend({"track": "원문 확인", "text": line} for line in got.get("steps") or [])
    return [dict(source, origin=source.get("origin") or origin)
            for source in got.get("sources") or [] if isinstance(source, dict) and source.get("url")]


def _read_sources(links, article_url, results, block, steps):
    """기사가 인용한 비뉴스 링크 먼저, 그다음 검색으로 찾은 관련 자료 상위 2건."""
    sources = []
    if links:
        sources.extend(_collect(links, article_url, primary_sources.MAX_SOURCES, "article",
                                block, steps))
    read = {source["url"] for source in sources}
    candidates = [{"url": row["url"]} for row in results if row.get("url") not in read]
    if candidates:
        sources.extend(_collect(candidates, article_url, MAX_SEARCH_SOURCES, "search",
                                block, steps))
    if not any(entry.get("key") == "primary" for entry in block["lookup_status"]):
        block["lookup_status"].append({"key": "primary", "status": "unavailable",
                                       "detail": "읽을 원문 링크 없음(기사 링크가 뉴스·목록 페이지뿐)",
                                       "completed_at": _now()})
    return sources


# ── 자료 목록·판단 재료 ──────────────────────────────────────────────────────

def _reading_list(background, sources, results):
    """[{title, url, host, note}] — 위키백과, 읽은 원문, 검색 결과 순으로 최대 5건.

    note는 우리말 이름표만 쓴다. 검색 요약(대개 영어)을 넣으면 분석 본문에 붙는
    [더 알아보기] 카드가 외국어 문장으로 채워진다.
    """
    rows, seen = [], set()

    def add(title, url, host, note):
        if not url or url in seen or len(rows) >= MAX_READING:
            return
        seen.add(url)
        host = host or _host(url)
        rows.append({"title": _one_line(title)[:120] or host, "url": url, "host": host,
                     "note": _one_line(note)[:80]})

    for item in background or []:
        add(item.get("title"), item.get("url"), _host(item.get("url")), "용어·배경 설명(위키백과)")
    titles = {row.get("url"): row.get("title") for row in results or []}
    for source in sources or []:
        chars = source.get("chars") or 0
        add(titles.get(source.get("url")) or source.get("host"), source.get("url"),
            source.get("host") or _host(source.get("url")),
            "{} · {:,}자 읽음".format(ORIGIN_NOTES.get(source.get("origin"), "참고 원문"), chars)
            if chars else ORIGIN_NOTES.get(source.get("origin"), "참고 원문"))
    for row in results or []:
        term = _one_line(row.get("term"))
        add(row.get("title"), row.get("url"), row.get("host") or _host(row.get("url")),
            "\"{}\" 검색으로 찾은 참고 자료".format(term) if term else "검색으로 찾은 참고 자료")
    return rows


def materials(block, sources=()):
    """synthesize_briefing에 넘길 재료 — 위키백과 요약, 검색 요약, 읽은 원문 발췌.

    조각마다 출처 호스트를 붙인다. 판단이 "(출처: 호스트)"로 사실을 밝히고, 근거 대조
    코퍼스에도 그 호스트가 들어 있어야 지어낸 출처가 걸러진다. 짧은 요약을 앞에 둔다 —
    긴 원문이 먼저 오면 상한에서 요약이 잘린다.
    """
    block = block or {}
    head, pages = [], []
    for item in block.get("background") or []:
        head.append("[용어·배경 — {}] {}: {}".format(
            _host(item.get("url")) or "wikipedia.org", _one_line(item.get("title")),
            _one_line(item.get("summary"))[:MATERIAL_SUMMARY_CHARS]))
    for row in (block.get("web") or {}).get("results") or []:
        if not isinstance(row, dict):
            continue
        head.append("[검색 요약 — {}] {} — {}".format(
            row.get("host") or _host(row.get("url")), _one_line(row.get("title")),
            _one_line(row.get("snippet"))[:300]))
    for source in sources or []:
        text = str(source.get("text") or "").strip()
        if not text:
            continue
        pages.append("[{} — {}]\n{}".format(
            ORIGIN_LABELS.get(source.get("origin"), "참고 원문"),
            source.get("host") or _host(source.get("url")), text[:MATERIAL_SOURCE_CHARS]))
    return "\n\n".join(head + pages)[:MAX_MATERIAL_CHARS]


def apply_verdict(block, verdict, targets, steps=None):
    """정리 결과를 블록에 붙인다 — build와 resynthesize가 같은 모양을 쓰게.

    followups는 비운다. 정보성 기사에는 후속 조회(urlscan·레지스트리)가 없어야 한다 —
    실측(카테나-X): 판단이 요청한 후속 조회가 정상 기업 도메인을 urlscan으로 조회했다.
    """
    import investigation    # investigation이 이 모듈을 import하므로 여기서 부른다

    targets = targets if isinstance(targets, dict) else {}
    steps = block.setdefault("steps", []) if steps is None else steps
    verdict["followups"] = []
    ledger = {question: "open" for question in targets.get("questions") or []}
    for row in verdict.get("question_status") or []:
        if isinstance(row, dict) and row.get("question") in ledger:
            ledger[row["question"]] = row.get("status") or ledger[row["question"]]
    block["synthesis"] = verdict
    block["synthesis_status"] = {"status": "completed"}
    if ledger:
        block["questions"] = [{"question": q, "status": status} for q, status in ledger.items()]
    block["action_plan"] = investigation.merge_actions(verdict, None)
    steps.extend({"track": "종합 판단", "text": line} for line in verdict.get("steps") or [])


# ── 블록 ─────────────────────────────────────────────────────────────────────

@analysis_trace.step("정보성 기사 배경·자료 조사", "lookup", inputs=("title", "body", "targets", "links"))
def build(iocs, text="", title="", category="", body="", targets=None, links=None,
          article_url="", synthesize=True):
    """정보성 기사의 조사&대응 블록. 절대 예외를 던지지 않고 None도 돌려주지 않는다.

    iocs·category는 investigation.build와 시그니처를 맞추려고 받는다 — 공격 지표는 조회하지
    않는다(article_kind가 지표가 있는 기사를 여기로 보내지 않는다).
    """
    targets = dict(targets) if isinstance(targets, dict) else {}
    try:
        article_url = source_evidence.article_url(article_url)
    except Exception:
        article_url = str(article_url or "")
    subtype = _one_line(targets.get("article_subtype")) or DEFAULT_SUBTYPE
    reason = _one_line(targets.get("article_kind_reason")) or DEFAULT_REASON
    if not reason.endswith("."):
        reason += "."     # 뒤에 EXPLAIN_TAIL 문장이 이어 붙는다
    steps = []
    block = {
        "article_kind": INFORMATIONAL,
        "route": {"primary": "", "label": "정보성 기사 — " + subtype,
                  "explain": reason + EXPLAIN_TAIL, "tracks": [], "scores": {}},
        "source_urls": [article_url] if article_url else [],
        "targets": targets,
        "indicator_assessments": [],
        "seeds": [],
        "findings": [],
        "patterns": [],
        "response": None,
        "lookup_status": [],
        "steps": steps,
        "generated_at": _now(),
    }

    topics = []
    try:
        topics = subjects(targets, text, body)
    except Exception as error:
        steps.append({"track": "배경 자료", "text": "주제어 추출 실패: {}".format(str(error)[:70])})
    steps.append({"track": "분석 방향",
                  "text": "정보성 기사({}) — {} 공격 조사 경로(조회 계획·패턴 합성·후속 조회)는 "
                          "타지 않습니다.".format(subtype, reason)})
    # "조회 계획" + "·"로 시작하는 줄은 판단 탭 "이 조회를 고른 이유"에 그대로 나간다.
    steps.append({"track": "조회 계획",
                  "text": "· 조회할 공격 지표(도메인·해시·CVE·패키지)가 없는 기사라 urlscan·"
                          "VirusTotal·취약점·레지스트리 조회와 탐지 쿼리 생성은 고르지 않았습니다."})
    steps.append({"track": "조회 계획",
                  "text": "· 기사 주제({})의 개념 설명과 공식 문서·해설 자료를 찾아 읽습니다.".format(
                      ", ".join(topics)) if topics else
                  "· 배경 자료를 찾을 주제어가 없어 기사 원문과 분석만으로 정리합니다."})
    subject_note = ", ".join(topics) or "기사 주제"
    block["question_lookups"] = [
        {"question": question, "lookups": [
            {"key": "web", "why": "{}의 공식 문서·해설을 보안 문맥 없이 검색해 답의 근거를 "
                                  "찾습니다".format(subject_note)},
            {"key": "primary", "why": "기사가 인용한 원문과 검색으로 찾은 참고 원문을 직접 "
                                      "읽어 확인합니다"}]}
        for question in targets.get("questions") or [] if str(question or "").strip()]

    background = _lookup_background(topics, block, steps)
    if background:
        block["background"] = background
    web = _search_web(topics, block, steps)
    results = [row for row in (web or {}).get("results") or []
               if isinstance(row, dict) and row.get("url")]

    # 연구 자료 검색 관측 그룹(web.findings)과 읽은 자료 카드(web.references)는 기존
    # 화면 자리다. 위키백과 요약도 여기 실어야 조사 결과에 보인다.
    web_block = dict(web) if web else None
    if background:
        if web_block is None:
            web_block = {"findings": [], "references": [], "results": [], "terms": [], "steps": []}
        web_block["findings"] = list(web_block.get("findings") or []) + [
            "· {} — {}".format(_host(item.get("url")) or "wikipedia.org",
                               _one_line(item.get("summary"))[:FINDING_CHARS])
            for item in background if _one_line(item.get("summary"))]
        web_block["references"] = list(dict.fromkeys(
            list(web_block.get("references") or []) + [item["url"] for item in background]))
    if web_block:
        block["web"] = web_block

    sources = []
    try:
        sources = _read_sources(links, article_url, results, block, steps)
    except Exception as error:
        block["lookup_status"].append({"key": "primary", "status": "failed",
                                       "detail": "원문 수집 예외: " + type(error).__name__,
                                       "completed_at": _now()})
        steps.append({"track": "원문 확인", "text": "실패: {}".format(str(error)[:70])})
    if sources:
        block["primary"] = {"sources": [
            {"url": source.get("url") or "", "host": source.get("host") or _host(source.get("url")),
             "chars": source.get("chars") or 0, "retrieved_at": source.get("retrieved_at") or "",
             "origin": source.get("origin") or ""}
            for source in sources]}
        block["source_urls"] = list(dict.fromkeys(
            block["source_urls"] + [source["url"] for source in sources]))
    try:
        reading = _reading_list(background, sources, results)
    except Exception as error:
        reading = []
        steps.append({"track": "원문 확인", "text": "참고 자료 목록 실패: {}".format(str(error)[:70])})
    if reading:
        block["reading_list"] = reading
    if any(entry.get("status") == "returned" for entry in block["lookup_status"]):
        block["route"]["tracks"] = ["web"]

    if synthesize:
        verdict = None
        try:
            verdict = response_synth.synthesize_briefing(
                title, text, targets, block, article=body, materials=materials(block, sources))
        except Exception as error:
            steps.append({"track": "종합 판단", "text": "실패: {}".format(str(error)[:90])})
            block["synthesis_status"] = {"status": "failed", "retryable": True}
        if verdict:
            try:
                apply_verdict(block, verdict, targets, steps)
            except Exception as error:
                steps.append({"track": "종합 판단", "text": "정리 반영 실패: {}".format(str(error)[:90])})
        elif "synthesis_status" not in block:
            steps.append({"track": "종합 판단",
                          "text": "정리 생성 실패: 모델 응답 없음·형식 오류·근거 검증 탈락. 찾은 자료는 "
                                  "보존했으며 분석 완료로 간주하지 않습니다."})
            block["synthesis_status"] = {"status": "failed", "retryable": True}

    try:
        cover = playbook.coverage(block, targets.get("criteria"))
        if cover:
            block["coverage"] = cover
            steps.extend({"track": "산출물 점검", "text": line}
                         for line in playbook.coverage_steps(cover))
        gaps = [_one_line(gap) for gap in targets.get("gaps") or [] if _one_line(gap)]
        if gaps:
            block["gaps"] = gaps
            steps.append({"track": "산출물 점검",
                          "text": "공개 자료로 닿지 않아 더 필요하다고 본 것 {}가지: {}.".format(
                              len(gaps), "; ".join(gaps[:3]))})
    except Exception as error:
        steps.append({"track": "산출물 점검", "text": "실패: {}".format(str(error)[:90])})
    try:
        block["steps_summary"] = summarize(block)
    except Exception:
        block["steps_summary"] = "정보성 기사 — 공격 조사 생략."
    try:
        analyst_workflow.finalize(block, targets)
    except Exception as error:
        block.setdefault("steps", steps).append(
            {"track": "최종 점검", "text": "실패: {}".format(str(error)[:90])})
    return block


def summarize(block):
    """조사 과정 요약 — "정보성 기사 — 공격 조사 생략 · 참고 자료 n건 읽음(…) · …"."""
    block = block or {}
    parts = ["정보성 기사 — 공격 조사 생략"]
    sources = (block.get("primary") or {}).get("sources") or []
    if sources:
        hosts = list(dict.fromkeys(_bare(s.get("host")) or _host(s.get("url")) for s in sources))
        parts.append("참고 자료 {}건 읽음({})".format(len(sources), ", ".join(h for h in hosts[:3] if h)))
    background = block.get("background") or []
    if background:
        parts.append("용어·배경 {}건".format(len(background)))
    questions = (block.get("synthesis") or {}).get("question_status") or []
    if questions:
        answered = sum(1 for row in questions if row.get("status") == "answered")
        partial = sum(1 for row in questions if row.get("status") == "partial")
        parts.append("검토 질문 {}개 중 확인 {}{}".format(
            len(questions), answered, "·부분 {}".format(partial) if partial else ""))
    return " · ".join(parts) + "."


def reading_section(block):
    """분석 본문 끝에 붙일 [더 알아보기] 섹션. 자료가 없으면 "".

    한 줄에 한 항목, 줄은 "- "로 시작한다 — "["로 시작하면 대시보드가 새 섹션 제목으로
    읽는다. 제목 안의 대괄호("[PDF] …")도 소괄호로 바꾼다.
    """
    lines = []
    for item in ((block or {}).get("reading_list") or [])[:MAX_READING]:
        if not isinstance(item, dict):
            continue
        host = _one_line(item.get("host")) or _host(item.get("url"))
        title = _one_line(item.get("title")).replace("[", "(").replace("]", ")")
        note = _one_line(item.get("note")).replace("[", "(").replace("]", ")")
        if not (title or host):
            continue
        head = title if not host or not title or title == host else "{} ({})".format(title, host)
        lines.append("- " + (head or host) + (" — " + note if note else ""))
    if not lines:
        return ""
    return "[더 알아보기]\n" + "\n".join(lines)
