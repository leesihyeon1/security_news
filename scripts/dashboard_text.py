"""Text normalization for dashboard exports."""

import re
from datetime import datetime


def data_status(period_label, period, latest_collected_at=""):
    bounds = re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", period_label or "")
    result = {"latest_collected_at": latest_collected_at,
              "stale_after_hours": 36 if period == "daily" else 192}
    if len(bounds) == 2 and "UTC" in period_label:
        for key, value in zip(("period_start", "period_end"), bounds):
            result[key] = datetime.strptime(value, "%Y-%m-%d %H:%M").isoformat() + "Z"
    return result


def _strip_sentences(text, should_drop):
    """should_drop(문장)이 참인 문장만 빼고, 나머지는 원래 구분자(". ", 줄바꿈 등)
    그대로 잇는다. should_drop은 정규식 패턴(.search 메서드가 있는 것) 또는
    문장 하나를 받아 bool을 돌려주는 함수 둘 다 받는다.

    실측: 원래 구현은 문장 단위로 나눈 뒤 항상 "\\n"으로 다시 이어서, 아무것도
    지울 게 없어도 본문 전체가 문장마다 줄바꿈되는 글로 바뀌었다(analysis 필드
    61건 전부가 그렇게 재포맷됐다 — 실제로 지워진 문장은 그중 일부뿐이었는데).
    분리는 구분자를 캡처 그룹으로 남겨서 하고, 지운 문장의 구분자만 같이 버리고
    나머지 구분자는 원문 그대로 둔다. 아무것도 안 지웠으면 원문을 그대로 돌려준다.
    """
    test = should_drop.search if hasattr(should_drop, "search") else should_drop
    text = text or ""
    segments = re.split(r"((?<=[.!?。！？])\s+|\n)", text)
    kept = []
    dropped_any = False
    for index in range(0, len(segments), 2):
        chunk = segments[index]
        separator = segments[index + 1] if index + 1 < len(segments) else None
        if test(chunk):
            dropped_any = True
            continue
        kept.append(chunk)
        if separator is not None:
            kept.append(separator)
    if not dropped_any:
        return text.strip()
    return "".join(kept).strip()


# 이것만으로 이미 유출이다 — 우리가 무엇을 쓰는지 몰라도, 내부 추적 파일 이름이나
# PIR 식별자, "당사가 이런 내부 목록을 갖고 있다"는 문구 자체가 정찰 정보다. 문맥과
# 무관하게 어디서든 지운다.
MENTIONS_PRIVATE_FILE = re.compile(
    r"inventory\.yml|\bPIR-?\d*\b|"
    r"(?:당사|자사)\s*(?:관리\s*)?자산\s*(?:목록|인벤토리)|"
    r"우리\s*환경\s*[:：]",
    re.I,
)
# 총평처럼 모델이 쓰는 자유 서술 산문에서 쓰는 낱말 하나짜리 규칙 — 문장이 몇 개 안
# 되는 산문이라 오탐 비용이 낮다(실측: "자사 Check Point 장비가 영향받습니다"를
# 걸러야 한다). MENTIONS_PRIVATE_FILE의 네 가지도 당연히 포함한다.
MENTIONS_PRIVATE_ENV = re.compile(
    MENTIONS_PRIVATE_FILE.pattern + r"|자사|당사|우리\s*(?:회사|조직|자산)|내부\s*(?:자산|인벤토리)|자산\s*매칭",
    re.I,
)
# investigation 레코드 전용 — 이 표시만으로는 안 지운다. "사내에 있는지 확인한다",
# "자산 목록과 대조한다"는 모든 취약점 기사에 코드가 붙이는 정형 문구라, 실제 보유
# 제품 이름과 같이 나올 때만 위험하다(redact_asset_mentions 참고).
PRIVATE_CONTEXT_MARKER = re.compile(r"자사|당사|사내|우리\s*환경|자산\s*(?:목록|매칭|인벤토리)", re.I)


def public_text(text):
    """Remove sentences that describe the reader's private environment.

    총평·이슈 요약처럼 모델이 쓰는 자유 서술 산문에 쓴다. 실측(2026-09-22): "당사
    관리 자산 목록(Arista, Juniper, Citrix, Fortigate 등)에 Orkes Conductor가 없어",
    "사내 자산 목록(inventory.yml)과 대조", "우리 환경: Windows 단말 보유", "자사
    Check Point 장비가 영향받습니다" 같은 문장이 인증 없는 공개 API로 그대로 나갔다.

    심층분석(investigation) 레코드에는 이 함수를 쓰지 마라 — redact_private_environment()를
    써라. 산문과 달리 그쪽은 코드가 만든 정형 조치 문구("사내에 있는지 확인한다" 등)가
    많아서, 낱말 하나짜리 규칙을 그대로 적용하면 실제 보유 제품 이름이 없는 문장까지
    지워진다(실측: 384개 필드, 36개 레코드가 그렇게 과다 삭제됐다).
    """
    return _strip_sentences(text, MENTIONS_PRIVATE_ENV)


def redact_asset_mentions(text, product_names):
    """Remove sentences that pair a private-context marker with a real inventory product.

    "우리 환경의 해당 제품 보유 여부로 정해집니다"(제품명 없음)나 "사내에서 이
    저장소를 내려받은 이력이 있는지 확인한다"(제품명 없음)는 정형 조치 문구라 그대로
    둔다. "사내 운영 중인 Cisco IOS XR 버전이…"처럼 실제 우리 인벤토리에 있는 제품
    이름이 같은 문장에 나올 때만 지운다 — 그게 실제로 유출되는 정보다.
    """
    names = [n for n in (product_names or []) if n and len(n) >= 2]
    if not names:
        return text
    names_re = re.compile("|".join(re.escape(n) for n in names), re.I)
    return _strip_sentences(
        text, lambda chunk: bool(PRIVATE_CONTEXT_MARKER.search(chunk) and names_re.search(chunk)))


def redact_private_environment(value, product_names=None):
    """Recursively strip sentences that reveal our environment from any string leaf.

    심층분석(investigation) 레코드용이다. 자유 서술 필드가 중첩 dict/list로 깊게
    얽혀 있어 public_text()처럼 필드 단위로 불러 쓸 수 없어서, 구조를 그대로 걸으며
    문자열 잎마다 적용한다.

    public_text()가 아니라 MENTIONS_PRIVATE_FILE(파일명·PIR·소유 구문)만 무조건
    지운다 — 이 레코드에는 코드가 만든 정형 조치 문구가 많아서 낱말 하나짜리 규칙을
    그대로 쓰면 과다 삭제된다. product_names를 주면(우리 인벤토리의 실제 제품·별칭
    목록) redact_asset_mentions도 같이 돌려, 실제 보유 제품 이름이 "사내"·"자산
    목록" 같은 표현과 같이 나온 문장까지 잡는다.
    """
    if isinstance(value, str):
        text = _strip_sentences(value, MENTIONS_PRIVATE_FILE)
        if product_names:
            text = redact_asset_mentions(text, product_names)
        return text
    if isinstance(value, dict):
        return {key: redact_private_environment(item, product_names) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_private_environment(item, product_names) for item in value]
    return value


def is_korean_text(text):
    return len(re.findall(r"[가-힣]", text or "")) >= 4


def public_narrative(text):
    """Preserve the report sections without publishing private or English prose."""
    headers = ("총평", "핵심 위협 TOP 3", "권고 조치")
    markers = list(re.finditer(r"(?m)^[ \t]*\[([^\]\n]+)\][ \t]*", text or ""))
    bodies = {match.group(1): (text or "")[match.end():markers[i + 1].start() if i + 1 < len(markers) else len(text or "")]
              for i, match in enumerate(markers)}
    sections = []
    for header in headers:
        body = public_text(bodies.get(header, ""))
        lines = [line.strip() for line in body.splitlines() if is_korean_text(line)]
        if header != "총평":
            lines = ["{}. {}".format(i + 1, re.sub(r"^(?:\d+[.)]|[-*])\s*", "", line))
                     for i, line in enumerate(lines[:3])]
        sections.append("[{}]\n{}".format(header, "\n".join(lines) or "한국어 요약을 준비하지 못했습니다. 관련 기사와 판단 근거를 확인해 주세요."))
    return "\n\n".join(sections)


def public_evidence(event, source_label):
    signals = []
    if event.get("kev"):
        signals.append("KEV 등재 신호")
    exploitation = event.get("exploitation_status")
    if exploitation and exploitation != "none":
        signals.append("악용 상태: " + str(exploitation))
    if event.get("epss") is not None:
        signals.append("EPSS: " + str(event["epss"]))
    url = event.get("url") or ""
    return {
        "source_label": source_label,
        "url": url if url.startswith(("https://", "http://")) else "",
        "collected_at": event.get("fetched_at") or "",
        "signals": signals,
    }


def summary_excerpt(text, limit):
    text = re.sub(r"\s+", " ", (text or "").strip())
    if len(text) <= limit:
        return text
    # Only use punctuation followed by whitespace, avoiding decimal/version dots.
    ends = [match.end() for match in re.finditer(r"[.!?。！？](?=\s|$)", text)
            if match.end() <= limit]
    if ends:
        return text[:ends[-1]]
    prefix = text[:limit - 1].rstrip()
    if " " in prefix:
        prefix = prefix.rsplit(" ", 1)[0]
    return prefix + "\u2026"


def event_summary(event, limit):
    for field in ("ai_summary", "summary"):
        value = (event.get(field) or "").strip()
        if value and is_korean_text(value):
            return summary_excerpt(value, limit)
    return "요약 미제공 · 원문 확인"
