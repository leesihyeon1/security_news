# -*- coding: utf-8 -*-
"""분석문에서 "조사 대상"을 정규식으로 캐지 않고 LLM에게 받아 온다.

왜 필요한가
    조사&대응의 모든 트랙이 "우리말 분석문에서 정규식으로 뽑은 지표"를 요구했다.
    LLM이 쓴 한국어 산문을 우리가 정규식으로 파는 구조여서, 문장에 해시·도메인·CVE가
    문자 그대로 없으면 아무것도 안 켜졌다. 실측(34건): 트랙이 하나도 안 붙은 기사가
    12건이고 그중 4건은 조사할 것이 분명히 있는데 못 잡은 경우였다.

    대표적인 것이 Adobe Commerce 제로데이 기사다. Adobe가 CVE를 아직 안 줘서 본문에
    CVE 문자열이 없고, 그래서 취약점 트랙이 성립하지 않아 카드가 통째로 비었다.
    그런데 NVD에 제품명 "Adobe Commerce"로 검색하면 그 제로데이(CVE-2026-75650)가
    나온다 — 조사할 방법이 있었는데 문자열 하나 때문에 안 돌았다.

    그래서 산문을 캐는 대신, 분석을 만들 때 기계가 읽을 목록을 같이 받는다. 이미
    LLM을 부르고 있으므로 호출이 늘지 않는다.

무엇을 받나
    지표(도메인·IP·해시·URL·CVE)뿐 아니라 제품+버전, 패키지, 행위자, 악성코드명,
    파일·경로·레지스트리·명령까지 받는다. 앞의 것은 조회 입력이 되고 뒤의 것은
    탐지 쿼리 재료가 된다.

    "조사가능" 줄도 함께 받는다. 조사할 지표가 없는 기사(칼럼·통계·행사 소개)는
    비는 것이 맞는데, 지금은 카드가 조용히 사라져서 기능 고장과 구별되지 않는다.
    왜 없는지를 받아 두면 "없음"을 말할 수 있다.
"""

import re

# 프롬프트에 붙일 명세. 사람이 읽는 섹션이 아니라 도구가 읽는 목록이라는 점을 못박고,
# 줄 이름을 고정해 파싱이 흔들리지 않게 한다.
SPEC = """

[조사 대상]
이 섹션은 사람이 읽는 글이 아니라 자동 조사 도구가 읽는 목록이다. 아래 줄 이름을 그대로
쓰고, 본문에 실제로 나온 값만 적어라. 없으면 "없음"이라고 써라. 여러 개면 쉼표로 나눈다.
값에 볼드(**)나 설명을 붙이지 마라.
도메인:
IP:
해시:
URL:
CVE:
제품: 제품마다 "이름 버전" 한 덩어리로 쓰고, 여러 제품은 쉼표로 나눈다. 버전만 따로
  쓰지 말고 이름을 매번 반복하라. 버전을 모르면 이름만 쓰고 괄호 주석을 붙이지 마라.
  좋음) Adobe Commerce 2.4.9, Magento Open Source 2.4.7
  나쁨) Magento Open Source 2.4.7, 2.4.8, 2.4.9 / Adobe Commerce(버전 미확인)
패키지: 생태계:이름 형태. 예) npm:@scope/name, pypi:requests
행위자:
악성코드:
파일: 공격에 쓰인 파일 이름. 예) dui70.dll, 1.bat
경로: 예) C:\\ProgramData\\f47f2a8c21c9df4e
레지스트리키:
명령: 공격자가 실행한 명령줄. 예) nltest /domain_trusts
조사가능: 위 줄 중 하나라도 값이 있으면 "예", 전부 "없음"이면 "아니오"
조사불가사유: "아니오"일 때만, 왜 조사할 지표가 없는 기사인지 한 문장(예: 통계 요약 기사다)
"""

SECTION_RE = re.compile(r"\n?\s*\[\s*조사\s*대상\s*\]\s*\n(.*?)(?=\n\s*\[|\Z)", re.S)

# 줄 이름 → 결과 키. 화면에는 안 나가고 조사 코드만 쓴다.
FIELD_MAP = {
    "도메인": "domains", "IP": "ips", "해시": "hashes", "URL": "urls", "CVE": "cves",
    "제품": "products", "패키지": "packages", "행위자": "actors", "악성코드": "malware",
    "파일": "files", "경로": "paths", "레지스트리키": "registry", "명령": "commands",
}
EMPTY_VALUES = {"없음", "해당 없음", "해당없음", "-", "n/a", "na", "none", "null", ""}

LINE_RE = re.compile(r"^\s*(?:[-*]\s*)?([A-Za-z가-힣]+)\s*[:：]\s*(.*)$")
# 값에 붙어 오는 장식. 모델이 지시를 어기고 볼드나 따옴표를 붙이는 경우가 있다.
DECOR_RE = re.compile(r"^[\s*_`\"']+|[\s*_`\"']+$")


def _clean(value):
    return DECOR_RE.sub("", value or "").strip()


def _split(value):
    """쉼표로 나누되, 값 자체에 쉼표가 없는 항목만 다룬다는 전제로 단순하게 자른다."""
    parts = [_clean(part) for part in (value or "").split(",")]
    return [part for part in parts if part and part.lower() not in EMPTY_VALUES]


# 모델이 헤더를 빼먹고 필드만 이어 쓰는 경우가 있다(실측: 35건 중 1건에서 "[조사 대상]"
# 없이 "도메인: 없음"부터 시작했고, 헤더를 요구하는 정규식이 못 잡아 기계용 목록이
# 그대로 화면에 나갔다). 그래서 헤더가 없으면 필드 줄이 이어지는 구간을 찾아서 쓴다.
FIELD_LINE_RE = re.compile(
    "^[ " + chr(9) + "]*(?:[-*][ ]*)?(" + "|".join(FIELD_MAP) + "|조사가능|조사불가사유)"
    "[ ]*[:：]", re.M)
# 이만큼 이어져야 목록으로 본다. 한두 줄이면 본문 문장이 우연히 "제품: ..." 형태인
# 경우와 구별되지 않는다.
MIN_FIELD_LINES = 4


def _locate(text):
    """[조사 대상] 구간의 (시작, 끝, 본문)을 찾는다. 없으면 None."""
    text = text or ""
    match = SECTION_RE.search(text)
    if match:
        return match.start(), match.end(), match.group(1)

    # 헤더가 없는 경우 — 필드 줄이 연달아 나오는 구간을 통째로 본다.
    hits = list(FIELD_LINE_RE.finditer(text))
    if len(hits) < MIN_FIELD_LINES:
        return None
    start = hits[0].start()
    # 마지막 필드 줄의 끝(줄 끝까지)
    last = hits[-1]
    end = text.find(chr(10), last.end())
    end = len(text) if end < 0 else end
    return start, end, text[start:end]


def parse(text):
    """[조사 대상] 섹션을 dict로. 섹션이 없으면 빈 dict."""
    located = _locate(text)
    if not located:
        return {}
    found = {key: [] for key in FIELD_MAP.values()}
    investigable, reason = None, ""
    for line in located[2].splitlines():
        parsed = LINE_RE.match(line)
        if not parsed:
            continue
        name, value = _clean(parsed.group(1)), parsed.group(2)
        if name == "조사가능":
            cleaned = _clean(value)
            investigable = cleaned.startswith("예") or cleaned.lower().startswith("y")
            continue
        if name == "조사불가사유":
            reason = _clean(value)
            continue
        key = FIELD_MAP.get(name)
        if key:
            found[key] = _split(value)

    found = {key: values for key, values in found.items() if values}
    if investigable is None:
        investigable = bool(found)
    found["investigable"] = investigable
    if reason:
        found["reason"] = reason
    return found


def strip(text):
    """저장 전에 섹션을 떼어낸다 — 화면에 기계용 목록이 보이면 안 된다.

    헤더가 빠진 경우까지 지운다. 헤더만 보고 지우면 모델이 헤더를 빼먹은 회차에
    "도메인: 없음 / IP: 없음 …"이 분석 본문 끝에 그대로 붙어 나간다.
    """
    text = text or ""
    located = _locate(text)
    if not located:
        return text.strip()
    return (text[:located[0]] + text[located[1]:]).strip()


# 기사·분석문은 도메인을 무해화해 쓴다(247.cdnflare[.]xyz). 그대로 조회하면 안 잡힌다.
DEFANG_SUBS = (("[.]", "."), ("[:]", ":"), ("[/]", "/"), ("(.)", "."),
               ("(dot)", "."), ("[dot]", "."), ("hxxps", "https"), ("hxxp", "http"))


def undefang(value):
    text = value or ""
    for old_text, new_text in DEFANG_SUBS:
        text = text.replace(old_text, new_text)
    return text.strip()


def to_iocs(targets):
    """받은 값 중 지표 성격인 것을 기존 IOC 형식으로. 정규식 추출분과 합쳐 쓴다."""
    out = []
    for kind, key in (("domain", "domains"), ("ip", "ips"), ("url", "urls")):
        for value in targets.get(key) or []:
            value = undefang(value)
            if value:
                out.append({"type": kind, "value": value})
    for value in targets.get("hashes") or []:
        # 길이로 해시 종류를 가른다 — 모델이 종류까지 맞게 쓰리라 기대하지 않는다.
        kind = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value.strip()))
        if kind:
            out.append({"type": kind, "value": value.strip()})
    return out


def merge_iocs(existing, targets):
    """기존 IOC 목록에 LLM이 준 것을 더한다(값 기준 중복 제거)."""
    seen = {str((item.get("value") or "")).lower() for item in existing or []}
    merged = list(existing or [])
    for item in to_iocs(targets):
        key = item["value"].lower()
        if key not in seen:
            seen.add(key)
            merged.append(item)
    return merged


# 버전만 적힌 항목. 모델이 "Magento Open Source 2.4.7, 2.4.8, 2.4.9"처럼 이름을 한 번만
# 쓰고 버전을 쉼표로 이어 쓰면 뒤쪽이 제품명으로 잘린다 — 그대로 조회하면 "2.4.8"이
# 들어간 무관한 제품의 CVE가 딸려 온다(실측: 그렇게 들어온 CVE 4건이 전부 노이즈였다).
VERSION_ONLY_RE = re.compile(r"^v?\d+(?:[.\-]\w+)*$")
# "Adobe Commerce(버전 미확인)"처럼 뒤에 붙는 괄호 주석. 붙어 있으면 검색이 안 된다.
PAREN_RE = re.compile(r"[(（][^)）]*[)）]")
VERSION_TAIL_RE = re.compile(r"^(.*?)\s+(v?(?:\d+\.)+\d+[\w.\-]*)$")
PRODUCT_NAME_MIN = 3


def products(targets):
    """제품 이름과 버전을 나눈다. 이름이 아닌 것(버전만·너무 짧은 것)은 버린다."""
    out, seen = [], set()
    for raw in targets.get("products") or []:
        value = _clean(PAREN_RE.sub("", raw or ""))
        if not value or VERSION_ONLY_RE.match(value):
            continue
        match = VERSION_TAIL_RE.match(value)
        name, version = (match.group(1), match.group(2)) if match else (value, "")
        name = _clean(name)
        # 이름에 글자가 하나도 없으면 제품명이 아니다(숫자·점만 남은 조각).
        if len(name) < PRODUCT_NAME_MIN or not re.search(r"[A-Za-z가-힣]", name):
            continue
        key = name.lower()
        if key in seen:
            # 같은 제품이 버전만 다르게 여러 번 오면 버전 있는 쪽을 남긴다.
            if version:
                for item in out:
                    if item["name"].lower() == key and not item["version"]:
                        item["version"] = version
            continue
        seen.add(key)
        out.append({"name": name, "version": version})
    return out


def packages(targets):
    """생태계:이름 형태를 나눈다. 생태계를 안 쓴 경우는 이름만 준다."""
    aliases = {"pypi": "pip", "python": "pip", "pip": "pip", "npm": "npm",
               "node": "npm", "docker": "docker", "rubygems": "rubygems",
               "maven": "maven", "nuget": "nuget", "cargo": "rust", "crates": "rust",
               "go": "go", "composer": "composer", "packagist": "composer"}
    out = []
    for raw in targets.get("packages") or []:
        if ":" in raw:
            head, _, name = raw.partition(":")
            ecosystem = aliases.get(_clean(head).lower(), "")
        else:
            ecosystem, name = "", raw
        name = _clean(name)
        if name:
            out.append({"ecosystem": ecosystem, "name": name})
    return out
