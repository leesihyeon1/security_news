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
SPEC_TEMPLATE = """

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
주력: 이 건을 어느 축으로 조사해야 하는지 하나만 골라라. 아래 넷 중 이름 그대로 쓴다.
  user_action  = 사람이 속아서 직접 실행·입력하게 만드는 수법이 핵심이다. 막아야 할 것은
                 파일이 아니라 미끼(가짜 페이지·사칭 전화·가짜 안내)다.
  malware      = 실행되면 스스로 동작하는 파일이 핵심이다. 무엇을 하는 물건인지가 쟁점이다.
  vulnerability= 제품의 결함이 핵심이다. 쟁점은 "지금 패치해야 하는가"다.
  supply_chain = 신뢰하던 배포 경로가 오염된 것이 핵심이다. 패키지·확장·업데이트·빌드·
                 저장소처럼 "받아 쓰는 통로"로 들어온 건이면 여기다.
  고르는 기준은 기사에 무슨 단어가 많이 나오는지가 아니라 "무엇을 끊어야 이 공격이
  멈추는가"다. 공급망 침해는 악성코드를 함께 설명하지만, 끊어야 할 것은 오염된 배포
  경로이므로 supply_chain이다. 판단이 안 서면 "없음"이라고 쓰고 비워 둬라 — 억지로
  고르면 엉뚱한 조사가 돌아간다.
조사가능: 위 줄 중 하나라도 값이 있으면 "예", 전부 "없음"이면 "아니오"
조사불가사유: "아니오"일 때만, 왜 조사할 지표가 없는 기사인지 한 문장(예: 통계 요약 기사다)
목표: 이 기사에 대해 달성해야 할 것을 한 문장으로 정하라. 유형별 정답을 주지 않는다 —
  기사를 읽고 이번 건에 무엇이 가장 중요한지 직접 판단하라. 다만 쓸모 있는 목표는
  이런 성질을 갖는다:
    · 이번 지표 하나가 아니라 같은 수법이 다시 왔을 때도 쓸 수 있는가
    · 달성했는지 판정할 수 있는가(무엇이 나오면 끝난 것인지 분명한가)
    · 우리가 실제로 할 수 있는 일인가(외부 조회·사내 헌팅으로 닿는 범위인가)
  기사 요약을 되풀이하지 마라.
성공기준: 위 목표를 달성하려면 무엇이 나와야 하는지를 아래 이름들 중에서 골라 쉼표로
  나눠 쓰라. 이 사건에 필요한 것만 고르고, 필요 없는 것은 넣지 마라 — 나중에 실제로
  나왔는지 대조하므로 넣은 것은 약속이 된다.
{VOCAB}
확인질문: 목표를 달성하려면 조회로 답해야 할 질문 2~4개를 쉼표로 나눠 쓴다.
  예) 이 CVE가 실제 악용 중인가, 사내에 해당 버전이 있는가, 유포지가 아직 살아 있는가
"""

import playbook

# 어휘는 playbook이 갖고 있다 — 검증하는 쪽과 요구하는 쪽이 어긋나면
# 모델이 낼 수 없는 것을 약속하게 된다.
SPEC = SPEC_TEMPLATE.replace("{VOCAB}", playbook.vocabulary_spec())

SECTION_RE = re.compile(r"\n?\s*\[\s*조사\s*대상\s*\]\s*\n(.*?)(?=\n\s*\[|\Z)", re.S)

# 줄 이름 → 결과 키. 화면에는 안 나가고 조사 코드만 쓴다.
FIELD_MAP = {
    "도메인": "domains", "IP": "ips", "해시": "hashes", "URL": "urls", "CVE": "cves",
    "제품": "products", "패키지": "packages", "행위자": "actors", "악성코드": "malware",
    "파일": "files", "경로": "paths", "레지스트리키": "registry", "명령": "commands",
}
EMPTY_VALUES = {"없음", "해당 없음", "해당없음", "-", "n/a", "na", "none", "null", ""}

LINE_RE = re.compile(r"^\s*(?:[-*]\s*)?([A-Za-z가-힣]+)\s*[:：]\s*(.*)$")
# 모델이 "주력"으로 쓸 수 있는 축. investigation.TRACK_LABELS와 같은 이름이어야 한다 —
# 여기서만 아는 이름을 쓰면 선언이 조용히 버려진다.
PRIMARY_AXES = ("user_action", "malware", "vulnerability", "supply_chain")
# 값에 붙어 오는 장식. 모델이 지시를 어기고 볼드나 따옴표를 붙이는 경우가 있다.
DECOR_RE = re.compile(r"^[\s*_`\"']+|[\s*_`\"']+$")


def _clean(value):
    return DECOR_RE.sub("", value or "").strip()


def _split(value):
    """쉼표로 나눈다. 다만 괄호 안의 쉼표는 값의 일부다.

    확인질문에 "도메인 정찰 명령(nltest, net group, ADSI) 실행 이력이 있는가"처럼
    괄호 안에 목록이 들어오는데, 그대로 자르면 한 질문이 세 조각으로 쪼개진다
    (실측: 질문 4개가 6개로 늘어나고 뜻이 사라졌다).
    """
    parts, buf, depth = [], [], 0
    for char in (value or ""):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(char)
    parts.append("".join(buf))
    cleaned = [_clean(part) for part in parts]
    return [part for part in cleaned if part and part.lower() not in EMPTY_VALUES]


# 모델이 헤더를 빼먹고 필드만 이어 쓰는 경우가 있다(실측: 35건 중 1건에서 "[조사 대상]"
# 없이 "도메인: 없음"부터 시작했고, 헤더를 요구하는 정규식이 못 잡아 기계용 목록이
# 그대로 화면에 나갔다). 그래서 헤더가 없으면 필드 줄이 이어지는 구간을 찾아서 쓴다.
FIELD_LINE_RE = re.compile(
    "^[ " + chr(9) + "]*(?:[-*][ ]*)?(" + "|".join(FIELD_MAP)
    + "|조사가능|조사불가사유|목표|확인질문|성공기준|주력)"
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
    objective, questions, criteria, primary = "", [], [], ""
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
        if name == "목표":
            objective = _clean(value)
            continue
        if name == "확인질문":
            questions = _split(value)
            continue
        if name == "성공기준":
            criteria = _split(value)
            continue
        if name == "주력":
            # 어휘 밖의 값은 버린다. 여기서 거르지 않으면 "네트워크 침투" 같은
            # 자유 문장이 트랙 이름 자리에 들어와 조사 계획이 통째로 어긋난다.
            candidate = _clean(value).lower().replace("-", "_").replace(" ", "_")
            primary = candidate if candidate in PRIMARY_AXES else ""
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
    # 목표는 조회 전에 세우는 것이라 지표가 없어도 의미가 있다 — 지표가 하나도 없는
    # 기사에서도 "무엇을 확인해야 하는가"는 남는다.
    if objective:
        found["objective"] = objective
    if questions:
        found["questions"] = questions
    # 성공기준은 모델이 스스로 건 약속이다. 나중에 실제 산출물과 대조한다.
    if criteria:
        found["criteria"] = criteria
    # 주력 축은 모델의 판단이고, 실제로 그 조사를 돌릴 수 있는지는 investigation이 본다.
    if primary:
        found["primary"] = primary
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
