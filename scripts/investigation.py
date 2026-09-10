"""조사 방향을 정하고 두 트랙을 합친다 — 심층분석의 "조사&대응" 블록.

사건 성격에 따라 조사 방법이 갈린다:
    · 사용자 행위 기반 — ClickFix처럼 사람이 명령을 붙여넣어야 실행되는 유형. 파일이
      아니라 미끼 페이지·유포지가 핵심이라 URL 분석(urlscan)으로 본다.
    · 악성코드 기반 — 파일이 실행돼 스스로 동작하는 유형. 파일이 핵심이라 VT 동적
      분석(샌드박스가 실제 실행해 본 결과)으로 본다.

    한 기사에 둘 다 있는 경우가 흔하다(TerminalFix가 그렇다 — 침투는 사용자 행위,
    이후 단계는 악성코드). 그럴 때는 두 트랙을 같이 보여주고 어느 쪽이 주력인지만
    밝힌다. 증거가 있는 트랙만 만든다 — 해시가 없으면 VT 트랙은 아예 안 나온다.
"""

import re

import analysis_targets
import lure_hunter
import pattern_synth
import response_builder
import supply_chain_hunter
import vt_hunter
import vuln_hunter

# 키워드가 있느냐 없느냐로 방향을 정하면 틀린다. 실측(REVSTEALER 기사): 제목에
# STEALER·Miner, 분류가 "악성코드", 해시 5건인데도 본문에 "클립보드 하이재킹"(악성코드의
# 기능이다), "게임 치트·가짜 AI 도구 미끼"(배포 경로 설명), 그리고 MITRE 목록의
# "T1566.001 (피싱: ...)"이 걸려서 사용자 행위 기반으로 잘못 분류됐다.
#
# 그래서 세 가지를 구분한다:
#   ① 강한 표현(전달 방식 자체를 가리킴) vs 약한 표현(배포 경로 언급 수준)
#   ② 어디에 나왔나 — 제목·분류는 사건의 정체이고, 본문은 지나가는 언급일 수 있다
#   ③ MITRE 목록·용어 설명은 제외 — 기법 이름과 일반 설명이라 이 사건의 성격이 아니다

# 사람이 직접 명령을 실행한다는 것을 가리키는 표현.
USER_ACTION_STRONG_RE = re.compile(
    r"clickfix|click\s*fix|installfix|terminalfix|fake\s*captcha|가짜\s*(?:cloudflare\s*)?captcha|"
    r"turnstile|copy[\s-]*paste|붙여넣|복사해\s*실행|복사해서\s*실행|직접\s*실행하도록|"
    # captcha·"사람인지 확인" 화면 자체가 ClickFix 계열의 전달 방식이다. 실측:
    # "Midnight Blizzard Targets Travelers via CaptCha" 기사가 이 표현이 없어 malware로 갔다.
    r"captcha|캡차|verify\s*you\s*are\s*human|human\s*verification|사람인지\s*확인|"
    r"win\s*\+\s*r|windows\s*\+\s*r|실행\s*창에\s*붙|터미널에\s*붙",
    re.I,
)
# 배포 경로를 설명하는 표현 — 악성코드 기사에도 흔히 같이 나온다.
USER_ACTION_WEAK_RE = re.compile(
    r"피싱|phish|smishing|스미싱|사회공학|social\s*engineer|유인|미끼|lure|"
    r"watering\s*hole|악성\s*광고|malvertis|드라이브\s*바이|drive[\s-]*by|"
    r"게임\s*치트|가짜\s*(?:설치|도구|업데이트)",
    re.I,
)
# 실행되면 스스로 동작하는 것의 이름.
MALWARE_STRONG_RE = re.compile(
    r"stealer|스틸러|infostealer|ransomware|랜섬웨어|miner|마이너|채굴|trojan|트로이|"
    r"backdoor|백도어|\bRAT\b|원격제어|loader|로더|dropper|드로퍼|botnet|봇넷|"
    r"rootkit|루트킷|wiper|와이퍼|keylogger|키로거|worm|웜|악성코드|멀웨어|malware|"
    r"악성\s*모듈|백신\s*무력화|defender\s*무력화",
    re.I,
)
# 악성코드 기사에 흔하지만 그 자체로는 성격을 못 정하는 표현.
MALWARE_WEAK_RE = re.compile(
    r"페이로드|payload|샘플|sample|사이드로딩|sideload|모듈|module|드롭|drop",
    re.I,
)

# 기법 목록과 용어 설명은 이 사건이 무엇인지와 무관하다 — 점수에서 뺀다.
SKIP_SECTION_RE = re.compile(
    r"\[(?:MITRE\s*ATT&CK|선수\s*정보|용어)[^\]]*\].*?(?=\s\[|\Z)",
    re.I | re.S,
)

TITLE_WEIGHT = 4       # 제목·분류에 나온 표현은 사건의 정체다
BODY_CAP_STRONG = 3    # 본문 강한 표현은 3점까지만(같은 말 반복이 점수를 밀지 않게)
BODY_CAP_WEAK = 1
EVIDENCE_HASH = 2      # 분석할 파일이 있다
EVIDENCE_DOMAIN = 1    # 도메인은 C2로도 나오니 약하게 본다

# 취약점 기사는 앞의 두 축과 판단 기준이 다르다 — "패치를 지금 해야 하나"이고, 그건
# KEV 등재·EPSS·영향 제품 보유 여부로 정해진다.
VULN_STRONG_RE = re.compile(
    r"취약점|vulnerabilit|제로데이|zero[\s-]*day|패치|patch|익스플로잇|exploit|"
    r"원격\s*코드\s*실행|\bRCE\b|권한\s*상승\s*취약|KEV|known\s*exploited|"
    r"업데이트\s*권고|보안\s*공지|advisory",
    re.I,
)

TRACK_LABELS = {
    "user_action": "사용자 행위 기반 — URL 분석",
    "malware": "악성코드 기반 — VT 동적 분석",
    "vulnerability": "취약점 기반 — 패치 우선순위",
    "supply_chain": "공급망 기반 — 패키지 레지스트리",
}


def _strip_reference_sections(text):
    return SKIP_SECTION_RE.sub(" ", text or "")


def _score(head, body, strong_re, weak_re):
    """제목·분류(head)와 본문(body)을 나눠 점수와 근거를 뽑는다."""
    reasons = []
    score = 0
    head_hits = sorted({m.group(0).strip().lower() for m in strong_re.finditer(head)})
    head_weak = sorted({m.group(0).strip().lower() for m in weak_re.finditer(head)})
    if head_hits:
        score += TITLE_WEIGHT * len(head_hits)
    if head_weak:
        score += len(head_weak)
    if head_hits or head_weak:
        # 강한 표현을 앞에 둔다 — 근거를 읽는 사람이 무엇 때문인지 바로 알게.
        reasons.append("제목·분류에 {}".format(", ".join((head_hits + head_weak)[:4])))

    body_hits = sorted({m.group(0).strip().lower() for m in strong_re.finditer(body)})
    if body_hits:
        score += min(len(body_hits), BODY_CAP_STRONG)
        reasons.append("본문에 {}".format(", ".join(body_hits[:3])))
    body_weak = sorted({m.group(0).strip().lower() for m in weak_re.finditer(body)})
    if body_weak:
        score += min(len(body_weak), BODY_CAP_WEAK)
    return score, reasons


def classify(iocs, text="", title="", category="", targets=None):
    """어떤 트랙이 필요한지, 그중 무엇이 주력인지 판단한다.

    트랙 존재 여부는 증거(IOC 종류)로 정하고, 무엇을 주력으로 볼지는 사건의 성격
    (제목·분류·본문의 표현)으로 정한다. 해시가 없으면 VT로 볼 게 없고, 유포 도메인이
    없으면 URL 분석은 할 게 없다 — 그건 점수와 무관하게 확정이다.
    """
    hashes = vt_hunter.file_hashes_from_iocs(iocs)
    domains = lure_hunter._seed_domains_from_iocs(iocs)
    targets = targets or {}
    cves = vuln_hunter.cves_from_text(text, iocs)
    for cve in targets.get("cves") or []:
        if cve.upper() not in [c.upper() for c in cves]:
            cves.append(cve.upper())
    # 제품은 CVE가 아직 없는 제로데이에서 유일한 조사 입력이 된다(실측: Adobe가 CVE를
    # 안 준 StyleSmuggler 기사는 CVE가 없어 취약점 트랙이 통째로 안 켜졌다).
    products = analysis_targets.products(targets)

    # title·category를 따로 안 주면(구버전 호출) text 앞부분을 제목처럼 취급한다.
    head = " ".join([title or "", category or ""]).strip() or (text or "")[:160]
    body = _strip_reference_sections(text)

    user_score, user_reasons = _score(head, body, USER_ACTION_STRONG_RE, USER_ACTION_WEAK_RE)
    malware_score, malware_reasons = _score(head, body, MALWARE_STRONG_RE, MALWARE_WEAK_RE)

    # 증거(IOC)는 어떤 트랙을 만들 수 있는지만 정한다. 주력 판정에는 점수를 주지 않는다 —
    # 해시에 가점을 주면 파일 하나만 실려도 악성코드 분석으로 기울어, 취약점·동향 기사까지
    # malware로 간다(실측: 지표를 고정해 31건 재판정하니 29건이 malware).
    tracks = []
    if domains:
        tracks.append("user_action")
        user_reasons.append("유포 도메인 {}건".format(len(domains)))
    if hashes:
        tracks.append("malware")
        malware_reasons.append("파일 해시 {}건".format(len(hashes)))
    if cves or products:
        tracks.append("vulnerability")
    # 공급망은 앞의 셋과 달리 지표가 없어도 성립한다. 조사 대상이 기사에 적힌 값이
    # 아니라 레지스트리 자체이기 때문이다 — "지금 npm에 무엇이 올라오고 있는가"는
    # 기사에 해시가 있든 없든 조회된다.
    supply_chain = supply_chain_hunter.is_supply_chain(text, title)
    if supply_chain:
        tracks.append("supply_chain")

    strong_user = bool(USER_ACTION_STRONG_RE.search(head) or USER_ACTION_STRONG_RE.search(body))
    strong_malware = bool(MALWARE_STRONG_RE.search(head) or MALWARE_STRONG_RE.search(body))
    # 취약점은 제목·분류에 나올 때만 주력으로 본다 — 악성코드 기사도 본문에서 취약점을
    # 흔히 언급하기 때문에 본문 등장만으로는 주제가 아니다.
    vuln_score, vuln_reasons = _score(head, body, VULN_STRONG_RE, VULN_STRONG_RE)
    strong_vuln = bool(cves or products) and bool(VULN_STRONG_RE.search(head))
    if cves:
        vuln_reasons.append("CVE {}건".format(len(cves)))

    # 공급망은 제목에 레지스트리·공급망 표현이 있을 때만 주력으로 본다. 본문 한 줄에
    # "의존성"이 스친 정도로 주력을 뺏기면 악성코드 기사가 공급망 기사로 둔갑한다.
    strong_supply = bool(supply_chain) and supply_chain_hunter.is_supply_chain("", title)

    if not tracks:
        primary = ""
    elif strong_supply and not strong_malware and not strong_vuln:
        primary = "supply_chain"
    elif strong_vuln and vuln_score >= max(user_score, malware_score):
        primary = "vulnerability"
    elif not strong_user and not strong_malware and "supply_chain" in tracks and len(tracks) == 1:
        # 지표가 하나도 없는 공급망 기사 — 다른 트랙이 없으니 이쪽이 유일한 조사다.
        primary = "supply_chain"
    elif not strong_user and not strong_malware:
        # 어느 쪽으로도 볼 근거가 없으면 판정을 비운다. 억지로 하나를 고르면 화면에
        # "악성코드 기반입니다" 같은 단정이 근거 없이 붙는다.
        primary = ""
    elif len(tracks) == 1:
        primary = tracks[0]
    elif malware_score > user_score:
        primary = "malware"
    elif user_score > malware_score:
        primary = "user_action"
    else:
        # 동점이면 강한 표현이 있는 쪽. 둘 다 강하면 침투 단계를 먼저 본다.
        primary = "user_action" if strong_user else "malware"

    if not primary and tracks:
        # 트랙은 있는데 주력을 못 정한 경우 — 무엇이 있는지만 알리고 판단은 넘긴다.
        available = " / ".join(TRACK_LABELS[track].split(" — ")[1] for track in tracks)
        return {
            "primary": "",
            "label": "분석 방향 판정 보류",
            "explain": ("기사 문장만으로는 사용자 행위 기반인지 악성코드 기반인지 가릴 근거가 "
                        "없습니다. 확보된 지표에 맞는 조사({})를 모두 제시하니 성격을 보고 "
                        "고르시면 됩니다.".format(available)),
            "tracks": tracks,
            "hashes": hashes,
            "domains": domains,
            "cves": cves,
            "products": products,
            "scores": {"malware": malware_score, "user_action": user_score,
                       "vulnerability": vuln_score},
        }

    supply_reasons = []
    if supply_chain:
        registries = supply_chain_hunter.registries_from_text("{} {}".format(title or "", text or ""))
        if registries:
            supply_reasons.append("레지스트리 언급: {}".format(", ".join(
                supply_chain_hunter.REGISTRY_LABELS.get(r, r) for r in registries)))
        if supply_chain_hunter.mentions_docker("{} {}".format(title or "", text or "")):
            supply_reasons.append("Docker Hub 언급")
    reason_map = {"malware": malware_reasons, "user_action": user_reasons,
                  "vulnerability": vuln_reasons, "supply_chain": supply_reasons}
    basis = "; ".join((reason_map.get(primary) or [])[:3])
    explain = ""
    if primary == "user_action":
        explain = ("사용자가 직접 명령을 실행해야 하는 유형입니다. 파일을 막는 것보다 "
                   "유포지(미끼 페이지)를 찾아 차단하는 쪽이 효과가 크므로, URL 분석을 "
                   "주력으로 봅니다.")
        if "malware" in tracks:
            explain += " 실행 이후 단계의 파일 {}건은 VT 동적 분석으로 보완합니다.".format(len(hashes))
    elif primary == "malware":
        explain = ("파일이 실행되면 스스로 동작하는 유형입니다. 무엇을 하는 악성코드인지는 "
                   "탐지율이 아니라 실제 행위로 봐야 하므로, VT 동적 분석(샌드박스 실행 "
                   "결과)을 주력으로 봅니다.")
        if "user_action" in tracks:
            explain += " 유포·통신에 쓰인 도메인 {}건은 URL 분석으로 함께 봅니다.".format(len(domains))
    elif primary == "supply_chain":
        explain = ("공급망 기사입니다. 이런 기사에는 해시·도메인이 안 실리는 경우가 많은데, "
                   "조사할 대상이 기사에 적힌 값이 아니라 패키지 레지스트리 자체여서 "
                   "지표가 없어도 조사가 됩니다. 기사가 지목한 레지스트리에 지금 무엇이 "
                   "올라오고 있는지 조회하고, 그것이 사내에 들어왔는지 확인할 쿼리를 냅니다.")
    elif primary == "vulnerability":
        explain = ("취약점 기사입니다. 판단해야 할 것은 \"지금 패치해야 하나\"이고, 그건 CVSS "
                   "점수가 아니라 실제 악용 여부(CISA KEV)·악용 확률(EPSS)·우리 환경의 해당 "
                   "제품 보유 여부로 정해집니다. 그 셋을 조회해 정리했습니다.")
    if basis:
        explain += " (판단 근거: {} / 점수 악성코드 {} : 사용자 행위 {})".format(
            basis, malware_score, user_score)

    return {
        "primary": primary,
        "label": TRACK_LABELS.get(primary, ""),
        "explain": explain,
        "tracks": tracks,
        "hashes": hashes,
        "domains": domains,
        "cves": cves,
        "products": products,
        "scores": {"malware": malware_score, "user_action": user_score,
                   "vulnerability": vuln_score},
    }


def summarize(block):
    """조사 과정을 한두 문장으로. 상세 단계는 접어두고 이걸 먼저 읽게 한다.

    단계 문장을 다시 파싱하지 않고 결과물에서 센다 — 문구가 바뀌어도 요약이 어긋나지
    않는다.
    """
    seeds = block.get("seeds") or []
    malware = block.get("malware") or {}
    parts = []

    if seeds:
        observed = sum(1 for seed in seeds if seed.get("in_urlscan"))
        dom_checked = sum(1 for seed in seeds if seed.get("dom_markers") is not None
                          and (seed.get("dom_confirmed") or seed.get("dom_markers") == {} or seed.get("dom_markers")))
        cloaked = sum(1 for seed in seeds if (seed.get("cloaked_hosts") or []))
        text = "도메인 {}곳을 urlscan에서 조회했습니다({}곳은 스캔 기록 있음)".format(
            len(seeds), observed)
        if cloaked:
            text += ", 그중 {}곳은 스캐너에게 응답을 감췄습니다".format(cloaked)
        parts.append(text)

    files = malware.get("files") or []
    if files:
        if malware.get("checked"):
            parts.append("파일 해시 {}건 중 {}건을 VT 동적 분석으로 확인했습니다".format(
                malware.get("total_hashes") or len(files), len(files)))
        else:
            parts.append("파일 해시 {}건은 VT 링크만 준비했습니다(키 없음)".format(
                malware.get("total_hashes") or len(files)))

    queries = sum(len(seed.get("queries") or []) for seed in seeds)
    queries += sum(len(file.get("queries") or []) for file in files)
    tail = []
    if queries:
        tail.append("검색 쿼리 {}개".format(queries))
    if block.get("patterns"):
        tail.append("알려진 패턴 {}개".format(len(block["patterns"])))
    if tail:
        parts.append("{}를 확보했습니다".format("와 ".join(tail)))

    if not parts:
        return ""
    return " · ".join(parts) + "."


# ── 조회 등록표 ──────────────────────────────────────────────────────────────
# 트랙마다 if 문을 하나씩 두면 소스를 늘릴 때마다 build()를 고쳐야 하고, 어떤 입력이
# 어디로 가는지 코드를 읽어야만 알 수 있었다. 여기 한 줄이 하나의 조회다.
#
#   key     : 결과가 블록에 들어가는 이름(화면 렌더러가 이 이름으로 찾는다)
#   label   : 조사 과정에 찍히는 이름
#   consumes: 이 조회가 먹는 입력 — 사람이 읽는 설명이자, 입력이 비면 건너뛰는 근거
#   run     : ctx를 받아 트랙 dict를 돌려주는 함수(없으면 None)
#   merge   : 트랙을 블록에 넣는 방법. 대부분 key에 그대로 넣지만 URL 트랙만 예외다.


def _run_url(ctx):
    return lure_hunter.investigation_for_iocs(
        ctx["iocs"], api_key=ctx["urlscan_key"], text=ctx["text"])


def _merge_url(block, track):
    # URL 트랙만 결과를 블록 최상위(seeds/patterns/findings)에 편다 — 이 형식으로
    # 저장된 기록이 이미 있어서 화면 코드가 그대로 읽는다.
    block.update({key: track.get(key) for key in ("seeds", "patterns", "findings")})


def _run_malware(ctx):
    return vt_hunter.analyze_hashes(ctx["route"]["hashes"], api_key=ctx["vt_key"],
                                    iocs=ctx["iocs"])


def _run_supply(ctx):
    return supply_chain_hunter.analyze(ctx["text"], title=ctx["title"], iocs=ctx["iocs"])


def _run_vuln(ctx):
    return vuln_hunter.analyze(ctx["route"]["cves"], text=ctx["text"],
                               products=ctx["route"].get("products"))


def _merge_named(key):
    def merge(block, track):
        block[key] = track
    return merge


LOOKUPS = (
    {"key": "user_action", "label": "URL 분석",
     "consumes": "도메인·URL", "run": _run_url, "merge": _merge_url},
    {"key": "malware", "label": "VT 동적분석",
     "consumes": "파일 해시", "run": _run_malware, "merge": _merge_named("malware")},
    {"key": "supply_chain", "label": "공급망 조회",
     "consumes": "레지스트리 이름·패키지", "run": _run_supply,
     "merge": _merge_named("supply_chain")},
    {"key": "vulnerability", "label": "취약점 조회",
     "consumes": "CVE·제품 이름", "run": _run_vuln, "merge": _merge_named("vulnerability")},
)


def run_lookups(ctx, block, steps):
    """등록표를 돌며 성립한 트랙만 실행한다.

    조회 하나가 죽어도 나머지는 낸다. 예전에는 예외가 build() 밖으로 나가서 워커가
    조사&대응 전체를 버렸다 — VT 한 번 실패에 urlscan 결과까지 사라지는 구조였다.
    실패도 조사 과정에 남긴다. 조용히 빠지면 "원래 결과가 없었다"와 구별되지 않는다.
    """
    for lookup in LOOKUPS:
        if lookup["key"] not in ctx["route"]["tracks"]:
            continue
        try:
            track = lookup["run"](ctx)
        except Exception as error:
            steps.append({"track": lookup["label"],
                          "text": "조회 실패({}) — 이 트랙 결과는 비어 있습니다.".format(
                              str(error)[:70])})
            continue
        if not track:
            steps.append({"track": lookup["label"],
                          "text": "{}로 조회했지만 결과가 없었습니다.".format(lookup["consumes"])})
            continue
        lookup["merge"](block, track)
        if track.get("generated_at"):
            block.setdefault("generated_at", track["generated_at"])
        steps.extend({"track": lookup["label"], "text": line}
                     for line in track.get("steps") or [])


def build(iocs, text="", urlscan_key=None, vt_key=None, title="", category="",
          body="", synthesize=True, targets=None):
    """조사&대응 블록. 트랙별 결과를 한 dict로 합친다.

    반환 형태는 기존(seeds/patterns/findings)을 그대로 유지하고 route·malware만
    추가한다 — 이미 저장된 분석 기록을 그리는 화면 코드가 깨지지 않게.
    """
    targets = targets or {}
    route = classify(iocs, text=text, title=title, category=category, targets=targets)
    block = {"route": {key: route[key]
                       for key in ("primary", "label", "explain", "tracks", "scores")}}

    # 지표가 없어도 본문에서 대응 재료가 나오면 블록을 만든다 — 예전에는 트랙이 없으면
    # 통째로 건너뛰어서, IOC를 싣지 않은 기사(실측 31건 중 25건)에는 조사&대응이 아예
    # 붙지 않았다. 그런 기사에도 파일명·경로·행위 서술은 남아 있다.
    if not route["tracks"]:
        # 조사할 것이 없는 기사(칼럼·통계·행사)는 비는 것이 맞다. 문제는 지금까지
        # 카드가 조용히 사라져서 "기능이 고장난 것"과 구별되지 않았다는 점이다.
        # LLM이 왜 없는지를 함께 주므로 그것을 그대로 밝힌다.
        if targets and targets.get("investigable") is False:
            block["route"].update({
                "label": "조사 대상 없음",
                "explain": ("이 기사에는 조사할 지표가 없습니다{}. 도메인·해시·CVE·패키지 "
                            "어느 것도 나오지 않아 외부 조회로 확인할 것이 없고, 본문에서 "
                            "뽑을 탐지 재료도 없습니다. 기능이 동작하지 않은 것이 아니라 "
                            "조사할 대상이 없는 기사입니다.").format(
                                " — " + targets["reason"] if targets.get("reason") else ""),
            })
        else:
            block["route"].update({
                "label": "지표 없음 — 본문 기반 대응",
                "explain": ("기사에 도메인·해시 같은 지표가 없어 urlscan·VirusTotal 조사는 할 수 "
                            "없습니다. 대신 분석 본문에 나온 파일명·경로와 서술된 행위를 탐지 "
                            "쿼리로 만들어 뒀습니다."),
            })

    # 조사 과정은 트랙별로 모아 한 목록으로 합친다 — 두 트랙이 같이 돌면 어느 쪽
    # 작업인지 구분이 필요하다.
    steps = []

    run_lookups({"iocs": iocs, "text": text, "title": title, "route": route,
                 "urlscan_key": urlscan_key, "vt_key": vt_key, "targets": targets},
                block, steps)

    block.setdefault("patterns", [])

    # 여기까지는 미리 정해둔 규칙만 돌았다 — IOC 값 쿼리와 손으로 등록한 카탈로그다.
    # 그것만으로는 "본문에 적힌 이번 사건의 구체값"이 다음 사건에도 쓸 수 있는 형태로
    # 올라가지 않는다. 그 일반화는 LLM에게 맡기고, 나온 쿼리는 실제로 조회해서
    # 살아남은 것만 받는다(pattern_synth). 실패해도 나머지 결과는 그대로 낸다.
    if synthesize and (text or body):
        try:
            synth = pattern_synth.synthesize(title, text, body=body, iocs=iocs,
                                             api_key=urlscan_key)
            if synth.get("patterns"):
                block["patterns"] = list(block["patterns"]) + synth["patterns"]
            steps.extend({"track": "패턴 합성", "text": line}
                         for line in synth.get("steps") or [])
        except Exception as error:
            steps.append({"track": "패턴 합성", "text": "실패: {}".format(error)})

    block["steps"] = steps
    block.setdefault("seeds", [])
    block.setdefault("findings", [])
    block["steps_summary"] = summarize(block)
    # 대응 — 조사에서 나온 값과 본문의 구체값을 차단 목록·탐지 쿼리로 바꾼다.
    block["response"] = response_builder.build(block, iocs, primary=route["primary"], text=text)
    if not route["tracks"] and not block["response"]:
        # 이유를 말할 수 있으면 카드를 남긴다 — 빈 화면보다 "왜 없는지"가 낫다.
        if targets and targets.get("investigable") is False:
            block["steps"] = block.get("steps") or []
            block["steps_summary"] = block["route"]["explain"]
            return block
        return None      # 근거도 없이 비어 있으면 예전처럼 카드를 만들지 않는다
    return block


if __name__ == "__main__":
    import argparse
    import json
    import sys

    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="IOC로 조사&대응 블록을 만든다")
    parser.add_argument("--ioc", action="append", default=[],
                        help="type:value 형식(예: sha256:18c2..., url:https://...)")
    parser.add_argument("--text", default="", help="기사 본문(트랙 판단용)")
    parser.add_argument("--title", default="", help="기사 제목(판단 가중치가 크다)")
    parser.add_argument("--category", default="", help="기사 분류(예: 악성코드)")
    parser.add_argument("--body", default="", help="원문 발췌(패턴 합성 근거)")
    parser.add_argument("--no-synth", action="store_true", help="LLM 패턴 합성을 건너뛴다")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    iocs = []
    for raw in args.ioc:
        kind, _, value = raw.partition(":")
        iocs.append({"type": kind, "value": value if value else kind})

    result = build(iocs, text=args.text, title=args.title, category=args.category,
                   body=args.body, synthesize=not args.no_synth)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
    elif not result:
        print("조사할 IOC가 없습니다.")
    else:
        print("[분석 방향] {}\n  {}\n".format(result["route"]["label"], result["route"]["explain"]))
        if result.get("steps_summary"):
            print("[조사 과정 요약] " + result["steps_summary"])
            print()
        if result.get("steps"):
            print("[상세 과정]")
            for index, step in enumerate(result["steps"], 1):
                print(" {:>2}. ({}) {}".format(index, step["track"], step["text"]))
            print()
        for line in result.get("findings") or []:
            print(("   " if line.startswith("· ") else " ") + line)
        malware = result.get("malware") or {}
        if malware:
            print("\n[악성코드 동적 분석]")
            for line in malware.get("findings") or []:
                print(("   " if line.startswith("· ") else " ") + line)
