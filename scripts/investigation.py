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
import common_utils
import extension_hunter
import github_hunter
import intel_hunter
import lookup_plan
import lure_hunter
import past_analyses
import pattern_synth
import playbook
import primary_sources
import response_builder
import response_synth
import supply_chain_hunter
import vt_hunter
import vuln_hunter
import web_search

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
    # 보조 조회도 이름을 갖는다. 예전에는 넷만 있어서, 트랙 목록에 github·intel·web이
    # 섞이면 "판정 보류" 안내문을 만들다가 KeyError로 조사&대응이 통째로 사라졌다.
    "extension": "확장 프로그램 기반 — 스토어 조회",
    "github": "저장소 기반 — GitHub 조회",
    "intel": "교차 인텔 — OTX·Shodan·abuse.ch",
    "web": "공개 자료 — 웹 검색",
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


def classify(iocs, text="", title="", category="", targets=None, raw_body=""):
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
    # 저장소 주소가 있으면 그 저장소·계정·파일을 직접 본다. 예전에는 도메인만 보고
    # github.com이 정상 인프라라는 것만 확인하고 끝냈다.
    if github_hunter.refs_from(iocs, text, targets):
        tracks.append("github")
    # 확장 프로그램 ID가 본문에 있으면 스토어에 직접 조회한다. 공급망 기사인데
    # 패키지 레지스트리에는 없는 통로라, 이게 없으면 조사가 빈손으로 끝난다.
    if extension_hunter.ids_from_text(text, raw_body):
        tracks.append("extension")
    # 지표가 하나라도 있으면 다른 인텔리전스에도 물어본다 — 한 곳만 보는 것은 조사가
    # 아니라 조회다.
    # URL도 조회 대상이다 — URLhaus는 "이 주소가 유포지로 신고됐나"에 답하고, 그건
    # urlscan이 페이지 모양을 보는 것과 다른 질문이다.
    if domains or hashes or any((i.get("type") or "").lower() in
                                ("ip", "ipv4", "ip-dst", "ip-src", "url")
                                for i in iocs or []):
        tracks.append("intel")
    # 웹 검색은 키가 있을 때만 성립한다. 키가 없으면 트랙 자체를 만들지 않아, 계획도
    # 화면도 "없는 도구를 쓴다"고 말하지 않는다.
    if web_search.available() and web_search.terms_from(targets):
        tracks.append("web")

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

    # 모델이 선언한 주력 축이 있으면 규칙 판정보다 앞세운다.
    #
    # 왜 규칙만으로는 안 되는가
    #     주력 판정은 미리 적어 둔 정규식 어휘로만 돌아간다. 어휘에 없는 수법은 영원히
    #     못 맞추고, 실제로 그렇게 됐다(실측 44건): 공급망으로 분류된 기사 3건이 각각
    #     user_action·malware·user_action으로 갔고 supply_chain이 주력인 것은 0건이었다.
    #     결정 트리에서 supply_chain만 "strong_malware·strong_vuln이 없을 때"라는 조건을
    #     달고 있는데, strong_malware는 본문 전체에서 backdoor·loader·악성코드 같은 말을
    #     찾는다. 공급망 침해 기사는 유포된 페이로드를 반드시 설명하므로 이 조건이 거의
    #     항상 깨진다 — 본문이 길수록 불리해지는 구조였다(같은 기사도 요약만 넣으면
    #     supply_chain, 본문까지 넣으면 user_action이 나왔다).
    #
    #     어휘를 더 채우는 방법도 있지만 그건 새 수법이 나올 때마다 같은 일이 반복된다.
    #     기사를 읽고 "무엇을 끊어야 이 공격이 멈추는가"를 정하는 것은 판단이라 모델에
    #     맡기고, 코드는 그 선언대로 조사를 돌릴 수 있는지만 본다.
    declared = str(targets.get("primary") or "").strip()
    declared_note = ""
    if declared in TRACK_LABELS:
        if declared == "supply_chain" and "supply_chain" not in tracks:
            # 공급망 조사는 기사에 적힌 지표가 아니라 레지스트리 자체를 조회하므로
            # 지표가 없어도 돌아간다. 규칙이 제목에서 못 알아본 건을 선언이 메운다.
            tracks.append("supply_chain")
            supply_chain = True
        if declared in tracks:
            if declared != primary:
                declared_note = (
                    "주력 축을 {}으로 잡았습니다 — 기사를 읽고 판단한 결과이며, 표현만 "
                    "세는 규칙 판정({})과 다릅니다.".format(
                        TRACK_LABELS[declared].split(" — ")[0],
                        TRACK_LABELS[primary].split(" — ")[0] if primary in TRACK_LABELS
                        else "보류"))
            primary = declared
        else:
            # 선언은 있는데 그 조사를 돌릴 입력이 없다. 억지로 주력이라고 적으면
            # 화면에는 "공급망 기반"이라 쓰여 있는데 조회는 하나도 안 도는 일이 생긴다.
            declared_note = (
                "주력을 {}으로 보려 했지만 그 조사를 돌릴 입력이 없어 확보된 지표 "
                "기준으로 되돌립니다.".format(TRACK_LABELS[declared].split(" — ")[0]))

    if not primary and tracks:
        # 트랙은 있는데 주력을 못 정한 경우 — 무엇이 있는지만 알리고 판단은 넘긴다.
        available = " / ".join(
            TRACK_LABELS.get(track, track).split(" — ")[-1] for track in tracks)
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
            "declared_note": declared_note,
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
    if primary == "extension":
        explain = ("브라우저 확장이 통로인 유형입니다. 확장은 정상 개발자 계정이 넘어가면 "
                   "기존 사용자에게 악성 업데이트가 그대로 밀려 들어가므로, 기사에 적힌 ID가 "
                   "스토어에 아직 살아 있는지와 그 확장이 어떤 권한을 요구하는지를 직접 "
                   "조회합니다.")
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
        # 선언이 판정을 바꿨거나 못 바꿨으면 그 사실을 조사 과정에 남긴다.
        "declared_note": declared_note,
    }


# 조치를 언제 하느냐로 줄 세운다. 종합 판단은 시점을 주고(즉시·오늘·이번 주),
# 재료에서 나온 조치는 시점이 없다 — 지금은 그 둘이 화면의 다른 자리에 따로 있어
# 읽는 사람이 머리로 합쳐야 한다(실측 2026-09-18: 대응 24건 전부 그랬다).
WHEN_ORDER = ("즉시", "오늘", "이번 주", "이번주")
WHEN_FALLBACK = 90


def _when_rank(when):
    text = (when or "").strip()
    for index, label in enumerate(WHEN_ORDER):
        if label in text:
            return index
    # 날짜가 적힌 것(기한)은 이름표보다 뒤, 시점 없는 것보다는 앞에 둔다.
    return 10 if re.search(r"\d", text) else WHEN_FALLBACK


def merge_actions(verdict, response):
    """종합 판단의 계획과 재료에서 나온 조치를 시점 순 한 목록으로.

    같은 일을 두 번 적지 않는다 — 판단이 이미 말한 조치는 재료 쪽에서 뺀다. 판정은
    문장 앞부분이 겹치는지로 한다(재료 쪽 문장이 더 길고 뒤에 설명이 붙는다).
    """
    merged = []
    for step in (verdict or {}).get("plan") or []:
        action = " ".join(str(step.get("action") or "").split())
        if not action:
            continue
        merged.append({"action": action, "why": step.get("why") or "",
                       "when": step.get("when") or "", "source": "판단"})
    heads = {item["action"][:18] for item in merged}
    for raw in (response or {}).get("actions") or []:
        action = " ".join(str(raw).split())
        if not action or action[:18] in heads:
            continue
        merged.append({"action": action, "why": "", "when": "", "source": "재료"})
    merged.sort(key=lambda item: _when_rank(item["when"]))
    return merged


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


def _run_extension(ctx):
    # 확장 ID는 모델에게 묻지 않고 본문에서 직접 뽑는다 — 32자 a-p 문자열이라
    # 오인할 수 없는 형태다. 1차 자료에도 ID가 실리는 경우가 많아 함께 본다.
    ids = extension_hunter.ids_from_text(
        ctx["text"], ctx.get("body") or "", ctx.get("primary_text") or "")
    return extension_hunter.analyze(ids, objective=(ctx["targets"] or {}).get("objective") or "")


def _run_github(ctx):
    return github_hunter.analyze(ctx["iocs"], text=ctx["text"], targets=ctx["targets"])


def _run_intel(ctx):
    return intel_hunter.analyze(ctx["iocs"], targets=ctx["targets"])


def _run_web(ctx):
    # 다른 조회에서 이미 자료를 찾은 이름은 다시 검색하지 않는다 — 하루 한도가 있다.
    answered = []
    for hit in ((ctx.get("block") or {}).get("intel") or {}).get("references") or []:
        answered.append(hit)
    return web_search.analyze(ctx["targets"], answered=answered)


def _run_supply(ctx):
    return supply_chain_hunter.analyze(ctx["text"], title=ctx["title"], iocs=ctx["iocs"])


def _run_vuln(ctx):
    return vuln_hunter.analyze(ctx["route"]["cves"], text=ctx["text"],
                               products=ctx["route"].get("products"))


def _merge_named(key):
    def merge(block, track):
        block[key] = track
    return merge


# 1차 자료에서 가져올 지표 수. extract_iocs는 도메인을 먼저 담아서, 기본 상한(50)으로는
# 도메인만 50개 차고 해시가 잘려 나간다(실측: Anthropic 보고서에 도메인 36개가 먼저
# 잡히고 SHA-256 2개가 밀렸다).
PRIMARY_IOC_LIMIT = 200

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
    {"key": "extension", "label": "확장 프로그램 조회",
     "consumes": "브라우저 확장 ID(크롬 웹 스토어·엣지 애드온)", "run": _run_extension,
     "merge": _merge_named("extension")},
    {"key": "github", "label": "GitHub 조회",
     "consumes": "저장소 주소(owner/repo)", "run": _run_github,
     "merge": _merge_named("github")},
    {"key": "intel", "label": "교차 인텔 조회",
     "consumes": "도메인·IP·URL·해시(OTX·Shodan·RDAP·URLhaus·ThreatFox)",
     "run": _run_intel,
     "merge": _merge_named("intel")},
    {"key": "web", "label": "연구 자료 검색",
     "consumes": "캠페인·악성코드 이름·CVE(Google CSE)", "run": _run_web,
     "merge": _merge_named("web")},
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


# 후속 조회 — 종합 판단이 남긴 질문을 이미 가진 도구로 한 바퀴 더 돈다. 예전에는
# "남은 질문"을 만들어 놓고 거기서 멈췄다(실측: Magento 건이 남긴 질문 5개 중 3개는
# 우리가 가진 도구로 답할 수 있는 것이었다). 한 바퀴로 묶는 이유는 시간이다 —
# 기사 하나에 이미 400초가 넘게 든다.
def _run_followups(requests, urlscan_key=None, vt_key=None, block=None):
    """요청받은 값을 종류별로 조회해 판단 재료로 쓸 문장을 만든다.

    block을 주면 해시 후속 조회로 얻은 파일 정보를 악성코드 트랙에 합친다. 판단에
    쓸 한 줄만 뽑고 버리면 샌드박스 분석 링크가 사라져, "샘플이 있는데 어디서 보나"에
    답할 수 없다.
    """
    lines, steps = [], []
    for item in requests or []:
        kind, value = item.get("type"), item.get("value")
        question = item.get("question") or ""
        try:
            if kind in ("domain", "ip"):
                field = "page.domain" if kind == "domain" else "ip"
                results, total = lure_hunter.urlscan_search(
                    '{}:"{}"'.format(field, value), size=3, api_key=urlscan_key)
                hosts = [((r.get("page") or {}).get("domain") or "") for r in results]
                lines.append("{} {} — urlscan {}건{}".format(
                    kind, value, total,
                    "(예: " + ", ".join(h for h in hosts if h) + ")" if any(hosts) else ""))
            elif kind == "hash":
                track = vt_hunter.analyze_hashes([value], api_key=vt_key, iocs=[])
                found = (track or {}).get("findings") or []
                lines.append("해시 {} — {}".format(
                    value[:20], found[0][:160] if found else "VT에 결과 없음"))
                if block is not None and (track or {}).get("files"):
                    existing = block.get("malware")
                    if isinstance(existing, dict):
                        seen = {f.get("hash") for f in existing.get("files") or []}
                        existing["files"] = (existing.get("files") or []) + [
                            f for f in track["files"] if f.get("hash") not in seen]
                    else:
                        # 기사에 해시가 없어 악성코드 트랙이 아예 없던 건이다. 후속
                        # 조회로 샘플을 찾았으니 여기서 트랙이 생긴다.
                        block["malware"] = track
            elif kind == "cve":
                track = vuln_hunter.analyze([value], text="")
                found = (track or {}).get("findings") or []
                lines.append("{} — {}".format(
                    value, found[0][:160] if found else "조회 결과 없음"))
            elif kind == "package":
                ecosystem = "npm" if value.startswith("@") else "pip"
                info = supply_chain_hunter.lookup_package(ecosystem, value)
                lines.append("패키지 {} — 레지스트리 존재 {} · OSV {}건".format(
                    value, info.get("exists"), info.get("osv_count")))
            else:
                continue
            steps.append("후속 조회 \"{}\" — {} {}를 다시 확인했습니다.".format(
                question[:60], kind, value[:40]))
        except Exception as error:
            steps.append("후속 조회 실패({} {}): {}".format(kind, value[:30], str(error)[:50]))
    return lines, steps


def build(iocs, text="", urlscan_key=None, vt_key=None, title="", category="",
          body="", synthesize=True, targets=None, links=None, article_url=""):
    """조사&대응 블록. 트랙별 결과를 한 dict로 합친다.

    반환 형태는 기존(seeds/patterns/findings)을 그대로 유지하고 route·malware만
    추가한다 — 이미 저장된 분석 기록을 그리는 화면 코드가 깨지지 않게.
    """
    targets = targets or {}
    route = classify(iocs, text=text, title=title, category=category, targets=targets,
                     raw_body=body)
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
    # 주력 축을 모델 선언으로 바꿨거나 바꾸지 못했으면 그 사실을 맨 앞에 남긴다.
    # 조용히 바뀌면 "왜 이 축으로 봤나"를 되짚을 수 없다.
    if route.get("declared_note"):
        steps.append({"track": "분석 방향", "text": route["declared_note"]})

    # 기사가 인용한 1차 자료를 먼저 읽는다 — 2차 보도가 생략한 내용이 판단을 바꾼다
    # (실측: Sansec 원문 첫 줄에 기사가 "미할당"이라던 CVE 번호가 적혀 있었다).
    primary = {"sources": [], "steps": []}
    if links:
        try:
            primary = primary_sources.collect(links, article_url=article_url)
            steps.extend({"track": "원문 확인", "text": line}
                         for line in primary.get("steps") or [])
        except Exception as error:
            steps.append({"track": "원문 확인", "text": "실패: {}".format(error)})

    # 목표를 보고 어떤 조회를 돌릴지 고른다. 예전에는 지표 종류만 보고 정해서, 목표와
    # 무관한 조회가 돌고 시간을 썼다. 계획을 못 세우면 예전 방식 그대로다.
    if synthesize and targets.get("objective"):
        try:
            chosen = lookup_plan.plan(targets.get("objective"), targets.get("questions"),
                                      [{"key": l["key"], "label": l["label"],
                                        "consumes": l["consumes"]} for l in LOOKUPS],
                                      route, targets=targets)
            route["tracks"] = chosen["tracks"]
            steps.extend({"track": "조회 계획", "text": line}
                         for line in chosen.get("steps") or [])
        except Exception as error:
            steps.append({"track": "조회 계획", "text": "실패: {}".format(error)})

    # 1차 자료에서 읽은 글도 조회 재료다. 지표를 여기에만 싣는 연구 글이 많아서,
    # 넘기지 않으면 애써 받아온 IOC 표를 조회에 못 쓴다.
    #
    # 실측(2026-09-18, Anthropic 위협 보고서 기사): 기사 본문에는 지표가 한 개도 없어
    # 모델이 "조사 불가"로 판정했는데, 기사가 인용한 Anthropic 원문을 받아 보니
    # SHA-256 2개·MD5 1개·CVE 7개·도메인 36개가 들어 있었다. 받아 놓고 한 건도
    # 조회하지 않았다 — 트랙이 기사 본문만 보고 정해진 뒤였기 때문이다.
    primary_text = " ".join(src.get("text") or "" for src in primary.get("sources") or [])
    if primary_text:
        known = {str(item.get("value") or "").lower() for item in iocs or []}
        fresh = [item for item in common_utils.extract_iocs(
            primary_text, limit=PRIMARY_IOC_LIMIT)
            if str(item.get("value") or "").lower() not in known]
        if fresh:
            iocs = list(iocs or []) + fresh
            kinds = {}
            for item in fresh:
                kinds[item["type"]] = kinds.get(item["type"], 0) + 1
            # 지표가 늘었으니 트랙을 다시 정한다. 주력 축은 모델 선언이 우선이라
            # 여기서 바뀌지 않는다.
            route = classify(iocs, text=text, title=title, category=category,
                             targets=targets, raw_body=" ".join([body, primary_text]))
            block["route"] = {key: route[key] for key in
                              ("primary", "label", "explain", "tracks", "scores")}
            steps.append({"track": "조사 방향",
                          "text": "1차 자료에서 지표 {}건을 더 찾아 조회 대상에 넣었습니다"
                                  "({}) — 기사 본문에는 없던 값입니다.".format(
                                      len(fresh),
                                      ", ".join("{} {}건".format(k, v)
                                                for k, v in sorted(kinds.items())))})
    run_lookups({"iocs": iocs, "text": text, "title": title, "route": route,
                 "urlscan_key": urlscan_key, "vt_key": vt_key, "targets": targets,
                 "body": body, "primary_text": primary_text, "block": block},
                block, steps)

    block.setdefault("patterns", [])

    # 여기까지는 미리 정해둔 규칙만 돌았다 — IOC 값 쿼리와 손으로 등록한 카탈로그다.
    # 그것만으로는 "본문에 적힌 이번 사건의 구체값"이 다음 사건에도 쓸 수 있는 형태로
    # 올라가지 않는다. 그 일반화는 LLM에게 맡기고, 나온 쿼리는 실제로 조회해서
    # 살아남은 것만 받는다(pattern_synth). 실패해도 나머지 결과는 그대로 낸다.
    if synthesize and (text or body):
        try:
            synth = pattern_synth.synthesize(title, text, body=body, iocs=iocs,
                                             api_key=urlscan_key, targets=targets)
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

    # 마지막으로 조회 결과 전체를 읽고 판단한다. 여기까지는 값이 있으면 문장을 붙이는
    # 조립이었고, "그래서 무엇을 해야 하는가"를 정하는 단계가 없었다. 실패해도 앞의
    # 결과는 그대로 낸다 — 판단이 없어도 재료는 쓸 수 있다.
    # 이 유형이 요구하는 산출물을 다 냈는지 대조한다. 빠진 것을 밝히지 않으면
    # "완벽히 대응했다"를 확인할 방법이 없다 — 조용히 없는 것과 원래 필요 없는 것이
    # 구별되지 않는다.
    try:
        # 내가 만든 유형 목록이 아니라, 모델이 목표를 세울 때 선언한 기준으로 본다.
        cover = playbook.coverage(block, targets.get("criteria"))
        if cover:
            block["coverage"] = cover
            steps.extend({"track": "산출물 점검", "text": line}
                         for line in playbook.coverage_steps(cover))
        # 어휘로 표현할 수 없어 약속에 못 넣은 것. 검증 대상은 아니지만 숨기지 않는다 —
        # "우리 도구로 여기까지"가 어디인지 카드에 남아야 다음에 무엇을 만들지 알 수 있다.
        gaps = [g for g in (targets.get("gaps") or []) if str(g).strip()]
        if gaps:
            block["gaps"] = gaps
            steps.append({"track": "산출물 점검",
                          "text": "이 대응을 완결하려면 더 필요하다고 본 것 {}가지 — "
                                  "지금 우리 도구로는 닿지 않습니다: {}.".format(
                                      len(gaps), "; ".join(gaps[:3]))})
    except Exception as error:
        steps.append({"track": "산출물 점검", "text": "실패: {}".format(error)})

    if synthesize:
        try:
            # 교차 조회가 찾아 준 참고 링크(다른 연구자의 보고서)도 원문으로 읽는다.
            # 기사가 인용하지 않은 자료라 여기서만 얻을 수 있다.
            intel_refs = (((block.get("intel") or {}).get("references") or [])
                          + ((block.get("web") or {}).get("references") or []))
            if intel_refs:
                try:
                    more = primary_sources.collect(
                        [{"url": u} for u in intel_refs], article_url=article_url, limit=1)
                    primary["sources"] = (primary.get("sources") or []) + more["sources"]
                    steps.extend({"track": "원문 확인", "text": line}
                                 for line in more.get("steps") or [])
                except Exception as error:
                    steps.append({"track": "원문 확인",
                                  "text": "참고 링크 원문 확인 실패: {}".format(error)})
            # 읽은 1차 자료를 블록에 남긴다. 남기지 않으면 산출물 점검이 "공개 분석·
            # 1차 자료"를 미달로 찍는다 — 실제로는 읽었는데도(실측: socket.dev·
            # DomainTools 2건을 읽고 external_reports 미달).
            if primary.get("sources"):
                block["primary"] = {"sources": [
                    {"url": source.get("url") or "", "host": source.get("host") or "",
                     "chars": source.get("chars") or 0}
                    for source in primary["sources"]]}
            # 같은 계열의 과거 분석을 붙인다. 44건이 쌓여 있는데 어느 단계도 보지
            # 않고 있었다 — 같은 수법이 반복되는지는 기록에서만 보인다.
            related = []
            try:
                related = past_analyses.find_related(targets, exclude_title=title)
                if related:
                    block["related"] = related
                    steps.extend({"track": "과거 분석", "text": line}
                                 for line in past_analyses.steps(related))
            except Exception as error:
                steps.append({"track": "과거 분석", "text": "조회 실패: {}".format(error)})
            evidence = primary_sources.as_evidence(primary.get("sources"))
            verdict = response_synth.synthesize(
                title, text, targets, block, primary=evidence,
                history=past_analyses.as_evidence(related))
            # URLhaus가 URL에서 알려 준 페이로드 해시. 기사에 없던 값이라 판단이
            # 요청할 수 없지만, 샘플 확보로 바로 이어지는 것이라 우리가 넣는다.
            auto = []
            known = {str(item.get("value") or "").lower() for item in iocs or []}
            for value in ((block.get("intel") or {}).get("discovered_hashes") or []):
                if value.lower() not in known:
                    auto.append({"type": "hash", "value": value,
                                 "question": "URLhaus가 이 URL의 페이로드로 준 해시가 "
                                             "실제 무엇인지"})
            pending = (verdict.get("followups") or []) if verdict else []
            pending = auto + list(pending)
            # 판단이 남긴 질문 중 우리 도구로 답할 수 있는 것을 한 바퀴 더 조회하고,
            # 그 결과로 판단을 다시 받는다. 새로 얻은 것이 없으면 다시 받지 않는다.
            if pending:
                extra_lines, extra_steps = _run_followups(
                    pending, urlscan_key=urlscan_key, vt_key=vt_key, block=block)
                steps.extend({"track": "후속 조회", "text": line} for line in extra_steps)
                if extra_lines:
                    again = response_synth.synthesize(
                        title, text, targets, block, primary=evidence,
                        extra="\n".join(extra_lines),
                        history=past_analyses.as_evidence(related))
                    if again:
                        again["followup_evidence"] = extra_lines
                        # 2차 판단이 새로 낸 후속 조회 요청은 버린다. 한 바퀴만 돌기로
                        # 했으니 그것들은 실행되지 않는데, 남겨 두면 화면에서
                        # "요청한 것과 다른 것을 조회했다"로 읽힌다(실측: 요청 4건과
                        # 실행 4건이 하나도 겹치지 않았다). 실행한 것만 남긴다.
                        again["followups"] = pending
                        verdict = again
            if verdict:
                block["synthesis"] = verdict
                block["action_plan"] = merge_actions(verdict, block.get("response"))
                steps.extend({"track": "종합 판단", "text": line}
                             for line in verdict.get("steps") or [])
                block["steps"] = steps
        except Exception as error:
            steps.append({"track": "종합 판단", "text": "실패: {}".format(error)})
            block["steps"] = steps
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
