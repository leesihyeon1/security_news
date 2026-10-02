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

import os
import re
import time

import analysis_targets
import article_kind
import briefing
import common_utils
import incident_scope
import extension_hunter
import goal_evidence
import github_hunter
import intel_hunter
import lookup_plan
import lure_hunter
import output_critic
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
import worker_progress
import source_evidence
import analyst_workflow
import browser_research
import research_actions
import research_entities

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


def classify(iocs, text="", title="", category="", targets=None, raw_body="",
             pinned=""):
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

    # 전에 이 기사를 분석하며 정한 축이 있으면 그것을 지킨다. 선언보다도 앞선다 —
    # 모델은 매번 새로 읽으므로 같은 본문에서도 답이 달라지고, 그때마다 조회 계획이
    # 통째로 바뀌면 재분석이 "다시 본 것"이 아니라 "다른 것"이 된다.
    if pinned and pinned in TRACK_LABELS and pinned != primary:
        if pinned == "supply_chain" and "supply_chain" not in tracks:
            tracks.append("supply_chain")
            supply_chain = True
        if pinned in tracks:
            declared_note = (
                "주력 축은 이전 분석에서 정한 {}을 그대로 씁니다 — 이번 판단은 {}이었지만, "
                "같은 기사를 볼 때마다 축이 바뀌면 재분석 결과를 앞의 것과 견줄 수 "
                "없습니다.".format(
                    TRACK_LABELS[pinned].split(" — ")[0],
                    TRACK_LABELS[primary].split(" — ")[0] if primary in TRACK_LABELS
                    else "보류"))
            primary = pinned

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


# 조치 문장에서 "무엇을 어떻게"만 뽑는 어휘.
ACTION_VERBS = {
    "차단": ("차단", "블록", "블랙리스트"),
    "패치": ("패치", "업데이트", "버전 올"),
    "헌팅": ("헌팅", "쿼리", "역추적", "탐지 룰", "탐지룰", "시그니처"),
    "격리": ("격리", "삭제", "제거", "언인스톨"),
    "폐기": ("폐기", "회수", "재발급", "교체", "초기화"),
}
ACTION_OBJECTS = {
    "도메인": ("도메인", "url", "주소", "인프라"),
    "해시": ("해시", "파일", "샘플", "바이너리"),
    "ip": ("ip", "아이피"),
    "취약점": ("cve", "취약점"),
    "패키지": ("패키지", "레지스트리", "의존성"),
    "확장": ("확장",),
    "계정": ("계정", "토큰", "자격증명", "세션", "비밀번호"),
}


# 이 동작만 겹치면 지운다. 차단·헌팅은 판단이 같은 말을 거의 항상 하고 재료 쪽이
# 덧붙이는 것이 없다. 반면 패치·격리·폐기는 재료 문장이 판단에 없는 구체를 싣는다 —
# 실측(저장분 50건): "KEV 등재 1건(CVE-2026-75650)은 실제 악용이 확인된 것이다",
# "지속성(예약 작업·Run 키)까지 제거해야 재감염이 끊긴다"가 그렇게 지워질 뻔했다.
DEDUP_VERBS = {"차단", "헌팅"}


def _action_signature(text):
    """조치 문장을 (동작, 대상) 쌍의 집합으로. 표현이 달라도 같은 일이면 겹친다."""
    low = str(text or "").lower()
    verbs = {name for name, words in ACTION_VERBS.items()
             if any(word in low for word in words)}
    objects = {name for name, words in ACTION_OBJECTS.items()
               if any(word in low for word in words)}
    return {(verb, obj) for verb in verbs for obj in objects}


def merge_actions(verdict, response):
    """종합 계획을 시점 순으로 표시하고, 없으면 재료를 검토 후보로 표시한다."""
    merged = []
    for step in (verdict or {}).get("plan") or []:
        action = " ".join(str(step.get("action") or "").split())
        if not action:
            continue
        merged.append(analyst_workflow.display_plan(step))
    # Material snippets remain in response.actions; they are not executable plans.
    if merged:
        merged.sort(key=lambda item: _when_rank(item.get("when") or ""))
        return merged
    seen = set()
    for raw in (response or {}).get("actions") or []:
        action = " ".join(str(raw).split())
        if not action or action in seen:
            continue
        seen.add(action)
        merged.append({"action": action,
                       "why": "판단 미완료: 재료에서 얻은 조사 후보입니다. 담당자·영향 범위·증거 보존·대안을 먼저 정합니다.",
                       "when": "검토 후", "done": "사내 로그로 실행 조건과 완료 기준을 확인하기 전에는 종결하지 않습니다.",
                       "source": "재료", "readiness": "review_required"})
    merged.sort(key=lambda item: _when_rank(item["when"]))
    return merged


# 교차 인텔 관측 중 "있다"는 쪽. 없다는 문장("…없습니다", "…않습니다")은 세지 않는다.
INTEL_HIT_RE = re.compile(r"커뮤니티 보고서 \d+건에 실려|등재돼 있습니다|ThreatFox 항목|신고된 URL \d+건")
INTEL_FAMILY_RE = re.compile(r"귀속:\s*([^.]+)")


def _malware_outcome(malware):
    files = malware.get("files") or []
    if not files:
        return ""
    if not malware.get("checked"):
        return "파일 해시 {}건 — VT 키가 없어 링크만 준비".format(malware.get("total_hashes") or len(files))
    verdicts = []
    for entry in files:
        report = entry.get("report") or {}
        malicious = report.get("malicious")
        if isinstance(malicious, int) and malicious > 0:
            label = str(report.get("label") or "악성").split("/")[0]
            engines = report.get("engines")
            verdicts.append("{} {}{}".format(
                label, malicious, "/{}".format(engines) if isinstance(engines, int) and engines else ""))
    return "VT 동적 분석 {}건 — {}".format(
        len(files), "악성 판정 " + ", ".join(verdicts[:3]) if verdicts else "악성 판정 없음")


def _intel_outcome(intel):
    findings = intel.get("findings") or []
    if not findings:
        return ""
    hits = [line for line in findings if INTEL_HIT_RE.search(line) and "않습니다" not in line]
    families = []
    for line in hits:
        match = INTEL_FAMILY_RE.search(line)
        for name in (match.group(1).split(",") if match else []):
            name = name.strip()
            if name and name not in families:
                families.append(name)
    if not hits:
        return "교차 인텔 — 공개 보고·등재 없음"
    return "교차 인텔 — 공개 보고·등재 {}건{}".format(
        len(hits), "(귀속 {})".format(", ".join(families[:3])) if families else "")


def _url_outcome(seeds):
    if not seeds:
        return ""
    confirmed = sum(1 for seed in seeds if seed.get("dom_confirmed"))
    empty = sum(1 for seed in seeds if seed.get("empty_response_hosts"))
    infected = {c.get("domain") for seed in seeds for c in seed.get("candidates") or []
                if lure_hunter.INFECTED_SITE_PIVOT in " ".join(c.get("reasons") or [])}
    bits = ["유포지 코드 확인 {}곳".format(confirmed) if confirmed else "유포지 코드 미확인"]
    if empty:
        bits.append("빈 응답(원인 미확인) {}곳".format(empty))
    if infected:
        bits.append("감염 사이트 후보 {}곳".format(len(infected)))
    return "urlscan 도메인 {}곳 — {}".format(len(seeds), ", ".join(bits))


def summarize(block):
    """조사 과정을 한두 문장으로 — 무엇을 돌렸는지가 아니라 각 조회에서 무엇이 나왔는지.

    예전에는 "도메인 3곳 조회·해시 2건 VT·쿼리 37개 확보"처럼 한 일의 양만 셌다(실측
    2026-09-28, Lunex 건 — 85단계를 돌고도 요약에는 결과가 한 마디도 없었다). 조회마다
    결과를 한 조각씩 뽑고, 판단이 있으면 그 결론의 크기(확인·미확인·질문 상태)를 앞에
    둔다. 단계 문장을 다시 파싱하지 않고 결과물에서 센다 — 문구가 바뀌어도 요약이
    어긋나지 않는다. 판단이 붙은 뒤 build()가 한 번 더 부른다.
    """
    parts = []
    synthesis = block.get("synthesis") or {}
    if synthesis:
        questions = synthesis.get("question_status") or []
        status = {key: sum(1 for row in questions if row.get("status") == key)
                  for key in ("answered", "partial", "open")}
        bits = ["확인 {}건".format(len(synthesis.get("confirmed") or [])),
                "미확인 {}건".format(len(synthesis.get("unconfirmed") or []))]
        if questions:
            bits.append("검증 질문 {}개 중 확인 {}·부분 {}·미해결 {}".format(
                len(questions), status["answered"], status["partial"], status["open"]))
        parts.append("판단 {} — {}".format(synthesis.get("verdict") or "-", ", ".join(bits)))

    sources = (block.get("primary") or {}).get("sources") or []
    if sources:
        hosts = list(dict.fromkeys(str(s.get("host") or "").replace("www.", "") for s in sources))
        parts.append("1차 자료 {}건 읽음({})".format(len(sources), ", ".join(h for h in hosts[:3] if h)))
    for piece in (_malware_outcome(block.get("malware") or {}),
                  _intel_outcome(block.get("intel") or {}),
                  _url_outcome(block.get("seeds") or [])):
        if piece:
            parts.append(piece)
    cves = (block.get("vulnerability") or {}).get("cves") or []
    if cves:
        kev = sum(1 for entry in cves if (entry.get("kev") or {}).get("added"))
        parts.append("취약점 {}건 — KEV 등재 {}건".format(len(cves), kev))
    web_refs = (block.get("web") or {}).get("references") or []
    if web_refs:
        parts.append("연구 자료 {}건 찾음".format(len(web_refs)))

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
        ctx["iocs"], api_key=ctx["urlscan_key"], text=ctx["text"],
        web_files=lure_hunter.web_files_from(ctx["targets"]),
        primary=(ctx.get("route") or {}).get("primary") or "",
        article_url=ctx.get("article_url") or "")


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
    texts = (ctx["text"], ctx.get("body") or "", ctx.get("primary_text") or "")
    ids = extension_hunter.ids_from_text(*texts)
    # 같은 ID라도 "악성 확장"인지 "탈취 대상 지갑"인지는 문맥이 가른다 — 원문(body·1차
    # 자료)만 본다. 우리말 분석문(text)은 모델이 옮겨 쓴 것이라 역할 근거로 삼지 않는다.
    roles = extension_hunter.roles_from_text(ctx.get("body") or "", ctx.get("primary_text") or "")
    return extension_hunter.analyze(ids, objective=(ctx["targets"] or {}).get("objective") or "",
                                    roles=roles)


def _run_github(ctx):
    return github_hunter.analyze(ctx["iocs"], text=ctx["text"], targets=ctx["targets"])


def _run_intel(ctx):
    # OTX는 해시 하나당 응답이 크고 최대 2회 재시도한다. 대표 샘플을 고른
    # 계획이 있으면 그 해시만 교차 조회하고, 도메인·IP는 그대로 확인한다.
    # 전체 해시는 IOC·헌팅 목록에 이미 보존되어 있어 조사 범위를 줄여도 값이
    # 사라지지 않는다.
    selected = {str(value).lower() for value in ctx.get("route", {}).get("hashes") or []}
    if selected:
        selected_iocs = []
        hash_types = {"md5", "sha1", "sha256"}
        for item in ctx["iocs"]:
            kind = str(item.get("type") or "").lower()
            value = str(item.get("value") or "")
            if kind not in hash_types or value.lower() in selected:
                selected_iocs.append(item)
        return intel_hunter.analyze(selected_iocs, targets=ctx["targets"])
    return intel_hunter.analyze(ctx["iocs"], targets=ctx["targets"])


def _run_web(ctx):
    # 다른 조회에서 이미 자료를 찾은 이름은 다시 검색하지 않는다 — 하루 한도가 있다.
    answered = []
    for hit in ((ctx.get("block") or {}).get("intel") or {}).get("references") or []:
        answered.append(hit)
    return web_search.analyze(ctx["targets"], answered=answered)


def _run_supply(ctx):
    return supply_chain_hunter.analyze(ctx["text"], title=ctx["title"], iocs=ctx["iocs"],
                                      targets=ctx["targets"])


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

# 종합 판단을 몇 라운드까지 반복할지 — 1차 판단 포함 총 라운드 수다. 기본값 2는
# 기존 동작(1차 판단 + 후속 조회 1회)과 같은 상한이라 비용이 늘지 않는다. 질문이
# 다 풀리거나 새로 얻은 것이 없으면 상한 전에 먼저 멈춘다.
MAX_INVESTIGATION_ROUNDS = int(os.environ.get("INVESTIGATION_MAX_ROUNDS", "2"))
MAX_FOLLOWUP_SOURCES = 2
MAX_FOLLOWUP_SOURCE_IOCS = 4
MAX_FOLLOWUP_LOOKUPS = 6
INVESTIGATION_SOFT_BUDGET_SECONDS = 180


def _collect_primary(links, **kwargs):
    client, ref = worker_progress.current()
    digest = worker_progress.fingerprint(links, kwargs)
    cached = worker_progress.load(client, ref, "sources:" + digest[:12], digest)
    if cached is not None:
        return cached
    result = primary_sources.collect(links, **kwargs)
    if result.get("sources"):
        worker_progress.save(client, ref, "sources:" + digest[:12], digest, result)
    return result

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
    catalog = {lookup["key"]: lookup for lookup in LOOKUPS}
    statuses = block.setdefault("lookup_status", [])
    stage_client, stage_ref = worker_progress.current()
    for key in dict.fromkeys(ctx["route"]["tracks"]):
        lookup = catalog.get(key)
        if lookup is None:
            continue
        status = {"key": key, "started_at": common_utils.utc_now_iso()}
        statuses.append(status)
        digest = worker_progress.fingerprint(
            key, ctx.get("iocs"), ctx.get("route"), ctx.get("targets"),
            ctx.get("primary_text"), ctx.get("article_url"),
            bool(ctx.get("urlscan_key")), bool(ctx.get("vt_key")))
        track = worker_progress.load(stage_client, stage_ref, "lookup:" + key, digest)
        try:
            if track is None:
                track = lookup["run"](ctx)
            else:
                status["reused"] = True
        except Exception as error:
            status.update(status="failed", detail="조회 예외: " + type(error).__name__,
                          completed_at=common_utils.utc_now_iso())
            steps.append({"track": lookup["label"],
                          "text": "조회 실패({}) — 이 트랙 결과는 비어 있습니다.".format(
                              str(error)[:70])})
            continue
        if not track:
            status.update(status="unavailable", detail="사용 가능한 응답 없음; 미탐지와 구분",
                          completed_at=common_utils.utc_now_iso())
            steps.append({"track": lookup["label"],
                          "text": "{}로 조회했지만 결과가 없었습니다.".format(lookup["consumes"])})
            continue
        partial = any(re.search(r"실패|못했|못해|받지 못|키.*(?:없|미설정)|응답 없음|403|429|timeout", str(line), re.I)
                      for line in track.get("steps") or [])
        status.update(status="partial" if partial else "returned",
                      detail="일부 조회 실패 포함" if partial else "응답 수집됨; 각 관측의 범위는 별도 판단",
                      completed_at=common_utils.utc_now_iso())
        if not partial and not status.get("reused"):
            worker_progress.save(stage_client, stage_ref, "lookup:" + key, digest, track)
        lookup["merge"](block, track)
        if track.get("generated_at"):
            block.setdefault("generated_at", track["generated_at"])
        steps.extend({"track": lookup["label"], "text": line}
                     for line in track.get("steps") or [])


# 후속 조회 — 종합 판단이 남긴 질문을 이미 가진 도구로 한 바퀴 더 돈다. 예전에는
# "남은 질문"을 만들어 놓고 거기서 멈췄다(실측: Magento 건이 남긴 질문 5개 중 3개는
# 우리가 가진 도구로 답할 수 있는 것이었다). 한 바퀴로 묶는 이유는 시간이다 —
# 기사 하나에 이미 400초가 넘게 든다.
def _corroborate_roles(block, steps):
    """조회 결과(샌드박스 통신·urlscan DOM)로 역할 미확인 지표를 확정 후보로 올린다.

    source_evidence.corroborate 참고. 바뀐 것은 조사 과정에 남기고, 판단 재료로도
    쓸 수 있게 문장으로 돌려준다.
    """
    lines = []
    for item in source_evidence.corroborate(block):
        label = source_evidence.ROLE_LABELS.get(item["role"], item["role"])
        line = "{}: {}. {}".format(item["value"], label, item.get("evidence") or "")
        steps.append({"track": "지표 역할 검토", "text": line})
        lines.append(line)
    return lines


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
        before = len(lines)
        try:
            if kind in ("domain", "ip"):
                field = "page.domain" if kind == "domain" else "ip"
                results, total = lure_hunter.urlscan_search(
                    '{}:"{}"'.format(field, value), size=5, api_key=urlscan_key)
                # 물어본 것은 "지금도 살아 있나"다. 건수와 마지막 관측일이 그 답이고,
                # 결과의 도메인 이름은 아니다 — 도메인으로 검색했으니 찾은 것도 같은
                # 도메인이라, 예전에는 "(예: a.com, a.com, a.com)"이 찍혔다.
                times = sorted(((r.get("task") or {}).get("time") or "")[:10]
                               for r in results if (r.get("task") or {}).get("time"))
                if not total:
                    lines.append("{} {} — urlscan에 관측 기록이 없습니다.".format(kind, value))
                else:
                    seen_hosts = sorted({((r.get("page") or {}).get("domain") or "")
                                         for r in results
                                         if ((r.get("page") or {}).get("domain") or "")
                                         and (r.get("page") or {}).get("domain") != value})
                    lines.append("{} {} — urlscan 관측 {}건{}{}".format(
                        kind, value, total,
                        ", 마지막 {}".format(times[-1]) if times else "",
                        ", 같은 자리에서 관측된 다른 호스트: "
                        + ", ".join(seen_hosts[:3]) if seen_hosts else ""))
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
                if block is not None and track:
                    existing = block.setdefault("vulnerability", {"cves": [], "findings": []})
                    by_id = {entry["cve"]: entry for entry in existing.get("cves") or []}
                    by_id.update({entry["cve"]: entry for entry in track.get("cves") or []})
                    existing["cves"] = list(by_id.values())
                    existing["findings"] = [line for entry in existing["cves"]
                                            for line in vuln_hunter._findings_for_cve(entry)]
            elif kind == "package":
                ecosystem = item.get("ecosystem")
                if ecosystem not in ("npm", "pip"):
                    steps.append("패키지 {} — 생태계 미확인으로 후속 조회를 보류했습니다.".format(value))
                    continue
                info = supply_chain_hunter.lookup_package(ecosystem, value)
                lines.append("패키지 {} — 레지스트리 존재 {} · OSV {}건".format(
                    value, info.get("exists"), info.get("osv_count")))
            else:
                continue
            steps.append("후속 조회 \"{}\" — {} {}를 다시 확인했습니다.".format(
                question[:60], kind, value[:40]))
            if block is not None:
                block.setdefault("followup_results", []).append({
                    "type": kind, "value": value, "question": question,
                    "lookup": {"domain": "urlscan", "ip": "urlscan", "hash": "virustotal",
                               "cve": "nvd", "package": "registry"}[kind],
                    "status": "returned", "result": lines[before] if len(lines) > before else "",
                })
        except Exception as error:
            steps.append("후속 조회 실패({} {}): {}".format(kind, value[:30], str(error)[:50]))
            if block is not None:
                block.setdefault("followup_results", []).append({
                    "type": kind, "value": value, "question": question,
                    "status": "failed", "result": "조회 실패: {}".format(str(error)[:80]),
                })
    return lines, steps


def build(iocs, text="", urlscan_key=None, vt_key=None, title="", category="",
          body="", synthesize=True, targets=None, links=None, article_url="",
          shared_primary=None, incident_label=""):
    """조사&대응 블록. 트랙별 결과를 한 dict로 합친다.

    반환 형태는 기존(seeds/patterns/findings)을 그대로 유지하고 route·malware만
    추가한다 — 이미 저장된 분석 기록을 그리는 화면 코드가 깨지지 않게.

    shared_primary·incident_label은 build_for_article()이 종합 기사를 사건별로
    나눠 이 함수를 여러 번 부를 때만 쓴다 — 둘 다 기본값(None/"")이면 이 함수는
    지금까지와 완전히 같게 동작한다. shared_primary를 주면 (이미 기사 레벨에서 한
    번 수집한) 1차 자료를 재사용해, 사건마다 같은 링크를 다시 수집하지 않는다.
    incident_label을 주면 반환 직전에 steps의 track과 response 차단목록의 label
    앞에 "[라벨]"을 붙여, 여러 사건의 결과를 하나로 합쳤을 때 어느 사건 것인지
    구분할 수 있게 한다.
    """
    started = time.monotonic()
    targets = targets or {}
    article_url = source_evidence.article_url(article_url)
    source_urls = [article_url] if article_url else []
    iocs, _ = source_evidence.filter_iocs(iocs, source_urls)
    targets = source_evidence.filter_targets(targets, source_urls)
    documents = [{"url": article_url, "text": body}]
    assessed = source_evidence.assess_iocs(iocs, documents)
    iocs = source_evidence.lookup_iocs(assessed)
    targets = source_evidence.restrict_targets(targets, assessed)
    # 이 기사를 전에 분석했다면 그때 정한 축을 가져온다. 한 번만 읽어 재분류까지 쓴다.
    pinned = ""
    try:
        pinned = past_analyses.stored_axis(title)
    except Exception:
        pinned = ""
    route = classify(iocs, text=text, title=title, category=category, targets=targets,
                     raw_body=body, pinned=pinned)
    block = {"route": {key: route[key]
                       for key in ("primary", "label", "explain", "tracks", "scores")}}
    block["source_urls"] = source_urls
    block["targets"] = targets
    block["indicator_assessments"] = assessed

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
    primary = shared_primary if shared_primary is not None else {"sources": [], "steps": []}
    if links and shared_primary is None:
        try:
            primary = _collect_primary(links, article_url=article_url)
            block.setdefault("lookup_status", []).extend(primary.get("attempts") or [])
            steps.extend({"track": "원문 확인", "text": line}
                         for line in primary.get("steps") or [])
        except Exception as error:
            block.setdefault("lookup_status", []).append({"key": "primary", "status": "failed",
                                                           "detail": "원문 수집 예외: " + type(error).__name__})
            steps.append({"track": "원문 확인", "text": "실패: {}".format(error)})

    # 1차 자료에서 읽은 글도 조회 재료다. 지표를 여기에만 싣는 연구 글이 많아서,
    # 넘기지 않으면 애써 받아온 IOC 표를 조회에 못 쓴다.
    #
    # 실측(2026-09-18, Anthropic 위협 보고서 기사): 기사 본문에는 지표가 한 개도 없어
    # 모델이 "조사 불가"로 판정했는데, 기사가 인용한 Anthropic 원문을 받아 보니
    # SHA-256 2개·MD5 1개·CVE 7개·도메인 36개가 들어 있었다. 받아 놓고 한 건도
    # 조회하지 않았다 — 트랙이 기사 본문만 보고 정해진 뒤였기 때문이다.
    source_urls.extend(src["url"] for src in primary.get("sources") or [] if src.get("url"))
    iocs, _ = source_evidence.filter_iocs(iocs, source_urls)
    targets = source_evidence.filter_targets(targets, source_urls)
    primary_text = " ".join(src.get("text") or "" for src in primary.get("sources") or [])
    if primary_text:
        known = {str(item.get("value") or "").lower() for item in iocs or []}
        fresh = [item for item in common_utils.extract_iocs(
            primary_text, limit=PRIMARY_IOC_LIMIT)
            if str(item.get("value") or "").lower() not in known]
        fresh, _ = source_evidence.filter_iocs(fresh, source_urls)
        if fresh:
            assessed = source_evidence.assess_iocs(list(assessed) + fresh,
                                                   documents + (primary.get("sources") or []))
            block["indicator_assessments"] = assessed
            iocs = source_evidence.lookup_iocs(assessed)
            targets = source_evidence.restrict_targets(targets, assessed)
            kinds = {}
            for item in fresh:
                kinds[item["type"]] = kinds.get(item["type"], 0) + 1
            # 지표가 늘었으니 트랙을 다시 정한다. 주력 축은 모델 선언이 우선이라
            # 여기서 바뀌지 않는다.
            route = classify(iocs, text=text, title=title, category=category,
                             targets=targets, raw_body=" ".join([body, primary_text]),
                             pinned=pinned)
            block["route"] = {key: route[key] for key in
                              ("primary", "label", "explain", "tracks", "scores")}
            steps.append({"track": "조사 방향",
                          "text": "1차 자료에서 지표 {}건을 더 찾아 조회 대상에 넣었습니다"
                                  "({}) — 기사 본문에는 없던 값입니다.".format(
                                      len(fresh),
                                      ", ".join("{} {}건".format(k, v)
                                                for k, v in sorted(kinds.items())))})
    # Plan once after source enrichment, so reclassification cannot erase the plan.
    if synthesize and targets.get("objective"):
        try:
            chosen = lookup_plan.plan(targets.get("objective"), targets.get("questions"),
                                      [{"key": l["key"], "label": l["label"],
                                        "consumes": l["consumes"]} for l in LOOKUPS],
                                      route, targets=targets, evidence=body[:4000] + "\n" + primary_text[:3500]
                                      + "\n[원문 후반·표]\n" + primary_text[-3000:])
            route["tracks"] = chosen["tracks"]
            block["question_lookups"] = chosen.get("question_lookups") or []
            if chosen.get("hashes") or route.get("hashes"):
                # 1차 자료의 전체 해시는 IOC·헌팅 목록에 남기되, VT 동적 분석은
                # 계획이 고른 대표 버전만 본다. 11개 버전을 전부 순차 조회하면 외부
                # API 지연으로 종합 판단까지 도달하지 못하고, 대표 샘플을 고르는
                # 목표도 무시하게 된다.
                all_hashes = list(route.get("hashes") or [])
                requested_hashes = chosen.get("hashes") or all_hashes
                evidence_for_samples = "\n".join([body[:5000], primary_text[:5000]])
                route["hashes"] = research_entities.sample_order(
                    requested_hashes, evidence=evidence_for_samples, limit=2)
                steps.append({"track": "조회 계획",
                              "text": "전체 해시 {}건 중 대표 샘플 {}건만 동적 분석하고, 나머지는 IOC·헌팅 대상으로 보존합니다."
                                      .format(len(all_hashes), len(route["hashes"]))})
            elif "malware" in route.get("tracks", []) and len(route.get("hashes") or []) > 2:
                all_hashes = list(route["hashes"])
                route["hashes"] = all_hashes[:2]
                steps.append({"track": "조회 계획",
                              "text": "동적 분석 대표 해시가 지정되지 않아 앞의 {}건만 우선 분석하고, 전체 {}건은 IOC·헌팅 대상으로 보존합니다."
                                      .format(len(route["hashes"]), len(all_hashes))})
            steps.extend({"track": "조회 계획", "text": line}
                         for line in chosen.get("steps") or [])
        except Exception as error:
            steps.append({"track": "조회 계획", "text": "실패: {}".format(error)})
    block["route"]["tracks"] = route["tracks"]
    if synthesize and targets.get("objective") and not block.get("research_plan"):
        block["research_plan"] = lookup_plan.build_task_graph(
            targets.get("objective"), targets.get("questions"), route.get("tracks") or [],
            set(route.get("tracks") or []), block.get("question_lookups"))
        # 원장의 목표를 판단 단계의 이슈 ID에 묶는다 — 질문 문장이 라운드마다 조금씩
        # 달라져도 어느 이슈의 조사인지 잃지 않게.
        issue_ids = {str(issue.get("question") or "").strip(): issue.get("id")
                     for issue in targets.get("issues") or [] if issue.get("id")}
        for task in block["research_plan"]:
            if issue_ids.get(str(task.get("goal") or "").strip()):
                task["issue_id"] = issue_ids[str(task["goal"]).strip()]
    block["targets"] = targets
    for item in assessed:
        if item.get("role"):
            steps.append({"track": "지표 역할 검토", "text": "{}: {}. {}".format(
                item["value"], source_evidence.ROLE_LABELS.get(item["role"], item["role"]),
                item.get("evidence") or "")})
    if primary.get("sources"):
        block["primary"] = {"sources": [{key: source.get(key) for key in
                              ("url", "host", "chars", "retrieved_at", "excerpt_sha256")}
                              for source in primary["sources"]]}
    run_lookups({"iocs": iocs, "text": text, "title": title, "route": route,
                 "urlscan_key": urlscan_key, "vt_key": vt_key, "targets": targets,
                 "body": body, "primary_text": primary_text, "block": block,
                 "article_url": article_url},
                block, steps)
    _corroborate_roles(block, steps)

    browser_track = browser_research.investigate(targets, block, route)
    block["shared_web_fingerprints"] = pattern_synth.shared_web_fingerprints(
        block.get("seeds"), block.get("negative_controls"))
    if browser_track:
        block["browser_research"] = browser_track
        rows = block.setdefault("question_lookups", [])
        browser_results = browser_track["results"]
        browser_live = next((item for item in browser_results
                             if item["source"] == "isolated_browser"), {})
        state = "returned" if browser_live.get("status") == "observed" else "partial"
        block.setdefault("lookup_status", []).append({
            "key": "브라우저 조사", "status": state,
            "detail": "격리 브라우저 관측" if state == "returned" else
                      browser_live.get("reason") or "저장된 스캔만 확인"})
        archived = [item["evidence"] for item in browser_results
                    if item["source"] == "archived_scan"]
        summary = "저장된 urlscan {}건의 DOM·HTTP 관측을 대조했습니다".format(len(archived))
        if state == "returned":
            snapshot = browser_live["evidence"]
            summary += "; 브라우저에서 {} 후 DOM 변경 {}, 클립보드 쓰기 {}건, HTTP 응답 {}건 관측".format(
                snapshot["action"], snapshot["before"]["dom_sha256"] != snapshot["after"]["dom_sha256"],
                len(snapshot["clipboard"]), len(snapshot["responses"]))
        else:
            summary += "; " + (browser_live.get("reason") or "브라우저 관측 미실행")
        block.setdefault("findings", []).append(summary)
        for question in browser_track["questions"]:
            row = next((item for item in rows if item.get("question") == question), None)
            if row is None:
                row = {"question": question, "lookups": []}
                rows.append(row)
            row.setdefault("lookups", []).append({
                "key": "브라우저 조사", "why": "저장 스캔과 실제 페이지의 클릭 전후 DOM·HTTP를 대조"})
            steps.append({"track": "브라우저 조사", "text": "{} — {}".format(question, summary)})

    block.setdefault("patterns", [])

    block["steps"] = steps
    block.setdefault("seeds", [])
    block.setdefault("findings", [])
    block["steps_summary"] = summarize(block)
    # 대응 — 조사에서 나온 값과 본문의 구체값을 차단 목록·탐지 쿼리로 바꾼다.
    block["response"] = response_builder.build(block, iocs, primary=route["primary"], text=text)
    analyst_workflow.prepare_queries(block.get("response"))

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
                    more = _collect_primary(
                        [{"url": u} for u in intel_refs], article_url=article_url, limit=1)
                    primary["sources"] = (primary.get("sources") or []) + more["sources"]
                    block.setdefault("lookup_status", []).extend(more.get("attempts") or [])
                    steps.extend({"track": "원문 확인", "text": line}
                                 for line in more.get("steps") or [])
                except Exception as error:
                    block.setdefault("lookup_status", []).append({"key": "primary", "status": "failed",
                                                                   "detail": "참고 원문 수집 예외: " + type(error).__name__})
                    steps.append({"track": "원문 확인",
                                  "text": "참고 링크 원문 확인 실패: {}".format(error)})
            # 읽은 1차 자료를 블록에 남긴다. 남기지 않으면 산출물 점검이 "공개 분석·
            # 1차 자료"를 미달로 찍는다 — 실제로는 읽었는데도(실측: socket.dev·
            # DomainTools 2건을 읽고 external_reports 미달).
            if primary.get("sources"):
                block["primary"] = {"sources": [
                    {"url": source.get("url") or "", "host": source.get("host") or "",
                     "chars": source.get("chars") or 0,
                     "retrieved_at": source.get("retrieved_at") or "",
                     "excerpt_sha256": source.get("excerpt_sha256") or ""}
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
            block["source_urls"] = list(dict.fromkeys(source_urls + [
                source["url"] for source in primary.get("sources") or [] if source.get("url")]))
            if set(block["source_urls"]) != set(source_urls):
                block["response"] = response_builder.build(block, iocs, primary=route["primary"], text=text)
                analyst_workflow.prepare_queries(block.get("response"))
            history_evidence = past_analyses.as_evidence(related)

            if text or body:
                try:
                    synth = pattern_synth.synthesize(
                        title, text, body=body + "\n" + primary_text + "\n" + evidence,
                        iocs=iocs, api_key=urlscan_key, targets=targets, web_evidence=block)
                    if synth.get("patterns"):
                        block["patterns"] = list(block["patterns"]) + synth["patterns"]
                    steps.extend({"track": "패턴 합성", "text": line}
                                 for line in synth.get("steps") or [])
                    block["response"] = response_builder.build(
                        block, iocs, primary=route["primary"], text=text)
                    analyst_workflow.prepare_queries(block.get("response"))
                except Exception as error:
                    steps.append({"track": "패턴 합성", "text": "실패: {}".format(error)})

            # 확인질문별 진행 원장 — "검색을 했다"가 아니라 "질문이 풀렸다"로 반복을
            # 멈춘다(question_status는 response_synth가 매 라운드 채운다).
            ledger = {q: "open" for q in (targets.get("questions") or [])}

            def _apply_status(verdict_data):
                if verdict_data:
                    goal_evidence.reconcile(verdict_data, block)
                for row in (verdict_data or {}).get("question_status") or []:
                    question = row.get("question")
                    if question in ledger:
                        ledger[question] = row.get("status") or ledger[question]

            verdict = response_synth.synthesize(
                title, text, targets, block, primary=evidence,
                history=history_evidence, article=body, related=related)
            if verdict is None:
                steps.append({"track": "종합 판단", "text": "판단 생성 실패: 모델 응답 없음·형식 오류·근거 검증 탈락. 조사 자료는 보존했으며 분석 완료로 간주하지 않습니다."})
                block["synthesis_status"] = {"status": "failed", "retryable": True}
            else:
                block["synthesis_status"] = {"status": "completed"}
            _apply_status(verdict)

            # 후속 조회를 여러 라운드로 돈다(상한 MAX_INVESTIGATION_ROUNDS). 질문이
            # 다 풀리거나, 더 조회할 것이 없거나, 새로 얻은 것이 없으면 상한 전에
            # 먼저 멈춘다. 각 라운드는 세 가지를 새 조회 재료로 삼는다: URLhaus가
            # 알려 준 페이로드 해시(기존 로직 그대로), 판단이 요청한 후속 조회
            # (_run_followups — 검증된 값 그대로 조회하는 경로라 새 트랙을 여는
            # classify() 재실행과 결과가 같다), 그리고 "동일 캠페인"으로 확정된
            # 관련 보고서의 IOC(관련성 판정 자체는 이미 response_synth가 그라운딩을
            # 거쳤다 — 여기서는 그 판정을 실행으로 옮길 뿐이다). 질문이 남아 있으면
            # web_search도 그 질문에서 뽑은 검색어로 다시 돈다(같은 용어를 반복하지
            # 않고 검색을 바꾼다).
            executed_pending = None
            round_num = 1
            followup_count = 0
            research_state = {"ran": False}

            def _run_hashes(values):
                found, hash_steps = _run_followups(
                    [{"type": "hash", "value": value, "question": "목표에 필요한 샘플 행위"}
                     for value in values], urlscan_key=urlscan_key, vt_key=vt_key, block=block)
                steps.extend({"track": "목표별 재조사", "text": line} for line in hash_steps)
                return found

            def _research_round():
                """목표별로 모자란 증거를 채우는 조사 한 번. 모델을 부르지 않는다."""
                research_state["ran"] = True
                found, action_steps = research_actions.execute(
                    block, iocs, urlscan_key, _run_hashes,
                    evidence_text="\n".join([body or "", primary_text or "", text or ""]))
                steps.extend({"track": "목표별 재조사", "text": line} for line in action_steps)
                if found:
                    block["shared_web_fingerprints"] = pattern_synth.shared_web_fingerprints(
                        block.get("seeds"), block.get("negative_controls"))
                return found
            while verdict and round_num < MAX_INVESTIGATION_ROUNDS:
                if time.monotonic() - started >= INVESTIGATION_SOFT_BUDGET_SECONDS:
                    steps.append({"track": "조사 반복", "text":
                                  "시간 예산에 도달해 추가 외부 조회를 멈췄습니다. 남은 질문은 미확인으로 보존합니다."})
                    break
                open_questions = [q for q, status in ledger.items() if status != "answered"]
                if ledger and not open_questions:
                    steps.append({"track": "조사 반복",
                                  "text": "확인질문이 모두 풀려 반복을 멈췄습니다."})
                    break
                known = {str(item.get("value") or "").lower() for item in iocs or []}
                pending = []
                for value in ((block.get("intel") or {}).get("discovered_hashes") or []):
                    if value.lower() not in known:
                        pending.append({"type": "hash", "value": value,
                                        "question": "URLhaus가 이 URL의 페이로드로 준 해시가 "
                                                    "실제 무엇인지"})
                        known.add(value.lower())
                pending.extend(verdict.get("followups") or [])
                for relation in verdict.get("campaign_relations") or []:
                    if relation.get("relation") != "동일 캠페인":
                        continue
                    candidate = next((r for r in related
                                      if r.get("title") == relation.get("title")), None)
                    for item in (candidate or {}).get("iocs") or []:
                        value = str(item.get("value") or "").strip()
                        kind = {"sha256": "hash", "sha1": "hash", "md5": "hash",
                               "domain": "domain", "ipv4": "ip", "cve": "cve"}.get(item.get("type"))
                        if value and kind and value.lower() not in known:
                            pending.append({"type": kind, "value": value,
                                            "question": "관련 보고서(\"{}\")가 같은 캠페인의 "
                                                        "지표로 제시한 값인지".format(
                                                            relation.get("title", ""))[:120]})
                            known.add(value.lower())
                if not pending and not open_questions:
                    break
                available = max(0, MAX_FOLLOWUP_LOOKUPS - followup_count)
                if len(pending) > available:
                    steps.append({"track": "조회 예산", "text": "후속 지표 {}건 중 {}건은 이번 조사 호출 한도로 보류했습니다.".format(
                        len(pending), len(pending) - available)})
                    pending = pending[:available]
                extra_lines, extra_steps = [], []
                if pending:
                    followup_count += len(pending)
                    extra_lines, extra_steps = _run_followups(
                        pending, urlscan_key=urlscan_key, vt_key=vt_key, block=block)
                    steps.extend({"track": "후속 조회", "text": line} for line in extra_steps)
                    executed_pending = pending
                    # 후속 해시 조회로 샌드박스 통신이 새로 생겼을 수 있다.
                    extra_lines = extra_lines + _corroborate_roles(block, steps)
                if open_questions:
                    web_round = None
                    try:
                        # 이미 검색한 말은 빼고, 남은 질문에서 뽑은 말로만 다시 찾는다.
                        searched = set((block.get("web") or {}).get("terms") or [])
                        web_round = web_search.analyze(targets, answered=searched,
                                                       open_questions=open_questions)
                    except Exception:
                        web_round = None
                    if web_round:
                        existing_web = block.get("web") or {}
                        known_findings = set(existing_web.get("findings") or [])
                        new_findings = [line for line in web_round.get("findings") or []
                                        if line not in known_findings]
                        block["web"] = dict(web_round, findings=(
                            (existing_web.get("findings") or []) + new_findings),
                            references=list(dict.fromkeys(
                                (existing_web.get("references") or [])
                                + (web_round.get("references") or []))),
                            terms=list(dict.fromkeys(
                                (existing_web.get("terms") or []) + (web_round.get("terms") or []))))
                        web_round["findings"] = new_findings
                        steps.extend({"track": "연구 자료 검색", "text": line}
                                     for line in web_round.get("steps") or [])
                        extra_lines = extra_lines + (web_round.get("findings") or [])
                        attempted_urls = {source_evidence.canonical_url(item.get("url"))
                                          for item in (primary.get("sources") or [])
                                          + (primary.get("attempts") or []) if item.get("url")}
                        fresh_refs = [url for url in web_round.get("references") or []
                                      if source_evidence.canonical_url(url) not in attempted_urls]
                        if fresh_refs:
                            try:
                                more = _collect_primary(
                                    [{"url": url} for url in fresh_refs],
                                    article_url=article_url, limit=MAX_FOLLOWUP_SOURCES,
                                    origin="search")
                            except Exception as error:
                                more = {"sources": [], "steps": [
                                    "후속 검색 참고 원문 조회 실패: {}".format(type(error).__name__)],
                                    "attempts": []}
                            primary["sources"] = (primary.get("sources") or []) + (more.get("sources") or [])
                            primary["attempts"] = (primary.get("attempts") or []) + (more.get("attempts") or [])
                            block.setdefault("lookup_status", []).extend(more.get("attempts") or [])
                            steps.extend({"track": "후속 원문 확인", "text": line}
                                         for line in more.get("steps") or [])
                            new_sources = more.get("sources") or []
                            if new_sources:
                                source_urls.extend(source["url"] for source in new_sources)
                                block["source_urls"] = list(dict.fromkeys(source_urls))
                                block["primary"] = {"sources": [{
                                    key: source.get(key) for key in
                                    ("url", "host", "chars", "retrieved_at", "excerpt_sha256")}
                                    for source in primary["sources"]]}
                                evidence = primary_sources.as_evidence(primary["sources"])
                                extra_lines.append("후속 검색 원문 {}건을 실제로 읽었습니다.".format(
                                    len(new_sources)))
                                fresh_iocs = source_evidence.extract_report_iocs(
                                    "\n".join(source.get("text") or "" for source in new_sources),
                                    limit=PRIMARY_IOC_LIMIT)
                                fresh_iocs, _ = source_evidence.filter_iocs(fresh_iocs, source_urls)
                                seen_values = {str(item.get("value") or "").lower()
                                               for item in iocs or []}
                                fresh_iocs = [item for item in fresh_iocs
                                              if str(item.get("value") or "").lower() not in seen_values]
                                assessed_new = source_evidence.assess_iocs(fresh_iocs, new_sources)
                                block.setdefault("indicator_assessments", []).extend(assessed_new)
                                iocs.extend(assessed_new)
                                fresh_requests = []
                                for item in sorted(assessed_new, key=lambda entry:
                                                   0 if entry.get("type") in
                                                   ("sha256", "sha1", "md5", "cve") else 1):
                                    kind = {"sha256": "hash", "sha1": "hash", "md5": "hash",
                                            "cve": "cve", "domain": "domain", "url": "domain",
                                            "ipv4": "ip"}.get(
                                                str(item.get("type") or "").lower())
                                    if not kind or (kind in ("domain", "ip") and
                                                    item.get("role") not in source_evidence.ATTACK_ROLES):
                                        continue
                                    value = (common_utils.host_from_indicator(item["value"])
                                             if item.get("type") == "url" else item["value"])
                                    if value.lower() in known:
                                        continue
                                    if len(fresh_requests) >= min(
                                            MAX_FOLLOWUP_SOURCE_IOCS,
                                            MAX_FOLLOWUP_LOOKUPS - followup_count):
                                        break
                                    fresh_requests.append({"type": kind, "value": value,
                                                           "question": "후속 원문 지표의 관측 여부"})
                                    known.add(value.lower())
                                if fresh_requests:
                                    followup_count += len(fresh_requests)
                                    observed, observed_steps = _run_followups(
                                        fresh_requests, urlscan_key=urlscan_key,
                                        vt_key=vt_key, block=block)
                                    steps.extend({"track": "후속 원문 지표 조회", "text": line}
                                                 for line in observed_steps)
                                    extra_lines.extend(observed)
                                    executed_pending = (executed_pending or []) + fresh_requests
                # 목표별로 모자란 증거를 보고 다음 조사를 고른다 — 판단이 요청한 지표만
                # 다시 보던 반복이 "외부 링크 미확인", "정상 비교군 없음", "샘플 행위 없음"
                # 같은 빈칸을 채우지 못했다. 시도 이력이 남아 같은 입력은 다시 돌지 않는다.
                if followup_count < MAX_FOLLOWUP_LOOKUPS:
                    action_lines = _research_round()
                    if action_lines:
                        followup_count += 1
                        extra_lines = extra_lines + action_lines
                block["response"] = response_builder.build(block, iocs, primary=route["primary"], text=text)
                analyst_workflow.prepare_queries(block.get("response"))
                if not extra_lines:
                    break
                again = response_synth.synthesize(
                    title, text, targets, block, primary=evidence,
                    extra="\n".join(extra_lines), history=history_evidence,
                    article=body, related=related)
                round_num += 1
                if not again:
                    break
                again["followup_evidence"] = (verdict.get("followup_evidence") or []) + extra_lines
                verdict = again
                _apply_status(verdict)
            if not research_state["ran"]:
                # 시간 예산·조기 종료로 반복이 재조사까지 닿지 못한 경우, 또는 판단 생성이
                # 실패한 경우. 재조사는 모델을 부르지 않으므로 판단이 없어도 돌린다(실측
                # 2026-10-02: 모델 지연으로 180초 예산이 먼저 찼고, 다음 회차에는 판단 자체가
                # 504로 실패해 재조사가 두 번 다 안 돌았다). 판단 문장은 다시 받지 않는다.
                if _research_round():
                    if verdict:
                        goal_evidence.reconcile(verdict, block)
                    steps.append({"track": "목표별 재조사", "text":
                                  "재조사 결과는 조사 기록과 목표별 증거 판정에 반영했고, 종합 판단 "
                                  "문장은 다시 받지 않았습니다."})
            if verdict is not None and executed_pending is not None:
                # 실행한 것만 남긴다 — 화면에서 "요청한 것과 다른 것을 조회했다"로
                # 읽히지 않게(마지막으로 실제 돌린 라운드의 목록만).
                verdict["followups"] = executed_pending
            if verdict:
                if block.get("research_plan"):
                    lookup_plan.reconcile_task_graph(block["research_plan"], block)
                # 검색식은 결과가 나왔다는 것만으로 탐지 근거가 아니다 — 조회용·확장 후보·
                # 검증된 탐지식으로 나눠 화면에 그대로 보인다.
                research_actions.assign_tiers(block)
                block["synthesis"] = verdict
                block["questions"] = [{"question": q, "status": status}
                                      for q, status in ledger.items()]
                # 내놓기 전에 한 번 더 본다. 차단 목록은 지표에서 기계적으로 나오고
                # 판단은 그 뒤에 따로 쓰여서, 둘이 어긋나도 아무도 몰랐다(실측:
                # 판단이 "정상 CDN이 악용된 것"이라고 적은 도메인이 차단 후보에
                # 그대로 남아 있었다).
                try:
                    spared = output_critic.review(verdict, block.get("response"), block)
                    if spared and output_critic.apply(block.get("response"), spared):
                        output_critic.reconcile_plan(verdict, spared)
                        steps.extend({"track": "산출물 검토", "text": line}
                                     for line in output_critic.steps(spared))
                except Exception as error:
                    steps.append({"track": "산출물 검토",
                                  "text": "실패: {}".format(str(error)[:90])})
                block["action_plan"] = merge_actions(verdict, block.get("response"))
                steps.extend({"track": "종합 판단", "text": line}
                             for line in verdict.get("steps") or [])
                block["steps"] = steps
        except Exception as error:
            steps.append({"track": "종합 판단", "text": "실패: {}".format(error)})
            block["steps"] = steps
    # 판단이 붙은 뒤 요약을 다시 만든다 — 앞에서 만든 요약에는 결론이 들어갈 수 없었다.
    if block.get("synthesis"):
        block["steps_summary"] = summarize(block)
    analyst_workflow.finalize(block, targets)
    if incident_label:
        # build_for_article()이 사건별로 이 함수를 불러 결과를 합칠 때만 쓰인다 —
        # 어느 항목이 어느 사건 것인지 화면에서 구분할 수 있게 라벨만 덧붙인다.
        for step in block.get("steps") or []:
            step["track"] = "[{}] {}".format(incident_label, step.get("track") or "")
        for group in (block.get("response") or {}).get("blocklists") or []:
            group["label"] = "[{}] {}".format(incident_label, group.get("label") or "")
        block["incident_label"] = incident_label
    if not route["tracks"] and not block["response"] and not block.get("synthesis"):
        # 이유를 말할 수 있으면 카드를 남긴다 — 빈 화면보다 "왜 없는지"가 낫다.
        if targets and targets.get("investigable") is False:
            block["steps"] = block.get("steps") or []
            block["steps_summary"] = block["route"]["explain"]
            return block
        return None      # 근거도 없이 비어 있으면 예전처럼 카드를 만들지 않는다
    return block


def log(message):
    print(message)


def build_for_article(iocs, text="", urlscan_key=None, vt_key=None, title="", category="",
                      body="", synthesize=True, targets=None, links=None, article_url=""):
    """build()의 기사 단위 진입점 — analysis_worker.py는 build() 대신 이 함수를 쓴다.

    사건이 하나(대다수 기사)면 build()를 신규 인자 없이 그대로 한 번 불러 반환한다
    — 오늘과 완전히 같은 코드 경로다. 종합 기사(analysis_targets가 사건구분을 둘
    이상 파싱했을 때)만 incident_scope.split()으로 나눈 사건마다 build()를 따로
    불러 결과를 합친다.

    사건을 나누는 이유는 response_synth._corpus()가 investigation 전체를 문자열로
    이어붙여 근거를 대조하기 때문이다 — 한 번의 build() 호출 안에서 여러 사건을
    같이 다루면 사건 A의 판단이 사건 B의 IOC를 근거로 대조해도 걸러지지 않는다.
    build()를 사건마다 따로 불러 block을 물리적으로 분리하면, response_synth.py를
    더 건드리지 않고 이 문제가 없어진다.
    """
    if article_kind.is_informational(targets):
        return briefing.build(iocs, text=text, title=title, category=category, body=body,
                              targets=targets, links=links, article_url=article_url,
                              synthesize=synthesize)
    incidents = incident_scope.split(targets or {}, iocs)
    if len(incidents) < 2:
        return build(iocs, text=text, urlscan_key=urlscan_key, vt_key=vt_key, title=title,
                     category=category, body=body, synthesize=synthesize,
                     targets=incidents[0]["targets"], links=links, article_url=article_url)

    # 1차 자료는 기사 레벨 자료라 사건마다 반복해서 수집할 이유가 없다 — 한 번만
    # 받아 모든 사건의 build()에 그대로 넘긴다.
    shared_primary = {"sources": [], "steps": []}
    if links:
        try:
            shared_primary = _collect_primary(links, article_url=article_url)
        except Exception as error:
            shared_primary = {"sources": [], "steps": [
                "1차 자료 수집 실패(사건 공통): {}".format(error)]}

    sub_blocks = []
    for incident in incidents:
        try:
            sub = build(incident["iocs"], text=text, urlscan_key=urlscan_key, vt_key=vt_key,
                       title=title, category=category, body=body, synthesize=synthesize,
                       targets=incident["targets"], links=links, article_url=article_url,
                       shared_primary=shared_primary, incident_label=incident["label"])
        except Exception as error:
            sub = None
            log("[-] 사건 \"{}\" 조사 실패: {}".format(incident["label"], error))
        if sub:
            sub["incident_id"] = incident["incident_id"]
            sub_blocks.append(sub)

    if not sub_blocks:
        return None
    return _combine_incidents(sub_blocks)


def _combine_incidents(sub_blocks):
    """사건별 block N개를 기사 하나의 block으로 합친다.

    기존 대시보드가 읽는 키(response/synthesis/steps/action_plan)는 모든 사건의
    내용을 이어붙여 채운다 — 키 이름은 그대로라 기존 화면 코드가 그대로 동작하고,
    내용만 사건별로 올바르게 분리된 채로 들어간다(build()가 이미 incident_label로
    각 항목에 "[사건 라벨]"을 붙여 뒀다). 사건 단위로 다시 보고 싶은 화면을 위해
    block["incidents"]에 사건별 block 전체를 그대로 남긴다.
    """
    labels = [b.get("incident_label") or (b.get("route") or {}).get("label") or ""
             for b in sub_blocks]
    combined = {
        "route": {
            "primary": "multi",
            "label": "종합 기사 — 사건 {}건".format(len(sub_blocks)),
            "explain": " / ".join(label for label in labels if label),
            "tracks": sorted({track for b in sub_blocks
                              for track in (b.get("route") or {}).get("tracks") or []}),
            "scores": {},
        },
        "source_urls": sorted({url for b in sub_blocks for url in b.get("source_urls") or []}),
        "targets": sub_blocks[0].get("targets") or {},
        "seeds": [seed for b in sub_blocks for seed in b.get("seeds") or []],
        "patterns": [pattern for b in sub_blocks for pattern in b.get("patterns") or []],
        "findings": [finding for b in sub_blocks for finding in b.get("findings") or []],
        "steps": [step for b in sub_blocks for step in b.get("steps") or []],
        "incidents": sub_blocks,
    }
    # Keep research tracks at the article level as well as inside each incident.
    # Older dashboard consumers read only the top-level keys; dropping these during
    # the multi-incident merge made valid sandbox/browser evidence look absent.
    malware_blocks = [(b.get("incident_label") or "", b.get("malware") or {})
                      for b in sub_blocks if b.get("malware")]
    if malware_blocks:
        files, findings, malware_steps = [], [], []
        seen_hashes = set()
        for label, track in malware_blocks:
            for file in track.get("files") or []:
                row = dict(file)
                row["incident_label"] = label
                key = str(row.get("hash") or "").lower()
                if key and key in seen_hashes:
                    continue
                seen_hashes.add(key)
                files.append(row)
            findings.extend(track.get("findings") or [])
            malware_steps.extend(track.get("steps") or [])
        combined["malware"] = {
            "checked": bool(malware_blocks) and all(track.get("checked") for _, track in malware_blocks),
            "partial": any(track.get("checked") for _, track in malware_blocks)
                       and not all(track.get("checked") for _, track in malware_blocks),
            "total_hashes": len(seen_hashes), "files": files,
            "findings": findings, "steps": malware_steps,
        }
    browser_blocks = [b.get("browser_research") for b in sub_blocks if b.get("browser_research")]
    if browser_blocks:
        combined["browser_research"] = {
            "questions": list(dict.fromkeys(q for track in browser_blocks
                                            for q in track.get("questions") or [])),
            "results": [dict(row, incident_label=label)
                        for label, block in ((b.get("incident_label") or "", b.get("browser_research") or {})
                                             for b in sub_blocks if b.get("browser_research"))
                        for row in block.get("results") or []],
        }
    combined["research_plan"] = [task for b in sub_blocks for task in b.get("research_plan") or []]
    combined["goal_evidence"] = [row for b in sub_blocks for row in b.get("goal_evidence") or []]
    combined["followup_results"] = [row for b in sub_blocks for row in b.get("followup_results") or []]
    responses = [b.get("response") for b in sub_blocks if b.get("response")]
    if responses:
        provenance = {}
        for response in responses:
            provenance.update(response.get("provenance") or {})
        combined["response"] = {
            "blocklists": [group for r in responses for group in r.get("blocklists") or []],
            "kql": [query for r in responses for query in r.get("kql") or []],
            "actions": [action for r in responses for action in r.get("actions") or []],
            "commands": [command for r in responses for command in r.get("commands") or []],
            "provenance": provenance,
            "generated_at": common_utils.utc_now_iso(),
        }
    else:
        combined["response"] = None
    verdicts = [b.get("synthesis") for b in sub_blocks if b.get("synthesis")]
    if verdicts:
        # synthesis를 한 dict로 억지로 합치면(예: confirmed 리스트를 그냥 이어붙이면)
        # 어느 사건 것인지 다시 알 수 없어진다. 대표 판단(첫 사건) + 사건별 원본
        # 목록(per_incident)으로 둔다 — 기존 단일-사건 화면 코드는 대표 판단을,
        # 사건 단위 화면은 per_incident를 읽으면 된다.
        combined["synthesis"] = dict(verdicts[0])
        combined["synthesis"]["per_incident"] = [
            {"incident_id": b.get("incident_id"), "label": b.get("incident_label") or "",
             **(b.get("synthesis") or {})}
            for b in sub_blocks if b.get("synthesis")
        ]
        combined["synthesis"]["headline"] = " / ".join(
            v.get("headline") or "" for v in verdicts if v.get("headline"))
    action_plans = [b.get("action_plan") for b in sub_blocks if b.get("action_plan")]
    if action_plans:
        combined["action_plan"] = [step for plan in action_plans for step in plan]
    questions = [question for b in sub_blocks for question in b.get("questions") or []]
    if questions:
        combined["questions"] = questions
    combined["question_lookups"] = [row for b in sub_blocks
                                     for row in b.get("question_lookups") or []]
    coverage = [b.get("coverage") for b in sub_blocks if b.get("coverage")]
    if coverage:
        combined["coverage"] = coverage[0]
    gaps = [gap for b in sub_blocks for gap in b.get("gaps") or []]
    if gaps:
        combined["gaps"] = gaps
    summaries = []
    for block in sub_blocks:
        synthesis = block.get("synthesis") or {}
        verdict = synthesis.get("verdict") or "조사 진행"
        label = block.get("incident_label") or "사건 {}".format(block.get("incident_id") or "?")
        summaries.append("{}: {}".format(label, verdict))
    combined["steps_summary"] = "사건별 조사 {}건 · {}.".format(
        len(sub_blocks), " · ".join(summaries))
    related = [item for b in sub_blocks for item in b.get("related") or []]
    if related:
        combined["related"] = related
    primaries = [b.get("primary") for b in sub_blocks if b.get("primary")]
    if primaries:
        seen_urls, merged_sources = set(), []
        for primary in primaries:
            for source in primary.get("sources") or []:
                if source.get("url") not in seen_urls:
                    seen_urls.add(source.get("url"))
                    merged_sources.append(source)
        combined["primary"] = {"sources": merged_sources}
    combined["lookup_status"] = [status for b in sub_blocks for status in b.get("lookup_status") or []]
    return combined


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
