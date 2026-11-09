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
import analysis_trace

# 프롬프트에 붙일 명세. 사람이 읽는 섹션이 아니라 도구가 읽는 목록이라는 점을 못박고,
# 줄 이름을 고정해 파싱이 흔들리지 않게 한다.
SPEC_TEMPLATE = """

[조사 대상]
이 섹션은 사람이 읽는 글이 아니라 자동 조사 도구가 읽는 목록이다. 아래 줄 이름을 그대로
쓰고, 없으면 "없음"이라고 써라. 여러 개면 쉼표로 나눈다. 값에 볼드(**)나 설명을 붙이지 마라.

줄은 두 종류다. 도메인부터 조사불가사유까지는 본문에 실제로 나온 값만 적는다. 목표·
성공기준·부족한것·확인질문 네 줄은 본문에서 뽑는 것이 아니라 네가 판단해서 쓰는 줄이고,
어떤 기사에서도 빠질 수 없다 — 본문에 근거가 없다는 이유로 건너뛰지 마라.
{ENV}
사건구분: 이 기사가 서로 무관하게 벌어진 사건 여러 건을 하나로 묶은 종합 기사라면, 각
  사건에 짧은 라벨을 붙여 쉼표로 나열하라(예: GhostCode 침해, WaterPlum 캠페인). 한
  사건을 여러 각도로 설명하는 기사면 사건은 하나다 — "없음"이라고 써라.
  사건이 둘 이상일 때만: 아래 도메인부터 명령까지의 모든 값 뒤에, 그 값이 속한 사건
  번호를 괄호로 붙여라(사건구분에 쓴 순서가 번호다). 예) 도메인: a.example(1), b.example(2)
  값 하나가 여러 사건에 걸치면 콤마로 번호를 더 쓴다. 예) c.example(1,2)
  번호를 안 붙인 값은 사건 1로 본다. 목표·확인질문·성공기준·부족한것·주력 다섯 줄도
  사건마다 따로 쓴다 — 줄 이름 뒤에 번호를 붙인다: 목표1:, 목표2:, 확인질문1:,
  확인질문2: 처럼. 사건이 하나면 지금까지처럼 번호 없이 각 줄을 한 번만 쓴다.
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
    · 우리가 실제로 할 수 있는 일인가
  마지막 항목을 특히 지켜라. 우리가 할 수 있는 것은 외부 조회로 사실을 확인하는 것과,
  사내에서 돌릴 탐지 쿼리·차단 목록·점검 명령을 만들어 내놓는 것까지다. 패치를 배포하거나
  키를 폐기하거나 절차를 수립하는 것은 우리 손 밖이다 — 그런 것을 목표에 적으면 달성
  판정이 영원히 나지 않는다.
    나쁨) 완화 조치를 배포한다 / API 키를 전면 교체한다 / 운영 환경에 적용한다
    좋음) 배포해야 할 완화 조치를 확정하고 적용 대상을 가려낸다 / 교체 대상 키를
          식별하고 노출 범위를 확정한다
  기사 요약을 되풀이하지 마라. 볼드(**)나 머리글 기호를 쓰지 마라 — 한 문장이다.
성공기준: 위 목표를 달성하려면 무엇이 나와야 하는지를 아래 이름들 중에서 골라 쉼표로
  나눠 쓰라. 이 사건에 필요한 것만 고르고, 필요 없는 것은 넣지 마라 — 나중에 실제로
  나왔는지 대조하므로 넣은 것은 약속이 된다.
{VOCAB}
부족한것: 바로 위 어휘는 우리가 이미 만들 줄 아는 것들이다. 그것만으로는 이 건의 대응이
  완결되지 않는다면, 무엇이 더 있어야 하는지 여기에 적어라. 본문에 없는 이야기여도 되고
  우리가 지금 가진 도구로 낼 수 없어도 된다 — 이 줄을 비우면 우리가 가진 도구가 곧 대응의
  한계가 되고, 그 한계는 아무도 눈치채지 못한 채 굳는다.
  각 항목은 무엇이 필요한지 짧게 쓴다. 여러 개면 쉼표로 나눈다.
  예) 확장 프로그램 스토어에서 같은 개발자의 다른 확장을 열거하는 조회,
      사내 자산 목록과 대조한 영향 범위, 피해자 조직에 배포된 패치 버전 확인
  정말로 위 어휘가 이 건을 전부 덮는다고 판단할 때만 "없음"이라고 쓴다. 생각이 안 난다는
  이유로 "없음"을 쓰지 마라 — 그 둘은 다른 말이고, 우리는 앞의 것만 믿는다.
확인질문: 목표를 달성하려면 조회로 답해야 할 질문 2~4개를 쉼표로 나눠 쓴다.
  실행 조건·버전 차이·유포 경로·외부 전송 목적지·공통 행위를 공개 근거로 확인할 질문을
  우선한다. 사내 설치 여부·교육 여부처럼 외부 조회로 답할 수 없는 질문만으로 채우지 마라.
  기사나 1차 자료가 확인하지 않은 배포 방식은 질문에서도 전제하지 마라. 로컬에
  주입된 브라우저 확장을 웹스토어 등록 확장으로 가정하지 말고, 등록 여부 자체가
  미확인이면 로컬 설치 흔적·매니페스트·Native Messaging Host 연결을 질문하라.
  샘플 해시 확보와 다른 목록의 동일 해시 대조처럼 서로 다른 검증 단계는 구분하라.
  예) 어떤 버전·실행 조건에서 정보가 유출되는가, 원 연구 보고서가 공개한 샘플과 유출 주소는 무엇인가,
      같은 캠페인이라는 근거가 있는 추가 샘플과 공통 행위는 무엇인가

마지막으로 목표·성공기준·부족한것·확인질문 네 줄을 다 썼는지 확인하라. 하나라도 없으면
이 섹션은 도구가 읽다 만 채로 버려진다.
"""

import common_utils
import playbook

# 어휘는 playbook이 갖고 있다 — 검증하는 쪽과 요구하는 쪽이 어긋나면
# 모델이 낼 수 없는 것을 약속하게 된다.
# 우리 환경은 import 시점이 아니라 쓸 때 읽는다 — 인벤토리·PIR 파일이 바뀌면
# 다음 분석부터 반영돼야 한다.
SPEC_WITH_VOCAB = SPEC_TEMPLATE.replace("{VOCAB}", playbook.vocabulary_spec())

INDICATOR_SPEC = """

[조사 대상]
이 섹션은 자동 조사 입력을 추출하기 위한 목록이다. 기사 본문에 실제로 나온 값만
적고, 없으면 "없음"이라고 써라. 목표·질문·대응 판단은 이 단계에서 만들지 마라.
종합 기사라면 사건구분에 사건 라벨을 쉼표로 나열하고, 아래 각 값 뒤에 소속 사건
번호를 붙여라(예: a.example(1), b.example(2)). 한 사건이면 사건구분은 없음이다.
제목의 주된 사건 뒤에 '동시에 발견된 다른 캠페인'처럼 관련 사례를 덧붙인 기사는
종합 기사가 아니다. 관련 사례의 지표를 주된 사건에 섞지 말고 사건구분도 없음으로 둬라.
기사유형: 위협사건 또는 정보성 중 하나만 써라.
  위협사건 = 실제 공격·침해·유출, 악성코드, 취약점 공개·악용, 위협 행위자 활동을 다루는
             기사다. 행위자·악성코드·지표를 구체적으로 다루는 위협 보고서도 여기다.
  정보성   = 정책·규제·가이드라인, 제품·서비스 출시, 기업 제휴·사업 발표, 기술 동향·연구·
             통계·칼럼처럼 특정 공격 사건을 다루지 않는 기사다. 제목에 "공급망"·"보안"이
             있어도 규제 대응·사업 발표 기사면 정보성이다.
사건구분:
도메인:
IP:
해시:
URL:
CVE:
제품: 취약점이 있거나 공격 대상이 된 제품만, 제품명과 버전을 한 덩어리로 적어라. 버전을
  모르면 제품명만 적어라. 발표·홍보·도입 대상인 제품·서비스·플랫폼은 적지 마라.
패키지: npm:이름 또는 pypi:이름 형태로 적어라.
행위자: 위협 행위자(해킹 그룹·캠페인 운영 주체)만 적어라. 기업·기관·파트너사·피해 조직
  이름은 적지 마라.
악성코드:
파일:
경로:
레지스트리키:
명령:
주제: 정보성이면 배경 자료를 찾을 핵심 표준·제도·기술·서비스 이름을 최대 4개, 원문에 영문
  표기가 있으면 괄호로 병기하라(예: 카테나-X(Catena-X), 디지털 제품 여권(DPP)). 위협사건이면 없음.
조사가능: 위협사건이고 위에 조회할 값이 하나라도 있으면 예, 정보성이거나 조회할 값이 없으면 아니오.
조사불가사유: 아니오라면 이유 한 문장, 그 외에는 없음.
"""


def indicator_spec():
    """Basic analysis extracts evidence; a later pass decides investigation goals."""
    return INDICATOR_SPEC


def spec():
    """분석 프롬프트에 붙일 [조사 대상] 지시문."""
    return SPEC_WITH_VOCAB.replace("{ENV}", common_utils.environment_brief())


# 예전 이름을 쓰는 곳이 있어 남겨 둔다(환경 블록이 빠진 형태).
SPEC = SPEC_WITH_VOCAB.replace("{ENV}", "")

SECTION_RE = re.compile(r"\n?\s*\[\s*조사\s*대상\s*\]\s*\n(.*?)(?=\n\s*\[|\Z)", re.S)

# 줄 이름 → 결과 키. 화면에는 안 나가고 조사 코드만 쓴다.
FIELD_MAP = {
    "도메인": "domains", "IP": "ips", "해시": "hashes", "URL": "urls", "CVE": "cves",
    "제품": "products", "패키지": "packages", "행위자": "actors", "악성코드": "malware",
    "파일": "files", "경로": "paths", "레지스트리키": "registry", "명령": "commands",
}
EMPTY_VALUES = {"없음", "해당 없음", "해당없음", "-", "n/a", "na", "none", "null", ""}

LINE_RE = re.compile(r"^\s*(?:[-*]\s*)?([A-Za-z가-힣]+)(\d{0,2})\s*[:：]\s*(.*)$")
# 값 끝에 붙는 사건 번호 태그. "a.example(1)" / "b.example(1,2)".
INCIDENT_TAG_RE = re.compile(r"\(([\d,\s]+)\)\s*$")
MIN_INCIDENTS_FOR_TAGGING = 2
# 모델이 "주력"으로 쓸 수 있는 축. investigation.TRACK_LABELS와 같은 이름이어야 한다 —
# 여기서만 아는 이름을 쓰면 선언이 조용히 버려진다.
PRIMARY_AXES = ("user_action", "malware", "vulnerability", "supply_chain")
# 값에 붙어 오는 장식. 모델이 지시를 어기고 볼드나 따옴표를 붙이는 경우가 있다.
DECOR_RE = re.compile(r"^[\s*_`\"']+|[\s*_`\"']+$")


def _clean(value):
    return DECOR_RE.sub("", value or "").strip()


def _strip_incident_tag(value):
    """값 끝의 "(1)"/"(1,2)" 사건 번호 태그를 떼어 (값, [번호,...])로 돌려준다."""
    match = INCIDENT_TAG_RE.search(value or "")
    if not match:
        return value, []
    nums = [int(n) for n in re.findall(r"\d+", match.group(1))]
    return value[:match.start()].strip(), nums


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
# 기사유형은 목록 맨 앞 줄이라 넣고, 주제는 조사가능 앞에 오므로 구간 안에 저절로
# 들어간다 — "주제: …"는 본문 문장에도 흔해서 구간 시작으로 잡히면 본문이 잘린다.
FIELD_LINE_RE = re.compile(
    "^[ " + chr(9) + "]*(?:[-*][ ]*)?(" + "|".join(FIELD_MAP)
    + "|조사가능|조사불가사유|사건구분|목표|확인질문|성공기준|주력|부족한것|기사유형)"
    r"\d{0,2}[ ]*[:：]", re.M)
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


def _split_hostless(found):
    """호스트가 없는 값을 도메인·URL 칸에서 빼낸다.

    모델이 URL 칸에 경로만("admin777111777.php", "/api/v1/agent/") 적거나 도메인 칸에
    파일명("tracker.js")을 적는 경우가 있다. 그대로 두면 유포지 조사·차단 목록이 그
    값을 호스트로 쓴다(실측 2026-09-26). 경로는 url_paths로 옮겨 헌팅 쿼리 재료로
    남기고, 파일명은 files로 옮긴다 — 버리지 않는다.
    """
    urls, paths, files = [], [], list(found.get("files") or [])

    def add_file(name):
        if name and name not in files:
            files.append(name)

    for value in found.get("urls") or []:
        plain = undefang(value)
        if common_utils.host_from_indicator(plain):
            urls.append(value)
            # 호스트가 있는 URL이라도 끝 조각이 파일이면(…/admin777111777.php) 그 파일도
            # 따로 남긴다 — 같은 파일을 요청하는 다른 사이트를 찾는 검색의 재료다.
            add_file(_url_filename(plain))
        elif FILENAME_ONLY_RE.match(plain.strip("/")):
            # 슬래시 없이 이름.확장자만 있으면 경로가 아니라 파일이다(admin777111777.php).
            add_file(plain.strip("/"))
        else:
            paths.append(value)
    found["urls"] = urls
    if paths:
        found["url_paths"] = list(dict.fromkeys(paths))
    domains = []
    for value in found.get("domains") or []:
        if common_utils.host_from_indicator(undefang(value)):
            domains.append(value)
        else:
            add_file(value)
    found["domains"] = domains
    found["files"] = files


FILENAME_ONLY_RE = re.compile(r"^[\w.-]+\.[A-Za-z0-9]{1,5}$")


def _url_filename(url):
    """URL 끝 조각이 파일(이름.확장자)이면 그 이름. 아니면 ""."""
    path = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("?", 1)[0].split("#", 1)[0]
    if "/" not in path:
        return ""
    name = path.rstrip("/").rsplit("/", 1)[-1]
    return name if FILENAME_ONLY_RE.match(name) else ""


# 주제는 배경 자료 검색어가 된다. 검색·조회 호출 수가 주제 수에 비례하므로 명세와 같은
# 상한(4개)을 파서에서도 지킨다.
MAX_TOPICS = 4


def _article_type(value):
    """기사유형 줄 → "threat" | "informational" | "". 모델이 "정보성(정책 발표)"처럼
    괄호 설명을 붙이거나 영어로 쓰는 경우까지 받는다."""
    cleaned = re.sub(r"\s+", "", _clean(value)).lower()
    if cleaned.startswith(("정보", "info")):
        return "informational"
    if cleaned.startswith(("위협", "공격", "threat", "attack")):
        return "threat"
    return ""


def _axis(value):
    # 어휘 밖의 값은 버린다. 여기서 거르지 않으면 "네트워크 침투" 같은
    # 자유 문장이 트랙 이름 자리에 들어와 조사 계획이 통째로 어긋난다.
    candidate = _clean(value).lower().replace("-", "_").replace(" ", "_")
    return candidate if candidate in PRIMARY_AXES else ""


@analysis_trace.step("LLM 응답에서 조사 대상 파싱", "artifacts", "extraction", inputs=("text",))
def parse(text):
    """[조사 대상] 섹션을 dict로. 섹션이 없으면 빈 dict.

    사건구분이 둘 이상이면 종합 기사다 — 값마다 붙은 "(N)" 태그로 어느 사건 소속인지
    가르고(incident_map), 목표·확인질문·성공기준·부족한것·주력은 사건별 번호 줄
    (목표1:, 목표2: ...)에서 따로 모은다(*_by_incident). 사건이 하나(대다수)면 이
    분기를 전혀 타지 않아 기존 출력과 완전히 같다 — incident_scope.split()이 이
    결과를 소비한다.
    """
    located = _locate(text)
    if not located:
        return {}

    raw_lines = []
    incidents = []
    for line in located[2].splitlines():
        parsed = LINE_RE.match(line)
        if not parsed:
            continue
        name, num, value = _clean(parsed.group(1)), parsed.group(2), parsed.group(3)
        if name == "사건구분":
            candidates = _split(value)
            if len(candidates) >= MIN_INCIDENTS_FOR_TAGGING:
                incidents = candidates
            continue
        raw_lines.append((name, num, value))

    multi = len(incidents) >= MIN_INCIDENTS_FOR_TAGGING
    found = {key: [] for key in FIELD_MAP.values()}
    investigable, reason = None, ""
    objective, questions, criteria, primary, gaps = "", [], [], "", []
    by_incident = {"objective": {}, "questions": {}, "criteria": {}, "gaps": {}, "primary": {}}
    incident_map = {}

    declared, topics = "", []
    for name, num, value in raw_lines:
        if name == "기사유형":
            declared = _article_type(value) or declared
            continue
        if name == "주제":
            for item in _split(value):
                item = _strip_incident_tag(item)[0] if multi else item
                if item and item not in topics:
                    topics.append(item)
            continue
        if name == "조사가능":
            cleaned = _clean(value)
            investigable = cleaned.startswith("예") or cleaned.lower().startswith("y")
            continue
        if name == "조사불가사유":
            reason = _clean(value)
            continue
        if name in ("목표", "확인질문", "성공기준", "부족한것", "주력"):
            slot = {"목표": "objective", "확인질문": "questions", "성공기준": "criteria",
                    "부족한것": "gaps", "주력": "primary"}[name]
            if multi and num:
                if slot == "objective":
                    by_incident[slot][int(num)] = _clean(value)
                elif slot == "primary":
                    by_incident[slot][int(num)] = _axis(value)
                else:
                    by_incident[slot][int(num)] = _split(value)
                continue
            if slot == "objective":
                objective = _clean(value)
            elif slot == "primary":
                primary = _axis(value)
            elif slot == "questions":
                questions = _split(value)
            elif slot == "criteria":
                criteria = _split(value)
            else:
                gaps = _split(value)
            continue
        key = FIELD_MAP.get(name)
        if not key:
            continue
        values = _split(value)
        if multi:
            clean_values = []
            for item in values:
                clean_value, tag_nums = _strip_incident_tag(item)
                clean_values.append(clean_value)
                if tag_nums:
                    incident_map.setdefault(key, {})[clean_value.lower()] = tag_nums
            found[key] = clean_values
        else:
            found[key] = values

    _split_hostless(found)
    found = {key: values for key, values in found.items() if values}
    if investigable is None:
        investigable = bool(found)
    found["investigable"] = investigable
    if reason:
        found["reason"] = reason
    # 분석 단계의 기사유형 선언과 배경 조사 주제. 조사 경로는 이 선언만으로 정하지 않는다
    # — article_kind.classify가 공격 지표와 함께 보고 정한다(선언이 틀린 위협 기사 방어).
    if declared:
        found["article_type_declared"] = declared
    if topics:
        found["topics"] = topics[:MAX_TOPICS]
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
    # 어휘 밖의 요구다. 기계가 대조할 수 없으니 약속으로 세지 않고, 공백으로 남긴다 —
    # 모델이 "이것도 있어야 한다"고 말할 자리가 없으면 우리가 만든 어휘가 곧 대응의
    # 한계가 된다(실측: 확장 스토어 조회가 필요하다는 것을 모델은 알고 있었는데 그
    # 말을 담을 곳이 없어, 로그를 사람이 읽고 나서야 조회기를 만들었다).
    if gaps:
        found["gaps"] = gaps
    if multi:
        found["incidents"] = incidents
        if incident_map:
            found["incident_map"] = incident_map
        for slot, key in (("objective", "objectives_by_incident"), ("questions", "questions_by_incident"),
                          ("criteria", "criteria_by_incident"), ("gaps", "gaps_by_incident"),
                          ("primary", "primary_by_incident")):
            if by_incident[slot]:
                found[key] = by_incident[slot]
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


@analysis_trace.step("정규식·LLM IOC 병합과 중복 제거", "artifacts", "extraction", inputs=("existing", "targets"))
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
