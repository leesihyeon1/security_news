# -*- coding: utf-8 -*-
"""조회 결과를 읽고 판단해 대응 방안을 낸다 — 심층 분석의 마지막 단계.

무엇이 빠져 있었나
    파이프라인은 기사를 분석하고(LLM), 지표를 뽑고, 외부를 조회했다. 그런데 조회
    결과를 읽고 판단하는 주체가 없었다. LLM은 조회가 시작되기 전에 이미 일을 마쳤고,
    조회 뒤에 남은 것은 규칙 조립뿐이었다.

    그 결과가 숫자로 드러난다(실측 13건): 대응 조치 43개가 서로 다른 틀 13개에서
    찍혀 나왔고, 그중 12개는 기사와 무관한 같은 문장이었다. 확인된 사실도 조회 결과를
    문장으로 옮긴 것이지 해석한 것이 아니었다.

    조사는 자동화됐지만 분석은 없었다. 이 모듈이 그 자리를 맡는다.

무엇을 판단하나
    목표(기사를 읽고 세운 것)를 조회 결과에 비추어 본다.
      - 확인된 것 / 확인 못한 것 / 기사와 어긋나는 것
      - 그래서 무엇을 어떤 순서로 해야 하는가
      - 무엇이 아직 불확실한가
    "조회 결과가 없었다"도 판단 재료다 — 유포지가 안 잡히면 이미 내려갔다는 뜻일 수
    있고, 그건 "안전하다"와 다르다.

지어내기를 막는 방법
    pattern_synth와 같은 규율을 쓴다. 판단문에 나오는 구체값(도메인·IP·해시·CVE·
    패키지)이 조회 재료에 실제로 있는지 대조하고, 없는 값이 섞이면 그 항목을 버린다.
    오늘 그 검증으로 지어낸 CVE와 해시를 실제로 잡아냈다.
"""

import json
import re
import analysis_trace

import article_kind
import common_utils
import analyst_workflow
import primary_sources
import source_evidence

# 조회 재료를 프롬프트에 넣을 때의 상한. 전부 넣으면 프롬프트가 수만 자가 되고,
# 정작 판단에 쓰이는 것은 앞쪽 요약이다.
MAX_FINDINGS = 40
MAX_VALUES_PER_LIST = 30
MAX_MATERIAL_CHARS = 9000
# 판단 항목 상한 — 늘어놓으면 카드가 다시 번잡해진다.
MAX_PLAN_STEPS = 5
MAX_LIST_ITEMS = 5
# 후속 조회 상한. 한 바퀴만 돌리므로 이 안에서 답이 나올 것만 고르게 한다.
MAX_FOLLOWUPS = 4

BS = chr(92)

# 지어내면 위험한 값의 모양. pattern_synth와 같은 기준이다 — 이런 종류가 조회 재료에
# 없이 나오면 그 문장은 근거가 없다.
RISKY_RE = re.compile(
    "(?:[a-z0-9][a-z0-9" + BS + "-]{1,60}" + BS + ".[a-z]{2,18}"      # 도메인
    "|" + BS + "d{1,3}(?:" + BS + "." + BS + "d{1,3}){3}"              # IP
    "|[a-f0-9]{32,64}"                                                 # 해시
    "|CVE-" + BS + "d{4}-" + BS + "d{4,7})", re.I)
# 판단문에 흔히 섞이지만 지표가 아닌 것들 — 제품·도구 이름이라 대조 대상이 아니다.
RISKY_SKIP = {
    "defender.microsoft.com", "virustotal.com", "urlscan.io", "osv.dev",
    "github.com", "nvd.nist.gov", "cisa.gov", "npmjs.com", "pypi.org",
}

PROMPT_HEAD = """당신은 SOC 대응 책임자다. 아래는 (1) 기사 분석, (2) 이 건의 대응 목표,
(3) 그 목표를 확인하려고 외부에서 실제로 조회한 결과다. 조회 결과를 읽고 판단하라.

지켜야 할 것:
- 설명·판단·조치·완료 기준은 한국어로 쓴다. 제품명·필드명·명령·지표의 원래 표기는 유지한다.
- 사건의 핵심을 실행 조건→수집·변조→외부 전송 순으로 설명하고, 버전별로 다른 기능을 합치지 마라.
  샌드박스가 대상 플랫폼·환경 조건을 충족했는지 모르면 무행위를 안전의 증거로 보지 마라.
- 네트워크 지표는 정찰 대상·정상 서비스·유포지·유출 수신지·C2를 구분한다.
  웹훅으로 전송됐다는 사실만으로 명령 수신·원격 제어 C2가 있다고 쓰지 마라.
  구체 유출 주소·동적 관측이 없으면 미확인으로 남기고 확보 경로를 제시하라.
- 탐지안은 공통 행위의 조합과 관측 가능한 데이터로 정당화하라. urlscan은 브라우저 관측이므로
  npm 실행·process.env 접근은 볼 수 없다. 일반 Node.js 프로세스 로그에도 소스코드는 담기지 않는다.
  해당 사건에 맞지 않는 브라우저·Windows 규칙, 단일 일반 파일명(index.js) 탐지를 권하지 마라.
- 기사 원문, 외부 조회 사실, 분석자의 추론, 사내 확인이 필요한 가설을 구분하라.
- 조회 상태가 실패·불가·부분이면 '미탐지'나 '안전'으로 바꾸지 마라. 검색 결과·과거 AI
  분석은 독립 검증이 아니며, 같은 레지스트리의 다른 악성 패키지를 이번 캠페인으로 묶지 마라.
- plan은 사건에 맞는 3~5개 실행안이다. 각 조치에 담당 역할, 발동 조건, 구체적인 로그·필드와
  조사 기간, 보존할 증거, 도구·패치·다운타임 제약 시 대안, 완료 기준을 채워라.
  '추가 조사' 같은 대안 대신 어떤 원본 로그·수동 점검·임시 통제를 쓸지 적어라.
- 확인→범위 파악·증거 보존→조건부 통제→복구 검증의 순서로 계획하라. 감염 미확인 상태에서
  무조건 격리·삭제·전면 키 교체를 지시하지 마라. 침해가 확인되면 해당 증거를 보존하고 범위를
  제한해 통제하며, 복구 후 재발 여부와 정상 업무 복원을 검증하라.
- 검색 0건만으로 종료하지 마라. 로그 수집 범위·보존 기간·센서 상태, 양성 테스트와 대체 로그를
  확인해야 한다. 0건이라는 사실과 감염이 없다는 결론을 구분하라.
- API 키·토큰·개인키 원문은 IOC 피드나 공개 보고서에 넣지 마라. 필요한 경우 접근 제한된
  증거 저장소에 보존하고 공개 결과에는 마스킹된 식별자·해시만 사용하라.
- 블록체인 주소·트랜잭션 해시는 IP/도메인 차단값이 아니다. 지원되는 텔레메트리에서만
  해당 값을 대조하고, 공용 RPC·LLM·CDN 도메인 전체 차단으로 바꾸지 마라.
- 종합 기사는 사건별로 판단하고, 서로 다른 사건의 행위·C2·지표를 연결하지 마라.
- 출처 URL·참고 자료 호스트는 차단 지표가 아니다. 같은 호스트의 다른 URL을 스캔한
  결과는 이 기사나 이 사건의 악성 행위 유무를 입증하지 못한다.
- 조회에서 찾지 못한 것은 미확인이지 기사와의 모순이나 안전의 증거가 아니다.
- 브라우저의 DOM 변경이나 클립보드 쓰기 횟수만으로 악성 유포를 확정하지 마라.
  복사 내용, 화면 안내, 해당 스크립트와 요청 목적지의 연결이 확인돼야 한다.
  격리 브라우저 미실행은 현재 페이지의 안전·악성 여부를 확인한 것이 아니다.
- KEV 미등재와 낮은 EPSS만으로 위험도를 낮추지 마라. EPSS는 향후 30일 악용 확률이며
  피해 영향·자산 노출·기사의 실제 악용 보도를 함께 구분해 판단하라.
- DeviceFileEvents는 파일 읽기·탈취를 증명하지 않는다. 통신·파일 이벤트만으로 실행이나
  감염을 단정하지 말고 프로세스·인증 로그 등 추가 확인 조건을 적어라.
- 아래 기준일보다 지난 기한은 '경과'로 표시하라. 앞으로 다가올 기한으로 쓰지 마라.
- 조회 재료에 없는 도메인·IP·해시·CVE·패키지를 쓰지 마라. 쓰면 그 항목은 버려진다.
- 기사 요약을 되풀이하지 마라. 조회로 무엇이 달라졌는지만 쓴다.
- [확인해야 할 질문]이 있으면 그 순서대로 question_status에 하나씩 판정을 남겨라.
  question은 그 질문 문장을 그대로 옮겨 적어라 — 새로 쓰거나 요약하면 다른 질문으로
  취급돼 버려진다.
- 질문별로 실제 조회·1차 자료의 어느 관측이 답의 근거인지 evidence에 적고, 관련된
  plan 조치가 있으면 그 번호를 plan_index에 적어라. 답을 못 낸 이유도 answer에 적어라.
  파일 해시 확보와 외부 목록의 같은 해시 여부 대조는 별개의 질문이다. 확인한 전자를
  미확인으로 되돌리거나 미확인인 후자를 확인됨으로 합치지 마라.
- 조사에서 특정 보호 기능이 이 샘플을 막지 못했다고 확인했다면 그 기능만 켜는
  조치를 유효한 대안으로 제시하지 마라. 적용 환경에서 검증할 통제와 남는 위험을 써라.
- [전에 우리가 분석한 같은 계열]이 있으면 그 각 항목이 지금 사건과 어떤 관계인지
  campaign_relations에 밝혀라. title은 그 항목의 제목을 그대로 옮겨 적어라. 이름·
  해시가 겹친다는 사실만으로 "동일 캠페인"이라 쓰지 마라 — 노린 대상·활동 시기·
  목적이 같은지, 기사·1차 자료가 서로를 직접 인용하는지, 샘플·설정·인프라가 실제로
  이어지는지를 본다. 그중 아무 근거도 없이 이름·해시만 같으면 "같은 도구만 사용"
  이나 "무관"으로 써라. 판단할 근거가 부족하면 "판단 보류"로 남겨라.
- "결과가 없었다"도 판단 재료다. 유포지가 안 잡히면 이미 내려갔다는 뜻일 수 있고,
  그것은 "안전하다"와 다르다. 없는 것을 없다고 쓰고, 그 뜻을 밝혀라.
- 우리 조직에 해당하지 않으면 해당하지 않는다고 쓰라. 억지로 조치를 만들지 마라.
- exposure는 "미확인"으로 끝내지 마라. 사내 로그에 접근할 수 없는 것은 사실이지만,
  피해 규모·악용 대상·탈취 대상은 이미 재료에 있다. 그것으로 "우리 쪽에서 무엇이
  위험한가"까지 밀고 가되, 측정이 아니라 추론임을 밝히고 무엇을 보면 확정되는지 적어라.
  해당 사항이 정말 없으면 who에 "해당 없음"과 그 이유를 쓴다.
- 이미 해 놓은 일을 조치로 쓰지 마라. 아래 [기사가 인용한 1차 자료 원문]은 우리가 이미
  받아서 읽은 것이고, 조회 결과도 이미 돌린 것이다. "원문을 입수하라", "IOC를 수집하라"
  처럼 이미 손에 있는 것을 구해 오라는 조치는 실행할 일이 없다 — 그 자료로 무엇을 할
  것인지를 써라.
- plan의 done은 비워 두지 마라. "차단했다"가 아니라 "무엇을 확인하면 끝난 것인가"를
  쓴다. 쿼리 결과가 0건이면 끝인지, 0건이어도 다른 것을 더 봐야 하는지가 갈린다 —
  그 구분이 없으면 실행하는 사람이 판단을 대신 해야 한다.
- timeline은 이 사건이 어떻게 흘러왔는지를 읽는 곳이다. "언제 시작해서, 언제
  드러나서, 지금 어디까지 왔나"가 보여야 한다 — 공격 활동 기간, 침해·탈취가 일어난
  시점, 1차 자료·연구 보고서가 공개된 날, 인프라가 등록되거나 마지막으로 관측된 날처럼
  사건의 사건을 먼저 쓴다.
  CVE 공개일이나 샌드박스 최초 등록일은 우리가 조회하다 알게 된 날짜지 이 사건의
  사건이 아니다. 그것만 늘어놓으면 시간축이 조회 기록이 된다 — 사건 쪽 날짜를 다 쓰고
  자리가 남을 때만 넣어라.
  재료에 실제로 적힌 날짜만 쓴다. 없으면 빈 배열로 두고, 날짜를 지어내지 마라.

[출력 형식 — JSON 하나만. 설명 문장을 앞뒤에 붙이지 마라]
{
  "verdict": "목표 달성 여부: 확인됨 | 부분 확인 | 미확인",
  "headline": "지금 상황을 한 문장으로(조회 결과 기준, 80자 안팎). 세부 사실·미확인 목록은 confirmed·unconfirmed에 나눠 쓰고 여기에 이어 붙이지 마라",
  "confirmed": ["조회로 확인된 사실. 무엇을 근거로 확인됐는지까지"],
  "unconfirmed": ["확인하지 못한 것과 그 이유"],
  "contradictions": ["기사 주장과 조회 결과가 어긋나는 점. 없으면 빈 배열"],
  "plan": [
    {"action": "무엇을 한다", "why": "출처와 근거, 왜 이 순서인가", "when": "즉시|오늘|이번 주|기한 날짜",
     "owner": "개인 이름이 아닌 담당 역할", "trigger": "어떤 근거·영향 자산이 확인되면 실행하는가",
     "check": "어느 로그·필드·기간으로 어떤 정상/악성 가설을 구분하는가",
     "preserve": "변경 전에 보존할 원본 증거와 시각·출처",
     "alternative": "도구가 없거나 즉시 조치할 수 없을 때 실행할 대안과 남는 위험",
     "done": "양성·0건 결과별 확인, 복구와 종료 조건. 불충분하면 미확인으로 유지"}
  ],
  "open_questions": ["대응을 마치려면 추가로 확인해야 할 것"],
  "exposure": {
    "who": "우리 환경에서 무엇이 어떻게 위험한가. 사내 로그가 없어도 조회 결과와 기사의 사실로 추론하라 — 그 확장을 쓰는 사람이 있다면 무엇이 털리는지, 그 제품을 쓴다면 어디까지 열리는지",
    "basis": "그렇게 본 근거. 조회 결과나 기사의 어느 사실인지 밝혀라",
    "confirm": "이 추정을 사실로 바꾸려면 무엇을 보면 되는가(우리가 볼 수 있는 것으로)"
  },
  "timeline": [
    {"when": "날짜 또는 기간", "what": "그때 무슨 일이 있었나", "source": "어디서 나온 날짜인가"}
  ],
  "followups": [
    {"type": "domain|ip|hash|cve|package", "value": "조회할 값", "lookup": "urlscan|virustotal|nvd|registry",
     "question": "무엇을 확인하려는가",
     "ecosystem": "package인 경우 원문에서 확인한 npm|pip, 불명확하면 빈 문자열"}
  ],
  "question_status": [
    {"question": "[확인해야 할 질문]의 질문을 그대로", "status": "answered|partial|open",
     "answer": "조회 재료로 답한 내용. 못 답했으면 왜 못 했는지",
     "evidence": "답의 출처와 실제 관측. 없으면 빈 문자열",
     "plan_index": "관련 plan 조치의 1부터 시작하는 번호. 없으면 0"}
  ],
  "campaign_relations": [
    {"title": "[전에 우리가 분석한 같은 계열]의 제목을 그대로",
     "relation": "동일 캠페인|관련 가능성|같은 도구만 사용|무관|판단 보류",
     "why": "그렇게 본 근거"}
  ]
}

followups에 대해:
- 후속 조회에서 domain/ip은 urlscan의 공개 페이지 관측 건수·최근 스캔 시각만,
  hash는 VirusTotal의 파일 보고서·동적 관측만, cve는 NVD/KEV 조회만,
  package는 레지스트리 등재·OSV만 확인한다. lookup도 해당 도구 이름으로 쓴다.
  urlscan IP 검색으로 연관 샘플·C2 프로토콜·동일 운영자를 판정할 수 없다.
  이 도구로 답할 수 없는 질문은 followups에 넣지 말고 open으로 남겨라.
- value는 조회 재료에 이미 나온 값이어야 한다. 새로 지어낸 값은 버려진다.
- 답이 이미 조회 재료에 있으면 넣지 마라. 같은 것을 두 번 조회하게 된다.
- 없으면 빈 배열로 두라.
"""


def log(message):
    print(message)


def _material(investigation, targets):
    """LLM에 넘길 조회 재료. 원자료 그대로가 아니라 판단에 쓰이는 부분만 추린다."""
    lines = []
    browser_lines = []
    for check in investigation.get("goal_evidence") or []:
        browser_lines.append("[목표 증거 점검] {} | 현재 {} | 필요한 것 {} | 근거 {}".format(
            str(check.get("question") or "")[:150], check.get("status") or "open",
            str(check.get("missing") or "없음")[:150], check.get("basis") or ""))
    for item in investigation.get("indicator_assessments") or []:
        if item.get("role"):
            lines.append("[지표 역할] {}: {} | {}".format(item.get("value"), item["role"],
                                                      str(item.get("evidence") or "")[:350]))
    for file in (investigation.get("malware") or {}).get("files") or []:
        lines.append("[샘플 관측] " + json.dumps({"hash": file.get("hash"), "error": file.get("error"),
                     "behaviour": file.get("behaviour"), "report": file.get("report"),
                     "sandbox_reports": ((file.get("enrichment") or {}).get("sandboxes") or [])[:2]},
                     ensure_ascii=False)[:3200])
        for sandbox in ((file.get("enrichment") or {}).get("sandboxes") or [])[:2]:
            lines.append("[샌드박스별 상세] {} | {} | 프로세스 {} | HTTP {}".format(
                sandbox.get("name") or "", sandbox.get("verdict") or "미판정",
                ", ".join(sandbox.get("process_tree") or [])[:250],
                json.dumps((sandbox.get("http") or [])[:3], ensure_ascii=False)[:400]))
    for entry in investigation.get("lookup_status") or []:
        lines.append("[조회 상태] {}: {} — {}".format(
            entry.get("key"), entry.get("status"), entry.get("detail") or ""))
        if entry.get("url"):
            lines.append("대상: " + str(entry["url"]))
    for source in (investigation.get("primary") or {}).get("sources") or []:
        lines.append("[실제로 읽은 출처] {} | 수집 {} | 발췌 해시 {}".format(
            source.get("url"), source.get("retrieved_at") or "미기록",
            str(source.get("excerpt_sha256") or "미기록")[:16]))
    route = investigation.get("route") or {}
    if route.get("label"):
        lines.append("[조사 방향] {} — {}".format(route["label"], route.get("explain") or ""))

    def add_findings(label, values):
        if not values:
            return
        lines.append("[{}]".format(label))
        lines.append("\n".join("- " + str(v) for v in values[:MAX_FINDINGS])[:900])

    add_findings("URL 분석 결과", investigation.get("findings"))
    browser_track = investigation.get("browser_research") or {}
    for question in browser_track.get("questions") or []:
        browser_lines.append("[페이지 조사 목표] " + str(question)[:180])
    for result in browser_track.get("results") or []:
        if result.get("source") == "archived_scan":
            observed = result.get("evidence") or {}
            browser_lines.append("[질문별 URL 증거] {} | {} | DOM {} | 요청 {}건 | {}".format(
                observed.get("evidence_id") or "", observed.get("domain") or "",
                observed.get("dom_status") or "미확인", len(observed.get("http") or []),
                observed.get("scan_url") or ""))
        elif result.get("status") == "observed":
            observed = result.get("evidence") or {}
            browser_lines.append("[격리 브라우저 관측] {} | 조작 {} | DOM 변경 {} | 클립보드 {}건 | 클릭 후 HTTP {}건".format(
                observed.get("evidence_id") or "", observed.get("action") or "",
                (observed.get("before") or {}).get("dom_sha256") !=
                (observed.get("after") or {}).get("dom_sha256"),
                len(observed.get("clipboard") or []),
                sum(row.get("phase") == "after" for row in observed.get("responses") or [])))
            for command in (observed.get("clipboard") or [])[:2]:
                browser_lines.append("[복사된 명령 특징] {} | 실행도구 {} | 목적지 {}".format(
                    command.get("sha256") or "", command.get("executable") or "",
                    ", ".join("{}{}".format(url.get("host") or "", url.get("path") or "")
                              for url in command.get("destinations") or [])))
            for response in (observed.get("responses") or [])[:16]:
                browser_lines.append("[페이지 HTTP] {} {}{} | 쿼리키 {} | 상태 {} | 본문 {} | 특징 {} | 시작점 {}".format(
                    response.get("phase") or "", response.get("host") or "",
                    response.get("path") or "/", ",".join(response.get("query_keys") or []),
                    response.get("status"), response.get("body_sha256") or
                    response.get("body_unobserved") or "미확인",
                    ",".join(response.get("features") or []),
                    (response.get("initiator") or {}).get("path") or "")[:340])
        else:
            browser_lines.append("[격리 브라우저 미확인] " + str(result.get("reason") or "미실행"))
    add_findings("VirusTotal 동적분석", (investigation.get("malware") or {}).get("findings"))
    add_findings("취약점 조회(KEV·EPSS·NVD)", (investigation.get("vulnerability") or {}).get("findings"))
    add_findings("패키지 레지스트리 조회", (investigation.get("supply_chain") or {}).get("findings"))
    for key, label in (("intel", "교차 인텔 조회"), ("github", "저장소 조회"),
                       ("extension", "확장 프로그램 조회"), ("web", "연구 자료 검색 후보")):
        add_findings(label, (investigation.get(key) or {}).get("findings"))

    vuln = investigation.get("vulnerability") or {}
    if vuln.get("cves"):
        lines.append("[조회된 CVE]")
        for entry in vuln["cves"][:MAX_FINDINGS]:
            lines.append("- {} | KEV {} | EPSS {} | 기한 {}".format(
                entry.get("cve"), "등재" if (entry.get("kev") or {}).get("added") else
                "미등재" if entry.get("kev_checked") is True else "조회 상태 미확인",
                entry.get("epss"), (entry.get("kev") or {}).get("due") or "-"))

    response = investigation.get("response") or {}
    for block in response.get("blocklists") or []:
        values = block.get("values") or []
        lines.append("[{} — {}건]".format(block.get("label") or "차단 후보", len(values)))
        lines.extend("- " + str(v) for v in values[:MAX_VALUES_PER_LIST])
    if response.get("kql"):
        lines.append("[헌팅 후보 — 사내 실행 미검증] " + ", ".join(
            q.get("name") or "" for q in response["kql"]))
        for query in response["kql"][:5]:
            lines.append("- {}: {}".format(query.get("name"), query.get("note") or ""))
    if response.get("commands"):
        lines.append("[준비된 단말 명령] " + ", ".join(
            c.get("name") or "" for c in response["commands"]))

    assets = targets.get("assets") if isinstance(targets, dict) else None
    if assets:
        lines.append("[자산 매칭] " + ", ".join(assets))

    text = "\n".join(browser_lines[:24] + lines)
    return text[:MAX_MATERIAL_CHARS]


def build_prompt(title, analysis, targets, investigation, primary="", extra="",
                 history="", article=""):
    objective = (targets or {}).get("objective") or ""
    questions = (targets or {}).get("questions") or []
    return (
        PROMPT_HEAD
        + "\n[판단 기준일 UTC] " + common_utils.utc_now_iso()[:10]
        # 우리 환경. 이걸 안 주면 "우리 쪽에서 무엇이 위험한가"를 재료 없이 묻는 셈이다.
        + ("\n" + common_utils.environment_brief() + "\n"
           if common_utils.environment_brief() else "")
        + "\n[기사 제목]\n" + (title or "")
        # 본문 앞부분만 자르면 후반의 해시 표·기술 상세가 빠진다 — 질문과 기술 구간을 고른다.
        + ("\n\n[기사 원문 — 보도이며 사내 관측은 아님]\n"
           + primary_sources.evidence_excerpt(article, questions, limit=12000) if article else
           "\n\n[제약] 기사 원문 미제공: 기존 AI 분석을 독립 검증 근거로 간주하지 마라.")
        + "\n\n[기존 AI 분석 — 원문과 대조할 가설]\n" + (analysis or "")[:4000]
        + "\n\n[이 건의 대응 목표]\n" + (objective or "(설정되지 않음 — 조회 결과로 직접 판단하라)")
        + ("\n\n[확인해야 할 질문]\n" + "\n".join("- " + q for q in questions) if questions else "")
        + "\n\n[외부 조회 결과]\n" + _material(investigation, targets or {})
        # 원문마다 기사 인용/검색 참고 여부를 표시한다. 후속 검색 자료를 기사 인용으로 격상하지 않는다.
        + ("\n\n[읽은 원문 — 출처 유형 표시]\n" + primary if primary else "")
        # 후속 조회로 새로 얻은 것. 1차 판단에서 못 답한 질문의 답이 여기 있다.
        + ("\n\n[후속 조회 결과]\n" + extra if extra else "")
        # 전에 우리가 분석한 같은 계열. 같은 수법이 반복되는지는 기록에서만 보인다.
        + ("\n\n" + history if history else "")
        + "\n\nJSON만 출력하라."
    )


def _close_truncated(text):
    """max_tokens에서 잘린 JSON을 마지막으로 완결된 항목까지 되살린다.

    문자열 밖의 쉼표 위치마다 그 시점의 괄호 스택을 기록해 두고, 뒤에서부터 "거기서
    자르고 열린 괄호를 닫은 것"을 파싱해 본다. 잘린 뒤쪽(대개 followups·timeline)만
    잃고 앞쪽의 판단·확인 사실·계획은 남는다.
    """
    stack, in_string, escaped, cuts = [], False, False, []
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            stack.append("}" if char == "{" else "]")
        elif char in "}]":
            if stack:
                stack.pop()
        elif char == "," and (len(stack) == 1 or stack[-1] == "]"):
            # 최상위 필드 사이이거나 배열 원소 사이에서만 자른다. 안쪽 객체의 필드
            # 사이에서 자르면 {"type": "hash"}처럼 값이 빠진 반쪽 항목이 살아남는다.
            cuts.append((index, "".join(reversed(stack))))
    for index, closing in reversed(cuts[-300:]):
        try:
            data = json.loads(text[:index] + closing)
        except ValueError:
            continue
        if isinstance(data, dict):
            return data
    return None


@analysis_trace.step("종합 판단 JSON 파싱·잘림 복구", kind="validation", inputs=("raw",))
def parse_with_status(raw):
    """(dict, salvaged). salvaged는 잘린 응답을 되살렸는지 — 판단 단계에 남긴다."""
    if not raw:
        return {}, False
    text = raw.strip()
    fence = re.search(r"```(?:json)?\s*(.+?)```", text, re.S)
    if fence:
        text = fence.group(1).strip()
    start = text.find("{")
    if start < 0:
        return {}, False
    text = text[start:]
    # 실측(2026-09-26): 응답이 "{\n {"verdict": ..."처럼 여는 중괄호를 한 번 더
    # 찍고 시작했다. 겹친 여는 괄호는 하나로 줄인다.
    text = re.sub(r"^\{\s*(?=\{)", "", text)
    try:
        # raw_decode는 앞의 객체 하나만 읽고 뒤에 붙은 설명·여분 괄호는 무시한다.
        data, _ = json.JSONDecoder().raw_decode(text)
        if isinstance(data, dict):
            return data, False
    except ValueError:
        pass
    data = _close_truncated(text)
    return (data, True) if data else ({}, False)


def parse(raw):
    """응답에서 JSON 객체를 꺼낸다. 앞뒤에 설명이 붙어 있거나 끝이 잘려도 살려 낸다."""
    return parse_with_status(raw)[0]


# 무해화 표기 → 실제 값. analysis_targets와 같은 규칙이다.
DEFANG_SUBS = (("[.]", "."), ("[:]", ":"), ("[/]", "/"), ("(.)", "."),
               ("(dot)", "."), ("[dot]", "."), ("hxxps", "https"), ("hxxp", "http"))


def _corpus(investigation, analysis, primary="", extra=""):
    """근거 대조용 텍스트 — 조회 재료·기사 분석·1차 자료·후속 조회를 합친 것.

    1차 자료를 빼놓았다가 크게 틀렸다. 실측(2026-09-16, 악성 확장 프로그램 건):
    socket.dev와 DomainTools 원문을 읽어 프롬프트에 넣어 놓고, 판단이 거기서 인용한
    manusai.sbs·forti-vpn.com·api.sprocketwhirl 같은 값을 "기사에 없다"며 폐기했다.
    대응 계획 4건이 그렇게 잘려 나갔다 — 1차 자료를 읽는 기능이 읽을수록 손해를 내는
    상태였다. 모델에게 근거로 준 글은 검증에서도 근거로 쳐야 한다.
    """
    blob = " ".join([
        json.dumps(investigation, ensure_ascii=False),
        analysis or "", primary or "", extra or "",
    ]).lower()
    # 1차 자료는 IOC를 무해화해 쓴다. 모델은 정상 형태로 복원해 답하므로, 코퍼스를
    # 그대로 두면 그 값이 "지어낸 것"으로 판정된다 — 실측(2026-09-17): DomainTools
    # 원문에 sprocketwhirl[.]top·manusai[.]sbs로 적혀 있었고, 판단이 쓴
    # sprocketwhirl.top·manusai.sbs가 폐기돼 대응 계획 4건이 잘려 나갔다.
    for fanged, plain in DEFANG_SUBS:
        blob = blob.replace(fanged, plain)
    return blob


def _invented(text, corpus):
    """문장에 조회 재료에 없는 지표가 섞였는지. 섞였으면 그 값들을 돌려준다."""
    bad = []
    for match in RISKY_RE.findall(str(text or "")):
        value = match.lower().strip(".")
        if value in RISKY_SKIP or len(value) < 5:
            continue
        if value not in corpus:
            bad.append(match)
    return bad


def _clean_list(values, corpus, dropped):
    out = []
    for value in values or []:
        text = " ".join(str(value).split())
        if not text:
            continue
        bad = _invented(text, corpus)
        if bad:
            dropped.append("근거 없는 값({}) — {}".format(", ".join(bad[:2]), text[:50]))
            continue
        out.append(text)
        if len(out) >= MAX_LIST_ITEMS:
            break
    return out


ALLOWED_QUESTION_STATUS = {"answered", "partial", "open"}
ALLOWED_RELATIONS = {"동일 캠페인", "관련 가능성", "같은 도구만 사용", "무관", "판단 보류"}
# 공격 사건 판단의 verdict. 화면은 이 셋만 색으로 구분하고 나머지는 회색으로 그대로
# 찍는다 — 20자로 자르기만 하면 "목표 달성 여부: 부분 확인" 같은 형식 문구나 임의의
# 값이 그대로 배지가 된다.
ALLOWED_VERDICTS = ("확인됨", "부분 확인", "미확인")


def normalize_verdict(value):
    """허용된 verdict로 맞춘다. 형식 문구가 붙은 값은 그 안의 허용 값을 쓰고, 나머지는
    미확인이다 — 판정이 불분명한 것을 확인된 쪽으로 올리지 않는다."""
    compact = re.sub(r"\s+", "", str(value or ""))
    if "부분확인" in compact or "일부확인" in compact:
        return "부분 확인"
    if "미확인" in compact:
        return "미확인"
    if "확인됨" in compact:
        return "확인됨"
    return "미확인"


def question_status(data, questions, corpus, plan_positions=None):
    """확인질문 판정. 실제로 물어본 질문(공백 정리 후 일치)만 받고, 답은 근거
    검사를 거친다 — 그라운딩이 통과 못 해도 질문·상태는 남긴다(무엇이 안 풀렸는지는
    그 자체로 진행 상황이다), 근거 없는 answer 텍스트만 비운다."""
    valid = {" ".join(str(q).split()) for q in questions or []}
    out, seen = [], set()
    for item in (data or {}).get("question_status") or []:
        if not isinstance(item, dict):
            continue
        question = " ".join(str(item.get("question") or "").split())
        if question not in valid or question in seen:
            continue
        seen.add(question)
        status = str(item.get("status") or "").strip().lower()
        if status not in ALLOWED_QUESTION_STATUS:
            status = "open"
        answer = " ".join(str(item.get("answer") or "").split())[:300]
        if answer and _invented(answer, corpus):
            answer = ""
        evidence = " ".join(str(item.get("evidence") or "").split())[:300]
        if evidence and _invented(evidence, corpus):
            evidence = ""
        if status == "answered" and not (answer and evidence):
            status = "open"
        row = {"question": question, "status": status, "answer": answer}
        if evidence:
            row["evidence"] = evidence
        try:
            plan_index = int(item.get("plan_index") or 0)
        except (TypeError, ValueError):
            plan_index = 0
        if plan_index in (plan_positions or {}):
            row["plan_index"] = plan_positions[plan_index]
        out.append(row)
    return out


def campaign_relations(data, related, corpus):
    """과거 분석과의 관계 판정. 실제로 제시한 후보 제목만, 관계는 정해진 값만 받는다
    — 지어낸 제목이나 "동일 캠페인" 같은 강한 판정이 근거 없이 통과하지 않게 한다."""
    valid = {" ".join(str(item.get("title") or "").split()) for item in related or []}
    out, seen = [], set()
    for item in (data or {}).get("campaign_relations") or []:
        if not isinstance(item, dict):
            continue
        title = " ".join(str(item.get("title") or "").split())
        if title not in valid or title in seen:
            continue
        relation = str(item.get("relation") or "").strip()
        if relation not in ALLOWED_RELATIONS:
            continue
        seen.add(title)
        why = " ".join(str(item.get("why") or "").split())[:200]
        if why and _invented(why, corpus):
            why = ""
        out.append({"title": title, "relation": relation, "why": why})
    return out


# ── 확인된 사실의 출처 ───────────────────────────────────────────────────────
# 판단은 "무엇이 확인됐나"를 confirmed에 문장으로 쓴다. 화면의 조사 결과는 이 문장을
# 핵심 사실로 보여 주는데, 문장만으로는 어느 조회에서 나온 사실인지 보이지 않았다 —
# 그래서 조사 결과 칸에는 조회 도구의 관측 문장(urlscan 스캔 건수·제목)이 대신 올라가
# 있었다(실측 2026-09-28, Lunex 건: 상위 3건이 주변 도메인 2곳의 스캔 설명과 ClickFix
# 상용문이었고, VT 판정·드라이버 CVE·1차 자료 분석은 결과 칸에 없었다).
# 문장 속 도구 이름·1차 자료 이름을 먼저 보고, 없을 때만 값(해시·CVE·도메인)을 조사
# 블록과 대조한다. 모델을 다시 부르지 않는다.
FINDING_SOURCE_LABELS = {
    "primary": "1차 자료", "malware": "VirusTotal", "intel": "교차 인텔",
    "user_action": "urlscan", "vulnerability": "NVD·KEV", "supply_chain": "레지스트리",
    "extension": "확장 스토어", "github": "GitHub", "web": "연구 자료 검색", "article": "기사 원문",
}
FINDING_SOURCE_HINTS = (
    ("malware", re.compile(r"\bVT\b|VirusTotal|샌드박스|동적\s*분석|malware\s*조회", re.I)),
    ("intel", re.compile(r"\bOTX\b|ThreatFox|URLhaus|Shodan|RDAP|교차\s*인텔|intel\s*조회", re.I)),
    ("user_action", re.compile(r"urlscan", re.I)),
    ("vulnerability", re.compile(r"\bNVD\b|\bKEV\b|\bEPSS\b|\bCVSS\b", re.I)),
    # 그냥 "레지스트리"는 넣지 않는다 — 악성코드 기사에서는 윈도 레지스트리(Run 키 등)라서
    # 패키지 레지스트리 조회로 잘못 붙는다(실측 2026-09-28, Lunex 건).
    ("supply_chain", re.compile(r"\bnpm\b|PyPI|RubyGems|패키지\s*레지스트리|\bOSV\b", re.I)),
    ("extension", re.compile(r"웹\s*스토어|애드온\s*스토어|엣지\s*애드온", re.I)),
    ("github", re.compile(r"GitHub", re.I)),
    ("web", re.compile(r"연구\s*자료\s*검색|웹\s*검색", re.I)),
    ("article", re.compile(r"기사\s*(?:원문|본문|보도)|보도에\s*따르면", re.I)),
)
# \b를 쓰지 않는다 — 한글 조사가 붙으면("…8554e1은") 경계가 안 생겨 해시를 못 잡는다.
HEX_VALUE_RE = re.compile(r"(?<![a-f0-9])[a-f0-9]{32,64}(?![a-f0-9])", re.I)
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
MAX_KEY_FINDINGS = 6


def _source_tags(line, investigation):
    """이 사실이 어느 조회·자료에서 나왔는지. [{"key","label"}], 못 가리면 []."""
    tags, seen = [], set()

    def add(key, label=None):
        label = label or FINDING_SOURCE_LABELS[key]
        if label not in seen:
            seen.add(label)
            tags.append({"key": key, "label": label})

    text = str(line or "")
    compact = re.sub(r"[\s._-]", "", text.lower())
    for source in (investigation.get("primary") or {}).get("sources") or []:
        host = str(source.get("host") or "").lower()
        if host.startswith("www."):
            host = host[4:]
        # 호스트 첫 조각(ontinue·arcticwolf)이 문장에 있으면 그 자료다. 세 글자 이하는
        # 뺀다 — "amd" 같은 조각은 제품 이름으로 흔히 나와 오인한다.
        token = host.split(".")[0]
        if len(token) >= 4 and token in compact:
            add("primary", "1차 자료 · " + host)
    for key, pattern in FINDING_SOURCE_HINTS:
        if pattern.search(text):
            add(key)
    if tags:
        return tags
    hashes = {h.lower() for h in HEX_VALUE_RE.findall(text)}
    files = {str(f.get("hash") or "").lower() for f in (investigation.get("malware") or {}).get("files") or []}
    if hashes & files:
        add("malware")
    cves = {c.upper() for c in CVE_ID_RE.findall(text)}
    known_cves = {str(e.get("cve") or "").upper() for e in (investigation.get("vulnerability") or {}).get("cves") or []}
    if cves & known_cves:
        add("vulnerability")
    seeds = {str(s.get("domain") or "").lower() for s in investigation.get("seeds") or []}
    if seeds and any(seed and seed in text.lower() for seed in seeds):
        add("user_action")
    return tags


def key_findings(confirmed, investigation):
    """조사 결과 칸에 올릴 핵심 사실 — 확인된 사실 + 출처 꼬리표."""
    return [{"fact": line, "sources": _source_tags(line, investigation or {})}
            for line in (confirmed or [])[:MAX_KEY_FINDINGS]]


# 차단을 지시하는 조치문. 차단 근거가 없는 값을 막으라고 하면 역할 판정과 결론이 서로
# 어긋난다(실측 2026-09-28, Lunex 건: 원문이 역할을 밝히지 않아 차단 목록에서 빠진
# 도메인 3곳을 할 일이 "피싱 도메인 차단"으로 권고했다).
BLOCK_INTENT_RE = re.compile(r"차단|블록|\bblock|\bdeny\b|싱크홀|sinkhole", re.I)


def _unblockable_hosts(investigation):
    """({차단 금지 역할 호스트}, {역할 미확정 호스트}) — 둘 다 소문자.

    둘을 나눈다. 정찰 대상·클라우드 메타데이터·비공인 주소처럼 "막으면 안 된다"가
    확정된 값과, 원문이 역할을 안 밝혀 "아직 모르는" 값은 다르다 — 뒤쪽을 막으라는
    조치를 지우면 관찰해야 할 값까지 사라진다.
    """
    context, unknown, actionable = set(), set(), set()
    for item in (investigation or {}).get("indicator_assessments") or []:
        kind = str(item.get("type") or "").lower()
        if kind not in source_evidence.NETWORK_KINDS or not item.get("role"):
            continue
        value = str(item.get("value") or "").lower()
        host = common_utils.host_from_indicator(value) or value
        if item.get("actionable") is True:
            actionable.add(host)
        elif item.get("role") in source_evidence.CONTEXT_ROLES:
            context.add(host)
        else:
            unknown.add(host)
    # 같은 호스트가 한쪽(도메인)에서 확정되고 다른 쪽(URL)에서 미확정이면 확정을 따른다.
    context -= actionable
    return context, unknown - actionable - context


def _block_review(action, never_block, unconfirmed):
    """차단 조치문에 든 값을 (차단 금지, 역할 미확정, 나머지)로 가른다.

    차단 조치가 아니면 셋 다 빈 목록이다.
    """
    if not (never_block or unconfirmed) or not BLOCK_INTENT_RE.search(action or ""):
        return [], [], []
    mentioned = []
    for match in RISKY_RE.findall(action):
        value = match.lower().strip(".")
        host = common_utils.host_from_indicator(value) or value
        if host not in mentioned:
            mentioned.append(host)
    blocked = [value for value in mentioned if value in never_block]
    doubtful = [value for value in mentioned if value in unconfirmed]
    return blocked, doubtful, [value for value in mentioned
                               if value not in never_block and value not in unconfirmed]


# 패키지 후속 조회의 생태계는 원문에 그 이름이 있어야 한다. 모델이 "pip"를 골랐다는
# 것만으로는 근거가 아니다 — 카테나-X 제휴 기사에서 원문에 npm·pip 언급이 없는데
# "catena-x" pip 조회가 돌았다(실측 2026-09-30).
ECOSYSTEM_ALIASES = {"npm": "npm", "pip": "pip", "pypi": "pip"}
ECOSYSTEM_SOURCE_RE = {
    "npm": re.compile(r"(?<![a-z0-9])npm(?![a-z0-9])", re.I),
    "pip": re.compile(r"(?<![a-z0-9])(?:pip|pypi)(?![a-z0-9])", re.I),
}


def followups(data, corpus, source=None):
    """LLM이 요청한 후속 조회 중 실행할 만한 것만. 지어낸 값은 버린다.

    조회 재료에 없던 값을 조회하겠다는 것은 없는 지표를 쫓는 것이다 — 그걸 돌리면
    시간만 쓰고 "결과 없음"이 나오는데, 그 결과가 다시 판단 재료로 들어간다.

    source는 기사 원문·분석(모델이 만든 것이 아닌 글). 주면 패키지 생태계 이름이 그
    안에 있어야 받는다. None이면 이 대조를 건너뛴다(예전 호출과 같은 동작).
    """
    allowed = {"domain": "urlscan", "ip": "urlscan", "hash": "virustotal",
               "cve": "nvd", "package": "registry"}
    out, seen = [], set()
    for item in (data or {}).get("followups") or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "").strip().lower()
        value = " ".join(str(item.get("value") or "").split())
        key = (kind, value.lower())
        if kind not in allowed or not value or key in seen:
            continue
        lookup = str(item.get("lookup") or allowed[kind]).strip().lower()
        if lookup != allowed[kind]:
            continue
        question = " ".join(str(item.get("question") or "").split())[:120]
        if kind in ("domain", "ip") and re.search(
                r"추가.{0,8}샘플|통신\s*프로토콜|운영자|동일\s*캠페인|"
                r"C2.{0,8}확정|추가\s*패널|VT|OTX|ThreatFox|Shodan", question, re.I):
            continue
        if value.lower() not in corpus:
            continue
        seen.add(key)
        # The displayed question must describe what this lookup actually measures.
        if item.get("lookup"):
            question = {
                "domain": "urlscan에서 공개 페이지 스캔 관측과 최근 시각은?",
                "ip": "urlscan에서 이 IP의 공개 페이지 스캔 관측과 최근 시각은?",
                "hash": "VirusTotal에서 이 해시의 파일·동적 관측은?",
                "cve": "NVD·KEV에서 이 CVE의 공개 상태는?",
                "package": "레지스트리에서 이 패키지의 등재·OSV 상태는?",
            }[kind]
        request = {"type": kind, "value": value, "question": question}
        if kind == "package":
            ecosystem = ECOSYSTEM_ALIASES.get(str(item.get("ecosystem") or "").strip().lower())
            if not ecosystem:
                continue
            if source is not None and not ECOSYSTEM_SOURCE_RE[ecosystem].search(source):
                continue
            request["ecosystem"] = ecosystem
        out.append(request)
        if len(out) >= MAX_FOLLOWUPS:
            break
    return out


# 날짜처럼 생긴 것. timeline 항목이 근거 있는 날짜를 담았는지 보는 데만 쓴다.
DATE_RE = re.compile(r"\d{4}[-./년]\s*\d{1,2}|\d{1,2}[-./월]\s*\d{1,2}|\d{4}")
MAX_TIMELINE = 8
# 판단 호출은 실패해도 대신할 것이 없다. 조사를 다 끝내 놓고 이 한 번이 타임아웃 나면
# 조사 결과는 남는데 판단·할 일·시간축·영향이 통째로 빈다 — 실측(09-18): 6건 중 2건이
# 그렇게 됐고, 둘 다 조사는 53단계·42단계까지 정상으로 돌았다. llm_generate의 기본
# 재시도(2회)는 기사마다 수백 번 도는 호출을 위한 값이라, 회차당 한 번뿐인 이 호출에는
# 더 버티게 한다.
SYNTH_ATTEMPTS = 2
# 판단 모델은 추론 모델이라 생각에 쓴 토큰도 상한에서 깎인다. 기본 8192로는 추론만
# 4~5천 토큰을 쓰고 본문 JSON이 followups 중간에서 잘렸다(실측 2026-09-26,
# finish_reason=length, 판단이 통째로 비었다). 상한을 올리면 생성 시간도 늘어나므로
# 타임아웃도 같이 올린다 — 8192 토큰 한 번에 180초가 걸렸다.
SYNTH_MAX_TOKENS = 16384
SYNTH_TIMEOUT = 420
COMPACT_RETRY_NOTE = (
    "\n\n[재요청] 앞선 응답이 길이 상한에서 잘렸거나 JSON이 아니었다. JSON 하나만 출력하라. "
    "모든 문자열 필드는 두 문장 이내로 줄이고, plan은 3개, timeline은 5개, followups는 "
    "2개 이하로 쓴다. 필드를 빼지는 마라.")
# 우리가 조회하다 알게 된 날짜 — NVD 공개일, 샌드박스 최초 등록일. 사건의 사건이
# 아니라 조회의 부산물이라, 자리가 모자라면 이쪽부터 버린다.
#
# 실측(Anthropic 위협 보고서 기사): 시간축 6줄이 CVE 공개일 4개와 VT 최초 등록일
# 2개로 다 찼다. 같은 조사에서 나온 Anthropic 보고서 관측 기간, Zscaler 공개일,
# 피싱 도메인 등록일은 모델이 뒤에 적었다가 앞에서 자르는 바람에 통째로 빠졌다.
REGISTRY_EVENT_RE = re.compile(
    r"공개일|공개\s*\(|최초\s*등록|최초\s*등장|등재|first\s*seen|published|"
    r"NVD|VirusTotal\s*최초|CVE-\d",
    re.I)
# 정렬용 날짜. 기간("2025-12 ~ 2026-08")이면 시작일을 쓴다.
WHEN_KEY_RE = re.compile(r"(\d{4})(?:[-./년]\s*(\d{1,2}))?(?:[-./월]\s*(\d{1,2}))?")


def _when_key(when):
    match = WHEN_KEY_RE.search(when or "")
    if not match:
        return (9999, 99, 99)
    return (int(match.group(1)), int(match.group(2) or 0), int(match.group(3) or 0))


def _exposure(value, corpus, dropped):
    """우리 쪽 영향 범위 추정. 근거가 재료 밖이면 버린다."""
    if not isinstance(value, dict):
        return {}
    who = " ".join(str(value.get("who") or "").split())
    if not who:
        return {}
    basis = " ".join(str(value.get("basis") or "").split())
    bad = _invented(who + " " + basis, corpus)
    if bad:
        dropped.append("근거 없는 값({}) — 영향 범위 추정".format(", ".join(bad[:2])))
        return {}
    return {"who": who[:400], "basis": basis[:400],
            "confirm": " ".join(str(value.get("confirm") or "").split())[:300]}


def _timeline(values, corpus, dropped):
    """시간축. 날짜가 없는 항목과 재료에 없는 값이 섞인 항목은 버린다.

    자르기 전에 다 검사한다. 앞에서부터 자르면 모델이 뒤에 적은 사건 날짜가
    검사도 받기 전에 사라진다. 자리가 모자라면 조회 부산물부터 버리고, 남은 것은
    날짜순으로 되돌린다 — 순서가 없는 시간축은 시간축이 아니다.
    """
    out = []
    for item in (values or []):
        if not isinstance(item, dict):
            continue
        when = " ".join(str(item.get("when") or "").split())
        what = " ".join(str(item.get("what") or "").split())
        if not (when and what) or not DATE_RE.search(when):
            continue
        if _invented(when + " " + what, corpus):
            dropped.append("근거 없는 값 — 시간축 \"{}\"".format(what[:40]))
            continue
        out.append({"when": when[:40], "what": what[:200],
                    "source": " ".join(str(item.get("source") or "").split())[:80]})
    if len(out) > MAX_TIMELINE:
        out.sort(key=lambda row: bool(REGISTRY_EVENT_RE.search(
            row["what"] + " " + row["source"])))
        out = out[:MAX_TIMELINE]
    out.sort(key=lambda row: _when_key(row["when"]))
    return out


@analysis_trace.step("조사 자료 종합·목표 재평가·대응안 생성", "synthesis", inputs=("analysis", "targets", "investigation", "extra", "article"), empty="failed")
def synthesize(title, analysis, targets, investigation, timeout=SYNTH_TIMEOUT,
               primary="", extra="", history="", article="", related=None):
    """조회 결과를 읽고 판단한다. 쓸 만한 결과가 없으면 None.

    related는 past_analyses.find_related()가 돌려준 후보 목록(원문 그대로) —
    campaign_relations의 title을 그 후보 제목과만 대조하는 데 쓴다. history는 그
    후보를 프롬프트에 넣을 문장으로 바꾼 것(past_analyses.as_evidence(related))이라
    보통 같이 넘긴다.

    반환: {"verdict","headline","confirmed","unconfirmed","contradictions",
           "plan":[{action,why,when}],"open_questions","question_status",
           "campaign_relations","steps"}
    """
    investigation = investigation or {}
    material = _material(investigation, targets or {})
    if not material.strip():
        return None      # 조회한 것이 없으면 판단할 재료도 없다

    prompt = build_prompt(title, analysis, targets, investigation, primary, extra, history, article)
    raw = common_utils.llm_generate(
        prompt, timeout=timeout, json_format=True,
        nvidia_max_attempts=SYNTH_ATTEMPTS, max_tokens=SYNTH_MAX_TOKENS)
    data, salvaged = parse_with_status(raw)
    if not data:
        # 한 번은 더 받아 본다. 같은 프롬프트를 그대로 다시 보내면 같은 자리에서 또
        # 잘리므로(추론 + 본문이 상한을 넘는 경우), 이번에는 짧게 쓰라고 못박는다.
        analysis_trace.note("응답 JSON 검증 실패: 축약 지시로 LLM 재호출", "synthesis", "reanalysis", "partial")
        log("    [-] 종합 판단 응답을 JSON으로 읽지 못해 짧은 형식으로 다시 받습니다.")
        raw = common_utils.llm_generate(
            prompt + COMPACT_RETRY_NOTE, timeout=timeout, json_format=True,
            nvidia_max_attempts=SYNTH_ATTEMPTS, max_tokens=SYNTH_MAX_TOKENS)
        data, salvaged = parse_with_status(raw)
    if not data:
        log("    [-] 종합 판단 응답을 두 번 다 JSON으로 읽지 못했습니다(응답 {}자).".format(
            len(raw or "")))
        return None

    corpus = _corpus(investigation, article or analysis, primary=primary, extra=extra)
    # 후속 조회 값은 모델 자신이 앞 단계에서 쓴 글(pattern_synth의 쿼리·설명)로 근거를
    # 삼지 못하게 한다 — 패턴 설명에 적힌 "*.cofinity-x.com"이 근거가 돼 정상 기업
    # 도메인 urlscan 조회가 돌았다(실측 2026-09-30, 카테나-X 건).
    followup_corpus = _corpus({key: value for key, value in investigation.items() if key != "patterns"},
                              article or analysis, primary=primary, extra=extra)
    dropped = []
    plan = []
    plan_positions = {}
    never_block, unconfirmed = _unblockable_hosts(investigation)
    for original_index, item in enumerate((data.get("plan") or [])[:MAX_PLAN_STEPS], 1):
        if not isinstance(item, dict):
            continue
        action = " ".join(str(item.get("action") or "").split())
        if not action:
            continue
        fields = {key: " ".join(str(item.get(key) or "").split())[:600]
                  for key in ("action", "why", "when", *analyst_workflow.PLAN_FIELDS)}
        bad = _invented(" ".join(fields.values()), corpus)
        if bad:
            dropped.append("근거 없는 값({}) — {}".format(", ".join(bad[:2]), action[:50]))
            continue
        blocked, doubtful, others = _block_review(action, never_block, unconfirmed)
        if blocked and not doubtful and not others:
            # 막으면 안 되는 값만 막으라는 조치 — 실행하면 정상 대상을 끊는다.
            dropped.append("차단 금지 지표만 막으라는 조치({}) — {}".format(
                ", ".join(blocked[:2]), action[:40]))
            continue
        fields["review_gaps"] = analyst_workflow.plan_gaps(fields)
        if blocked:
            fields["review_gaps"].append(
                "차단 금지 지표 포함({}) — 정찰 대상·비공인 주소 등이라 차단 목록에서 뺀다".format(
                    ", ".join(blocked[:3])))
        if doubtful:
            fields["review_gaps"].append(
                "차단 근거 미확정 지표({}) — 역할 확인 전에는 차단하지 않고 관찰만".format(
                    ", ".join(doubtful[:3])))
        if "0건 결과의 수집 범위·보존 기간 검증" in fields["review_gaps"]:
            fields["done"] = ("종료 보류: 0건만으로 피해 부재를 확정하지 않습니다. 수집 범위·보존 기간·"
                              "센서 상태와 양성 테스트·대체 로그를 확인하고, 불충분하면 미확인으로 유지합니다.")
        plan.append(fields)
        plan_positions[original_index] = len(plan)

    headline = " ".join(str(data.get("headline") or "").split())
    if _invented(headline, corpus):
        headline = ""

    result = {
        "verdict": normalize_verdict(data.get("verdict")),
        "headline": headline,
        "confirmed": _clean_list(data.get("confirmed"), corpus, dropped),
        "unconfirmed": _clean_list(data.get("unconfirmed"), corpus, dropped),
        "contradictions": _clean_list(data.get("contradictions"), corpus, dropped),
        "plan": plan,
        "open_questions": _clean_list(data.get("open_questions"), corpus, dropped),
        "exposure": _exposure(data.get("exposure"), corpus, dropped),
        "timeline": _timeline(data.get("timeline"), corpus, dropped),
        "objective": (targets or {}).get("objective") or "",
        "workflow_version": analyst_workflow.VERSION,
        "followups": followups(data, followup_corpus,
                               source=" ".join((article or "", analysis or ""))),
        "question_status": question_status(data, (targets or {}).get("questions"), corpus,
                                           plan_positions=plan_positions),
        "campaign_relations": campaign_relations(data, related, corpus),
    }
    if not (result["plan"] or result["confirmed"] or result["headline"]):
        log("    [-] 종합 판단의 판단·확인 사실·조치가 근거 검증에서 모두 탈락했습니다({}건 폐기)."
            .format(len(dropped)))
        return None
    result["key_findings"] = key_findings(result["confirmed"], investigation)

    steps = ["조회 결과를 종합해 대응 방안을 정리했습니다(판단 {} · 조치 {}단계)."
             .format(result["verdict"] or "-", len(plan))]
    if salvaged:
        steps.append("· 응답이 길이 상한에서 잘려, 마지막으로 완결된 항목까지만 반영했습니다.")
    for reason in dropped[:4]:
        steps.append("· 폐기: " + reason)
    result["steps"] = steps
    return result


BRIEFING_PROMPT = """당신은 보안 조직의 기술 정보 담당자다. 아래 정보성 기사를 한국어로 정리하라.
이것은 침해 사고가 아니다. IOC 차단, 악성코드 조사, 로그 헌팅, 격리와 패치를 권하지 마라.
기사 원문과 읽은 참고 자료를 구분하라. 검색 결과의 제목·요약만 본 자료는 원문을
읽었다고 하지 마라. 참고 자료로 확인되지 않은 규제 의무·시행일·조직 적용 여부는
확정하지 말고 확인할 질문으로 남겨라. 우리 조직의 시스템·계약·사업 범위는 알 수 없다.
회사·기관·제품을 공격자로 취급하지 마라. 근거에 없는 도메인·CVE·수치·날짜를 쓰지 마라.
확인된 사실에는 기사 또는 실제 읽은 자료의 출처를 명시하라. 공개 자료가 없으면 기사에
적힌 발표 사실만 확인됐다고 쓰고 배경 질문은 미확인으로 남겨라. 관련이 없으면 plan은
빈 배열이다. 할 일이 있더라도 검토 과제이지 사고 대응이 아니다.

JSON 하나만 출력하라:
{"verdict":"확인됨|부분 확인|미확인",
"headline":"기사와 배경의 핵심을 한국어 한 문장으로",
"confirmed":["기사 또는 자료로 확인된 사실과 출처"],
"unconfirmed":["아직 확인할 수 없는 사항과 이유"],
"contradictions":[],
"exposure":{"who":"우리 조직 해당 여부는 조건부로 설명. 모르면 미확인",
"basis":"기사 또는 읽은 자료의 근거","confirm":"내부에서 확인할 대상"},
"plan":[{"action":"구체적 검토 과제","why":"근거와 목적","when":"검토 시점",
"owner":"담당 역할","trigger":"검토 착수 조건","check":"확인할 공식 자료·내부 문서",
"done":"검토 완료 기준"}],
"open_questions":["공개 자료나 내부 정보가 더 필요한 질문"],
"question_status":[{"question":"판단 단계 질문을 그대로","status":"answered|partial|open",
"answer":"근거가 있는 답 또는 답하지 못한 이유","evidence":"출처와 근거"}]}

[제목]\n__TITLE__\n[기사 원문]\n__ARTICLE__\n[기본 분석]\n__ANALYSIS__
[검토 목표와 질문]\n__TARGETS__\n[참고 자료]\n__MATERIALS__
"""


BRIEFING_VERDICT = "정보성 기사"
BRIEFING_EXPOSURE_LEAD = "공격 사건이 아니어서 직접 노출·침해 대상은 없습니다."


@analysis_trace.step("정보성 기사 조사 결과와 활용안 생성", "synthesis", inputs=("analysis", "targets", "investigation", "materials"), empty="failed")
def synthesize_briefing(title, analysis, targets, investigation, article="", materials="",
                       timeout=SYNTH_TIMEOUT):
    """Synthesize an informational brief without the incident-response schema."""
    targets = targets or {}
    prompt = BRIEFING_PROMPT
    trend = targets.get("article_subtype") == article_kind.SUBTYPE_TACTIC_OVERVIEW
    if trend:
        prompt += ("\n[복수 전술 동향]\n이 기사는 여러 공격 전술을 비교한 보고서이지 "
                   "하나의 침해 사건이 아니다. 전술별 사례와 집계 수치의 기간·분모를 분리하라. "
                   "우리 조직에서 승인된 RMM 도구·원격접속 정책·로그 가시성을 확인하는 "
                   "조건부 검토는 가능하지만, 다른 사례의 IOC 차단·패치·일률적인 기한을 "
                   "권하지 마라. 사례 사이에 캠페인 연관성을 만들지 마라.\n")
    values = {
        "__TITLE__": title or "", "__ARTICLE__": (article or "")[:12000],
        "__ANALYSIS__": (analysis or "")[:7000],
        "__TARGETS__": json.dumps({key: targets.get(key) for key in
                                    ("objective", "questions", "topics", "issues", "gaps")},
                                   ensure_ascii=False),
        "__MATERIALS__": (materials or "")[:12000],
    }
    for marker, value in values.items():
        prompt = prompt.replace(marker, value)
    raw = common_utils.llm_generate(prompt, timeout=timeout, json_format=True,
                                    nvidia_max_attempts=SYNTH_ATTEMPTS,
                                    max_tokens=SYNTH_MAX_TOKENS)
    data, salvaged = parse_with_status(raw)
    if not data:
        return None
    corpus = _corpus({}, article or analysis, primary=materials)
    dropped = []
    plan = []
    for item in (data.get("plan") or [])[:MAX_PLAN_STEPS]:
        if not isinstance(item, dict):
            continue
        fields = {key: " ".join(str(item.get(key) or "").split())[:600]
                  for key in ("action", "why", "when", "owner", "trigger", "check", "done")}
        if not fields["action"] or _invented(" ".join(fields.values()), corpus):
            continue
        if trend and re.search(r"IOC.{0,12}차단|도메인.{0,12}차단|IP.{0,12}차단|"
                               r"패치 적용|즉시 격리|block\s+(?:the\s+)?(?:IOC|IP|domain)",
                               fields["action"], re.I):
            continue
        fields["preserve"] = analyst_workflow.NOT_APPLICABLE
        fields["alternative"] = analyst_workflow.NOT_APPLICABLE
        fields["review_gaps"] = analyst_workflow.plan_gaps(fields, informational=True)
        plan.append(fields)
    headline = " ".join(str(data.get("headline") or "").split())[:300]
    if _invented(headline, corpus):
        headline = ""
    confirmed = _clean_list(data.get("confirmed"), corpus, dropped)
    read_sources = bool((investigation or {}).get("background") or
                        ((investigation or {}).get("primary") or {}).get("sources"))
    if not read_sources:
        confirmed = [line for line in confirmed if "기사" in line]
    result = {
        # 정보성 기사에 "확인됨"(초록)·"미확인"을 붙이면 공격 사건을 확인한 것처럼 읽힌다.
        # 판정은 기사 성격으로 고정하고, 질문별 달성도는 question_status로 보인다.
        "verdict": BRIEFING_VERDICT,
        "headline": headline,
        "confirmed": confirmed,
        "unconfirmed": _clean_list(data.get("unconfirmed"), corpus, dropped),
        "contradictions": _clean_list(data.get("contradictions"), corpus, dropped),
        "plan": plan,
        "open_questions": _clean_list(data.get("open_questions"), corpus, dropped),
        "exposure": _exposure(data.get("exposure"), corpus, dropped),
        "objective": targets.get("objective") or "",
        "question_status": question_status(data, targets.get("questions"), corpus),
        "followups": [], "campaign_relations": [], "timeline": [],
        "workflow_version": analyst_workflow.VERSION,
    }
    if not (result["headline"] or result["confirmed"] or result["plan"]):
        return None
    exposure = result["exposure"] or {}
    who = str(exposure.get("who") or "").strip()
    exposure_lead = ("복수 전술의 동향 기사이므로 이 기사만으로 우리 조직의 침해를 "
                     "확정할 수 없습니다." if trend else BRIEFING_EXPOSURE_LEAD)
    if not who.startswith(exposure_lead):
        who = re.sub(r"^(?:미확인|해당 없음)[.。:\s]*", "", who)
        exposure["who"] = (exposure_lead + " " + who).strip()
        result["exposure"] = exposure
    result["key_findings"] = key_findings(result["confirmed"], investigation or {})
    result["steps"] = ["기사와 참고 자료를 구분해 배경·적용 가능성을 정리했습니다."]
    if salvaged:
        result["steps"].append("· 응답이 잘려 완결된 항목까지만 반영했습니다.")
    if dropped:
        result["steps"].append("· 근거 없는 구체값이 포함된 항목 {}건을 제외했습니다.".format(len(dropped)))
    return result
