# -*- coding: utf-8 -*-
"""전에 우리가 분석한 것 중 같은 계열을 찾아 붙인다.

무엇이 빠져 있었나
    분석 결과가 44건 쌓여 있는데 어느 단계도 그것을 보지 않았다. 매번 처음 보는
    사건처럼 조사하고, 매번 처음부터 판단했다.

    분석가의 연차가 드러나는 자리가 대개 여기다. "이거 지난주 LegionLoader 건이랑
    같은 ClickFix 인프라인데", "이 행위자 8월에도 봤고 그때는 npm이었다" — 이런
    연결은 지식이 아니라 기록에서 나온다. 기록은 있었는데 읽지 않고 있었다.

무엇을 근거로 잇나
    이름과 값이다. 행위자·악성코드 이름이 같거나, 도메인·해시·CVE·패키지·확장 ID가
    겹치면 같은 계열로 본다. 제목 유사도는 쓰지 않는다 — 같은 사건을 다룬 다른 기사와
    "같은 수법의 다른 사건"을 구별하지 못하기 때문이다. 여기서 찾으려는 것은 후자다.

    카테고리가 같다는 것만으로는 잇지 않는다. 그건 "둘 다 악성코드 기사"라는 말일
    뿐이라 연결로서 아무 값이 없다.

무엇을 하지 않나
    과거 판단을 근거로 쓰지 않는다. 이어 주기만 하고, 그 분석이 맞았는지는 사람이
    본다 — 우리 옛 판단을 새 판단의 사실로 삼으면 틀린 판단이 복리로 불어난다.
"""

import json
import os
import re

import campaign_radar
import common_utils

INSIGHTS_LIST_KEY = "insights:list"
# 한 건에 붙일 관련 분석 수. 많이 붙이면 프롬프트만 길어지고 판단에 도움이 안 된다.
MAX_RELATED = 3
# 이름이 이보다 짧으면 잇지 않는다 — "APT"·"RAT" 같은 낱말이 전부 걸린다.
MIN_NAME_CHARS = 4
# 값이 이보다 짧으면 잇지 않는다(짧은 도메인·파일명이 우연히 겹친다).
MIN_VALUE_CHARS = 7
# 관련 기록 하나에서 딸려 보낼 IOC 수 상한. 동일 캠페인으로 확정된 뒤에만 실제로
# 재조회에 쓰이므로, 많이 실어도 손해는 아니지만 프롬프트/조회 비용을 생각해 묶는다.
MAX_RELATED_IOCS = 20
# 이름 취급하지 않을 일반명사. campaign_radar의 STOPNAMES와 같은 이유다.
STOPNAMES = {
    "unknown", "n/a", "none", "various", "unattributed", "ransomware",
    "malware", "backdoor", "loader", "stealer", "trojan", "미확인", "불명",
    "다수", "미상", "해당 없음",
}


def log(message):
    print(message)


def _client():
    """Redis. 없으면 None — 연결이 안 된다고 조사를 멈추지는 않는다."""
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
        log("    [-] 과거 분석 조회 실패(조사에는 영향 없음): {}".format(str(error)[:70]))
        return None


def _norm(value):
    return common_utils.clean_text(str(value or "")).strip().lower()


# 이름 뒤에 붙는 일반명사. 떼지 않으면 "TerminalFix campaign"과 "TerminalFix"가
# 다른 이름이 된다. 실측(저장분): "StyleSmuggler implant", "BlueMoon 익스플로잇 키트",
# "TerminalFix campaign", "ted" 처럼 표기가 제각각이다.
# 영문 꼬리는 공백이 있을 때만 뗀다 — 붙여 쓰면 이름의 일부다("LegionLoader"를
# "legion"으로 자르면 안 된다). 한글 꼬리는 붙여 쓰는 일이 흔해 공백을 선택으로 둔다.
NAME_TAIL_RE = re.compile(
    r"(?:\s+(?:campaign|implant|backdoor|loader|stealer|ransomware|rat|malware|group)"
    r"|\s*(?:익스플로잇\s*키트|랜섬웨어|백도어|로더|스틸러|악성코드|캠페인|그룹))\s*$", re.I)
# 이름 자리에 들어온 자리표시자. 그대로 두면 서로 다른 사건이 "미확인"으로 이어진다.
PLACEHOLDER_NAME_RE = re.compile(r"미확인|불명|미상|해당\s*없음|unknown|unattributed", re.I)


def _names(targets):
    """행위자·악성코드 이름. 이름은 같은 계열을 가리키는 가장 강한 신호다.

    campaign_radar.split_entities를 그대로 쓴다 — 괄호 별칭 분해("김수키(Kimsuky)"를
    둘로), 쉼표·슬래시 분리, 꼬리 낱말 제거를 이미 거기서 하고 있어서 같은 규칙으로
    맞춰야 두 곳의 판정이 어긋나지 않는다.
    """
    out = set()
    for key in ("actors", "malware"):
        for value in (targets or {}).get(key) or []:
            for piece in campaign_radar.split_entities(str(value or "")):
                name = NAME_TAIL_RE.sub("", _norm(piece)).strip()
                if PLACEHOLDER_NAME_RE.search(name):
                    continue
                if len(name) >= MIN_NAME_CHARS and name not in STOPNAMES:
                    out.add(name)
    return out


def _values(targets):
    """지표 값. 같은 인프라를 다시 쓰면 여기서 걸린다."""
    out = set()
    for key in ("domains", "ips", "hashes", "cves", "packages", "urls"):
        for value in (targets or {}).get(key) or []:
            value = _norm(value)
            if len(value) >= MIN_VALUE_CHARS:
                out.add(value)
    return out


def _record_targets(record):
    return record.get("targets") or {}


def find_related(targets, exclude_title="", client=None):
    """같은 계열의 과거 분석. [{title, when, why}] 형식, 최신순.

    exclude_title은 지금 분석 중인 기사다 — 재분석하면 자기 자신이 걸리므로 뺀다.
    """
    names, values = _names(targets), _values(targets)
    if not (names or values):
        return []
    client = client or _client()
    if client is None:
        return []
    try:
        rows = client.lrange(INSIGHTS_LIST_KEY, 0, -1)
    except Exception as error:
        log("    [-] 과거 분석 목록을 읽지 못했습니다: {}".format(str(error)[:70]))
        return []

    related = []
    for raw in rows:
        try:
            record = json.loads(raw)
        except (ValueError, TypeError):
            continue
        title = record.get("title") or ""
        if not title or title == exclude_title:
            continue
        past = _record_targets(record)
        shared_names = names & _names(past)
        shared_values = values & _values(past)
        if not (shared_names or shared_values):
            continue
        why = []
        if shared_names:
            why.append("같은 이름: " + ", ".join(sorted(shared_names)[:3]))
        if shared_values:
            why.append("같은 지표: " + ", ".join(
                v[:24] for v in sorted(shared_values)[:3]))
        related.append({
            "title": title[:110],
            "when": (record.get("analyzed_at") or "")[:10],
            "why": " / ".join(why),
            "objective": (past.get("objective") or "")[:160],
            # 동일 캠페인으로 판정되면(response_synth.campaign_relations) 이 값들을
            # 다음 조사 라운드의 iocs에 합쳐 재조회한다 — "관련 보고서의 IOC를 이어
            # 조사"하는 동작의 입력. 판단 근거로 쓰지 않는다는 모듈 원칙은 그대로다;
            # 여기 실린 값은 IOC일 뿐, 과거 판단문은 여전히 넘기지 않는다.
            "iocs": [item for item in (record.get("iocs") or [])
                    if isinstance(item, dict) and item.get("value")][:MAX_RELATED_IOCS],
        })
    # 최신 분석이 앞에 오게 한다 — 같은 계열이면 최근 것이 더 쓸모 있다.
    related.sort(key=lambda item: item["when"], reverse=True)
    return related[:MAX_RELATED]


def stored_axis(title, client=None):
    """같은 기사를 전에 분석했다면 그때 정한 주력 축. 없으면 "".

    왜 고정하나
        주력 축은 모델 선언이 규칙 판정보다 앞선다. 모델은 매번 새로 읽으므로 같은
        기사를 다시 돌리면 축이 흔들린다 — 실측(Anthropic 위협 보고서 기사, 같은
        본문 3회): 판정 보류 → 악성코드 → 공급망. 축이 바뀌면 조회 계획이 통째로
        바뀌어서, 재분석이 "다시 본 것"이 아니라 "다른 것"이 된다.

        그래서 한 번 정해진 축은 재분석에서 유지한다. 처음 분석에서 축을 못 정한
        경우("판정 보류")는 빈 값이라 다음 분석이 새로 정할 수 있다 — 못 정한 것을
        못 정한 채로 굳힐 이유는 없다.

        환경변수 INVESTIGATION_RESET_AXIS를 주면 무시하고 새로 정한다. 처음 판단이
        틀렸을 때 빠져나갈 문이 없으면 안 된다.
    """
    if not title or os.environ.get("INVESTIGATION_RESET_AXIS"):
        return ""
    client = client or _client()
    if client is None:
        return ""
    try:
        rows = client.lrange(INSIGHTS_LIST_KEY, 0, -1)
    except Exception:
        return ""
    for raw in rows:
        try:
            record = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if (record.get("title") or "") != title:
            continue
        route = (record.get("investigation") or {}).get("route") or {}
        return str(route.get("primary") or "")
    return ""


def steps(related):
    """조사 과정에 남길 줄."""
    if not related:
        return []
    lines = ["전에 분석한 {}건이 같은 계열로 걸립니다 — 같은 수법이 반복되는지 "
             "보려는 것입니다.".format(len(related))]
    for item in related:
        lines.append("· {} ({}) — {}".format(item["title"][:70], item["when"] or "?",
                                             item["why"]))
    return lines


def as_evidence(related):
    """종합 판단 프롬프트에 넣을 형태.

    과거 판단이 아니라 "무엇을 같은 계열로 봤는지"만 준다. 옛 결론을 사실로 넘기면
    그때 틀린 판단이 새 판단의 근거가 된다.
    """
    if not related:
        return ""
    blocks = ["[전에 우리가 분석한 같은 계열]"]
    for item in related:
        blocks.append("- {} ({}) · {}{}".format(
            item["title"], item["when"] or "?", item["why"],
            "\n  그때 세운 목표: " + item["objective"] if item["objective"] else ""))
    blocks.append("이 연결이 이번 건 판단에 무엇을 뜻하는지 밝혀라 — 같은 인프라를 다시 "
                  "쓰는 것인지, 수법만 같은 것인지, 무관한데 이름만 겹친 것인지.")
    return "\n".join(blocks)
