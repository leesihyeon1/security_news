# -*- coding: utf-8 -*-
"""목표에 맞춰 무엇을 내야 하는지는 모델이 정하고, 냈는지는 코드가 검증한다.

한 번 잘못 만들었다가 되돌린 것
    처음에는 유형별 목표문을 여기 적어 두고 프롬프트에 넣어 줬다 — "사회공학이면
    범용 탐지 수단을 만드는 것이 목표다" 같은 문장을. 그러면 모델은 판단하지 않고
    내가 쓴 다섯 갈래에서 고르기만 한다. 새로운 유형이 오면 오히려 잘못된 방향으로
    끌고 간다. 미리 정해둔 규칙만 도는 문제를 고치겠다면서 같은 것을 다시 만든
    셈이었다.

    그래서 나눴다.
      · 무엇을 목표로 삼고 그 목표를 달성하려면 무엇이 나와야 하는가 → 모델이 정한다.
        기사가 무슨 유형인지, 이번 건에 무엇이 중요한지는 기사를 읽어야 아는 것이다.
      · 그래서 그것이 실제로 나왔는가 → 코드가 본다. 모델의 자기 평가는 믿을 수
        없지만, "urlscan 패턴이 있나"는 기계가 확실히 판정한다.

    모델은 목표와 함께 성공기준을 아래 어휘로 선언하고, 코드는 그 선언과 실제
    산출물을 대조한다. 어휘만 공유하고 선택은 맡긴다.

왜 어휘를 고정하는가
    "탐지 룰을 만든다" 같은 자유 문장으로 받으면 무엇이 나왔는지 기계가 판정할 수
    없다. 판정 가능한 단위로 받아야 "약속한 것을 냈는가"를 확인할 수 있다. 어휘는
    산출물의 종류일 뿐이고, 어느 것이 이 사건에 필요한지는 모델이 고른다.
"""

# 성공기준으로 쓸 수 있는 산출물 종류. 모델이 이 이름으로 선언하고, 코드가 확인한다.
# 종류를 늘리는 것은 조회기를 늘릴 때 함께 한다 — 낼 수 없는 것을 기준으로 삼으면
# 영원히 미달로 남는다.
def _patterns(block, platform=None):
    for pattern in block.get("patterns") or []:
        if platform is None or pattern.get("platform") == platform:
            return True
    return False


def _response(block, key):
    return bool((block.get("response") or {}).get(key))


def _blocklist_values(block):
    for item in ((block.get("response") or {}).get("blocklists") or []):
        if item.get("values"):
            return True
    return False


def _sample_source(block):
    """샘플을 실제로 어디서 받을 수 있는가.

    예전에는 file_info의 맨 위에서 external·sandboxes를 찾았는데 그 자리에는 아무것도
    없다 — vt_hunter는 그것들을 file_info["enrichment"] 아래에 넣는다. 그래서 Triage와
    Hybrid Analysis가 샘플을 찾아낸 건까지 "샘플 확보 경로 없음"으로 찍혔다
    (실측 2026-09-17, DeadLock 건: tria.ge/260910-csptssef64를 확보해 놓고 미달).

    "검색만" 링크는 확보가 아니다. 그 서비스에 실제로 샘플이 있다고 확인된 것만 센다.
    """
    for file_info in ((block.get("malware") or {}).get("files") or []):
        enrichment = file_info.get("enrichment") or {}
        for outside in enrichment.get("outside") or []:
            if outside.get("found"):
                return True
        for service in enrichment.get("external") or []:
            if service.get("confirmed"):
                return True
        # 셋 다 없을 때 해시로 검색해 찾은 공개 저장소도 확보 경로다. 분석 글만
        # 걸린 경우(writeups)는 세지 않는다 — 읽을 거리이지 받을 곳이 아니다.
        if (enrichment.get("searched") or {}).get("sources"):
            return True
    return False


ARTIFACTS = {
    "urlscan_pattern": (
        "같은 방식의 다른 유포지를 찾는 urlscan 검색 패턴",
        lambda b: _patterns(b, "urlscan") or bool(b.get("seeds"))),
    "dork": (
        "가짜 배포 페이지를 찾는 검색 연산자(dork)",
        lambda b: _patterns(b, "google_dork")),
    "vt_pattern": (
        "VirusTotal 행위 기반 검색 패턴",
        lambda b: _patterns(b, "virustotal")),
    "hunting_query": (
        "사내에서 돌릴 헌팅 쿼리(MDE KQL)",
        lambda b: _response(b, "kql")),
    "blocklist": (
        "차단·확인 대상 목록",
        _blocklist_values),
    "dynamic_analysis": (
        "동적 분석으로 확정한 행위",
        # 파일이 조회됐다는 것과 샌드박스가 실제로 실행해 봤다는 것은 다르다.
        # bool(files)만 보면 행위 데이터가 0건인 파일도 "냈다"가 된다.
        lambda b: any((f.get("behaviour") or {}).get("has_dynamic")
                      for f in ((b.get("malware") or {}).get("files") or []))),
    "sample_source": (
        "샘플 확보 경로(공개 저장소·샌드박스)",
        _sample_source),
    "patch_priority": (
        "KEV·EPSS로 본 패치 긴급도",
        lambda b: bool((b.get("vulnerability") or {}).get("cves"))),
    "registry_status": (
        "배포 경로 등재 현황(패키지 레지스트리·확장 스토어)",
        # 확장 스토어도 "받아 쓰는 통로"라는 점에서 레지스트리와 같은 자리다. 이걸
        # 빼놓으면 확장 건이 스토어 조회를 내고도 미달로 찍힌다.
        lambda b: bool(b.get("supply_chain") or b.get("extension"))),
    "repo_status": (
        "저장소·계정 상태 확인",
        lambda b: bool(b.get("github"))),
    "local_commands": (
        "단말에서 실행할 확인·복구 명령",
        lambda b: _response(b, "commands")),
    "external_reports": (
        "다른 연구자의 공개 분석·1차 자료",
        # 기사가 인용한 1차 자료를 직접 읽은 것도 여기 해당한다. 교차 인텔·웹 검색의
        # 참고 링크만 세다가, 벤더 원문 2건을 읽고도 미달로 찍은 적이 있다.
        lambda b: bool((b.get("intel") or {}).get("references")
                       or (b.get("web") or {}).get("references")
                       or (b.get("primary") or {}).get("sources"))),
}


def vocabulary_spec():
    """프롬프트에 넣을 어휘 설명. 이름과 뜻만 주고 선택은 맡긴다."""
    lines = []
    for key, (label, _) in ARTIFACTS.items():
        lines.append("  {} = {}".format(key, label))
    return "\n".join(lines)


def coverage(block, criteria):
    """모델이 선언한 성공기준과 실제 산출물을 대조한다.

    criteria는 targets["criteria"] — 모델이 목표를 세울 때 함께 선언한 산출물 종류다.
    선언이 없으면 대조할 것이 없으니 None을 돌려준다. 내가 대신 기준을 만들지 않는다.
    """
    wanted = [str(c).strip() for c in (criteria or []) if str(c).strip()]
    wanted = [c for c in wanted if c in ARTIFACTS]
    if not wanted:
        return None
    done, missing = [], []
    for key in wanted:
        label, check = ARTIFACTS[key]
        try:
            ok = bool(check(block or {}))
        except Exception:
            ok = False
        (done if ok else missing).append({"key": key, "label": label})
    return {"done": done, "missing": missing}


def coverage_steps(result):
    """조사 과정에 남길 줄. 약속한 것 중 무엇을 냈고 무엇이 빠졌는지."""
    if not result:
        return []
    total = len(result["done"]) + len(result["missing"])
    steps = ["목표를 세울 때 선언한 성공기준 {}개 중 {}개를 냈습니다.".format(
        total, len(result["done"]))]
    for item in result["missing"]:
        steps.append("· 미달: {} — 목표 달성에 필요하다고 선언했는데 나오지 "
                     "않았습니다.".format(item["label"]))
    return steps
