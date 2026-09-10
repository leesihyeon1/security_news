"""MISP Galaxy·warninglists에서 인텔 참조 데이터를 내려받아 assets/intel/에 가공 저장한다.

생성 파일:
    threat_actor_aliases.json  위협그룹 앨리어스 → 공식 명칭 (MISP Galaxy threat-actor)
    attack_techniques.json     MITRE ATT&CK 기법 ID 카탈로그 (LLM 환각 검증용)
    benign_iocs.json           벤인 인프라 목록 (MISP warninglists — IOC 오탐 필터)

원본은 수 MB라 저장소에 넣지 않고, 가공한 결과(수백 KB)만 커밋한다.
분기 1회 정도 재실행해 갱신하면 충분하다. 실패해도 기존 파일이 유지된다.

사용법:
    python update_intel_data.py
"""

import json
import re
import sys
from datetime import datetime

import requests

import common_utils

for stream in (sys.stdout, sys.stderr):
    if stream and hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

INTEL_DIR = common_utils.ASSETS_DIR / "intel"

GALAXY_BASE = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters"
WARNINGLIST_BASE = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists"

# 벤인 필터에 쓸 warninglist 선정 기준: "차단 지표로서 무의미한 공용 인프라"만.
# 공격자가 자주 악용하는 클라우드 스토리지 등은 기사 IOC로 의미가 있어 제외한다.
WARNINGLISTS = ["public-dns-v4", "cloudflare", "google", "microsoft"]

ATTACK_ID_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")


def fetch_json(url):
    print("[*] 다운로드: {}".format(url))
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    return resp.json()


def save(name, payload):
    INTEL_DIR.mkdir(parents=True, exist_ok=True)
    path = INTEL_DIR / name
    payload["generated_at"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    with path.open("w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, indent=1, sort_keys=True)
    print("[+] 저장: {} ({:,} bytes)".format(path, path.stat().st_size))


def build_threat_actor_aliases():
    data = fetch_json("{}/threat-actor.json".format(GALAXY_BASE))
    aliases = {}
    count = 0
    for cluster in data.get("values") or []:
        canonical = common_utils.clean_text(cluster.get("value"))
        if not canonical:
            continue
        count += 1
        names = [canonical] + list((cluster.get("meta") or {}).get("synonyms") or [])
        for name in names:
            key = common_utils.clean_text(name).lower()
            # 이미 다른 그룹의 공식 명칭인 키는 덮어쓰지 않는다 (동명 앨리어스 충돌 방지)
            if key and key not in aliases:
                aliases[key] = canonical
    save("threat_actor_aliases.json", {
        "source": "MISP Galaxy threat-actor",
        "groups": count,
        "aliases": aliases,
    })


def build_known_names():
    """이미 이름이 붙어 알려진 것들의 목록. "신규 캠페인" 판정에서 걸러내는 데 쓴다.

    공격 동향 레이더는 "우리 코퍼스에서 처음 본 이름"을 신규로 본다. 코퍼스가 두 달
    남짓이라 그 전부터 알려진 것도 신규로 뜬다(실측: Rhysida·APT37·Kimsuky가 신규
    캠페인 카드로 올라왔다). 행위자는 threat_actor_aliases.json으로 걸러지지만
    랜섬웨어·악성코드 이름은 그 사전에 없어서 따로 모은다.
    """
    names = {}
    for cluster, label in (("ransomware", "ransomware"),
                           ("malpedia", "malware"),
                           ("tool", "tool")):
        try:
            data = fetch_json("{}/{}.json".format(GALAXY_BASE, cluster))
        except Exception as error:
            print("[-] {} 클러스터를 받지 못했습니다: {}".format(cluster, error))
            continue
        for item in data.get("values") or []:
            canonical = common_utils.clean_text(item.get("value"))
            if not canonical:
                continue
            for name in [canonical] + list((item.get("meta") or {}).get("synonyms") or []):
                key = common_utils.clean_text(name).lower()
                # 짧은 이름은 일반 낱말과 겹쳐 오탐을 만든다 — 걸러내기 용도라
                # 잘못 걸리면 진짜 신규 캠페인이 사라진다.
                if len(key) >= 4 and key not in names:
                    names[key] = label
    save("known_names.json", {
        "source": "MISP Galaxy ransomware/malpedia/tool",
        "count": len(names),
        "names": names,
    })


def build_attack_techniques():
    data = fetch_json("{}/mitre-attack-pattern.json".format(GALAXY_BASE))
    techniques, tactics = {}, {}
    for cluster in data.get("values") or []:
        meta = cluster.get("meta") or {}
        external_id = common_utils.clean_text(meta.get("external_id"))
        if not ATTACK_ID_RE.fullmatch(external_id):
            # external_id가 없으면 "Phishing - T1566" 형식의 값에서 추출
            match = ATTACK_ID_RE.search(cluster.get("value") or "")
            external_id = match.group(0) if match else ""
        if not external_id:
            continue
        name = common_utils.clean_text(cluster.get("value")).rsplit(" - ", 1)[0]
        techniques[external_id] = name
        # 전술(킬체인 단계)도 함께 담는다 — 기법 ID만 나열하면 20개가 넘어가 읽히지
        # 않는다. 갤럭시는 "attack-Enterprise:initial-access" 형태로 준다.
        stages = []
        for entry in meta.get("kill_chain") or []:
            matrix, _, phase = str(entry).partition(":")
            # 갤럭시는 행렬을 플랫폼 이름으로 준다(attack-Windows:initial-access).
            # 모바일·ICS·구 pre-attack 행렬은 우리 환경과 무관하니 뺀다.
            if not phase or not matrix.startswith("attack-"):
                continue
            if phase not in stages:
                stages.append(phase)
        if stages:
            tactics[external_id] = stages
    save("attack_techniques.json", {
        "source": "MISP Galaxy mitre-attack-pattern",
        "techniques": techniques,
        "tactics": tactics,
    })


def build_benign_iocs():
    ips, cidrs, domains = set(), set(), set()
    used = []
    for list_name in WARNINGLISTS:
        try:
            data = fetch_json("{}/{}/list.json".format(WARNINGLIST_BASE, list_name))
        except Exception as error:
            print("[-] warninglist {} 실패(건너뜀): {}".format(list_name, error))
            continue
        used.append(list_name)
        list_type = (data.get("type") or "").lower()
        for value in data.get("list") or []:
            value = str(value).strip().lower()
            if not value or ":" in value:  # IPv6는 수집 대상이 아니므로 제외
                continue
            if list_type == "cidr":
                (cidrs if "/" in value else ips).add(value)
            elif list_type in ("hostname", "domain", "string"):
                domains.add(value.lstrip("."))
    save("benign_iocs.json", {
        "source": "MISP warninglists: {}".format(", ".join(used)),
        "ips": sorted(ips),
        "cidrs": sorted(cidrs),
        "domains": sorted(domains),
    })


def main():
    for build in (build_threat_actor_aliases, build_known_names,
                  build_attack_techniques, build_benign_iocs):
        # 하나가 실패해도 나머지는 갱신한다 (기존 파일은 보존됨)
        try:
            build()
        except Exception as error:
            print("[-] {} 실패: {}".format(build.__name__, error))


if __name__ == "__main__":
    main()
