# -*- coding: utf-8 -*-
"""패키지 레지스트리(npm·PyPI·Docker Hub 등) 공급망 기사를 조사한다.

왜 필요한가
    공급망 기사에는 해시도 도메인도 CVE도 없는 경우가 많다(실측: "AI Is Giving
    Lesser-Resourced Attackers Nation-State-Level Reach" 기사는 IOC 0건·CVE 0건이라
    조사&대응 카드가 통째로 안 붙었다). 그런데 그 기사가 말하는 위협은 분명하다 —
    "npm·PyPI·Docker Hub에 악성 패키지가 올라오고 있다"이다. 그건 조사할 수 있다.

피벗 방향
    "기사에 나온 캠페인 이름으로 패키지를 찾는" 방향은 안 된다. 실측으로 확인했다:
    GitHub 악성 패키지 권고 최근 100건 전문에 Shai-Hulud·Miasma·Dustmaker·TeamPCP가
    하나도 없다. 권고 제목은 "Malicious code in @scope/name (npm)" 형식뿐이라
    캠페인 이름을 담지 않는다. 그 방향으로 만들면 없는 것을 지어내게 된다.

    그래서 방향을 뒤집는다. "기사 → 패키지"가 아니라 "레지스트리 → 우리"다.
    기사가 지목한 레지스트리에 지금 무엇이 올라오고 있는지를 보여주고, 그것이
    사내에 들어왔는지 확인할 쿼리를 준다.

쓰는 곳
    전부 키 없이 조회된다(실측 2026-09-10: 7개 API 모두 HTTP 200).
      GitHub Advisory  type=malware  — 등재된 악성 패키지 목록
      OSV.dev          /v1/query     — 패키지별 취약점·악성 이력
      PyPI / npm 레지스트리          — 배포일·삭제 여부
"""

import json
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import common_utils
import analysis_targets

# 한 번에 받는 최대 건수. GitHub API의 페이지 상한이 100이라 이 위는 잘린다 —
# 잘렸다는 사실을 확인내용에 밝혀야 "100건"이 실제 총계인 것처럼 읽히지 않는다.
ADVISORY_PAGE_SIZE = 100
ADVISORY_URL = ("https://api.github.com/advisories?type=malware&ecosystem={}"
                "&per_page=" + str(ADVISORY_PAGE_SIZE) + "&sort=published&direction=desc")
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
PYPI_URL = "https://pypi.org/pypi/{}/json"
NPM_URL = "https://registry.npmjs.org/{}"

ADVISORY_UI_URL = "https://github.com/advisories?query=type%3Amalware+ecosystem%3A{}"
OSV_UI_URL = "https://osv.dev/list?q={}&ecosystem={}"
PYPI_UI_URL = "https://pypi.org/project/{}/"
NPM_UI_URL = "https://www.npmjs.com/package/{}"

CACHE_FILE = common_utils.DATA_DIR / "malware_packages_cache.json"
# GitHub API는 비인증 시간당 60회다. 하루 한두 번이면 충분하고, 12시간 캐시면 같은 날
# 여러 번 돌려도 한도에 닿지 않는다(vuln_hunter의 KEV 캐시와 같은 방식).
CACHE_HOURS = 12
REQUEST_TIMEOUT = 20
PAUSE_SECONDS = 1.0
# 개별 패키지 조회는 기사에 이름이 나온 경우에만 하고, 그것도 이 개수까지만 한다.
MAX_PACKAGE_LOOKUPS = 8
# 확인내용에 나열할 최근 등재 패키지 수. 전부 늘어놓으면 읽히지 않는다.
MAX_LISTED_PACKAGES = 12
# "최근"의 기준. 기사가 다루는 캠페인이 몇 달짜리여도, 지금 조치할 것은 최근 등재분이다.
RECENT_DAYS = 14

BS = chr(92)

# npm 뒤·앞에 이런 말이 있어야 대문자 "NPM"을 레지스트리로 본다.
NPM_CONTEXT = (r"(?:packages?|registry|ecosystem|install|malicious|typosquat\w*|javascript|"
               r"node\.?js|supply[\s-]*chain|패키지|레지스트리|생태계|저장소|악성|공급망|"
               r"자바스크립트|타이포스쿼트)")

# 기사에서 레지스트리를 알아보는 표현. GitHub Advisory의 ecosystem 값에 맞춰 둔다 —
# 그 값이 그대로 조회 키가 된다.
#
# npm은 단어 경계와 대소문자를 본다. 예전 r"npm"은 re.I로 어디서나 걸려서, 제품행사
# 기사 "Riverbed NPM 360"(Network Performance Monitoring)이 npm 레지스트리 조회를
# 일으킬 수 있었다(실측 2026-09-30 events.jsonl). 레지스트리 이름은 원문에서 거의 항상
# 소문자 "npm"으로 쓰이므로 소문자 낱말은 그대로 인정하고, 대문자·혼합 표기("NPM
# packages", "악성 NPM 패키지")는 가까이에 패키지·레지스트리 문맥이 있을 때만 인정한다.
# 한글이 바로 붙는 "npm에"도 낱말로 보려고 \b 대신 ASCII 경계를 쓴다.
REGISTRY_PATTERNS = (
    ("npm", r"(?-i:(?<![A-Za-z0-9])npm(?![A-Za-z0-9]))|npmjs"
            r"|(?<![A-Za-z0-9])npm(?![A-Za-z0-9])(?=[^\n]{0,24}?" + NPM_CONTEXT + r")"
            r"|" + NPM_CONTEXT + r"[^\n]{0,24}?(?<![A-Za-z0-9])npm(?![A-Za-z0-9])"
            r"|node[\s-]*package|노드\s*패키지"),
    ("pip", r"pypi|pip\s+install|python\s*package\s*index|파이썬\s*패키지"),
    ("rubygems", r"rubygems|ruby\s*gem"),
    ("maven", r"maven|메이븐"),
    ("nuget", r"nuget|뉴겟"),
    ("rust", r"crates\.io|cargo\s+add"),
    ("go", r"go\s*modules|pkg\.go\.dev"),
    ("composer", r"packagist|composer\s+require"),
)
REGISTRY_LABELS = {
    "npm": "npm", "pip": "PyPI", "rubygems": "RubyGems", "maven": "Maven",
    "nuget": "NuGet", "rust": "crates.io", "go": "Go 모듈", "composer": "Packagist",
}

# Docker Hub는 GitHub Advisory의 ecosystem에 없다 — 별도로 감지해서 문장으로만 다룬다.
DOCKER_RE = re.compile(r"docker\s*hub|dockerhub|컨테이너\s*이미지|container\s*image", re.I)

# 공급망 기사인지 판단하는 보조 신호. 레지스트리 이름이 없어도 이런 표현이 있으면
# 공급망 맥락으로 본다.
SUPPLY_CHAIN_RE = re.compile(
    r"소프트웨어\s*공급망|software\s*supply[\s-]*chain|의존성|dependency|오픈소스\s*패키지|악성\s*패키지|"
    r"malicious\s*package|typosquat|타이포스쿼트|저장소\s*오염|package\s*registry",
    re.I,
)
# "공급망" 한 단어는 물류·규제·ESG 문맥에도 흔하다(실측 2026-09-30: "유럽 공급망 규제 대응"
# 기사가 패키지 레지스트리 조사로 갔다). 앞뒤 가까이에 소프트웨어·공격 문맥이 있을 때만
# 소프트웨어 공급망 신호로 본다.
BARE_SUPPLY_CHAIN_RE = re.compile(r"공급망|supply[\s-]*chain", re.I)
SOFTWARE_CONTEXT_RE = re.compile(
    r"공격|악성|오염|침해|해킹|탈취|백도어|감염|패키지|오픈소스|라이브러리|빌드|업데이트|"
    r"레지스트리|SBOM|소프트웨어|코드|attack|compromis|malicious|backdoor|software|package|"
    r"open[\s-]*source|librar|build|update|registry|npm|pypi|github", re.I)
SUPPLY_CHAIN_WINDOW = 24


def _software_supply_chain(blob):
    for match in BARE_SUPPLY_CHAIN_RE.finditer(blob):
        window = blob[max(0, match.start() - SUPPLY_CHAIN_WINDOW):match.end() + SUPPLY_CHAIN_WINDOW]
        if SOFTWARE_CONTEXT_RE.search(window):
            return True
    return False

# 기사 본문에서 패키지 이름을 뽑는 형태. 임의의 단어를 패키지로 오인하지 않게,
# 스코프 표기이거나 설치 명령 뒤에 온 것만 인정한다.
SCOPED_PKG_RE = re.compile(r"@[a-z0-9][a-z0-9._-]{0,38}/[a-z0-9][a-z0-9._-]{0,38}", re.I)
INSTALL_PKG_RE = re.compile(
    r"(?:npm|pnpm|yarn)\s+(?:install|add|i)\s+([@a-z0-9][a-z0-9@._/-]{1,60})"
    r"|pip3?\s+install\s+([a-z0-9][a-z0-9._-]{1,60})"
    r"|docker\s+pull\s+([a-z0-9][a-z0-9._/-]{1,60})",
    re.I,
)


def log(message):
    print(message)


def _request_json(url, headers=None, payload=None):
    request = urllib.request.Request(url, data=payload, headers=headers or {})
    request.add_header("User-Agent", "boannews-intel/1.0 (threat research)")
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


# ── 기사 읽기 ────────────────────────────────────────────────────────────────
def registries_from_text(text):
    """기사가 지목한 레지스트리 목록. GitHub Advisory의 ecosystem 값으로 돌려준다."""
    blob = text or ""
    found = []
    for ecosystem, pattern in REGISTRY_PATTERNS:
        if re.search(pattern, blob, re.I):
            found.append(ecosystem)
    return found


def mentions_docker(text):
    return bool(DOCKER_RE.search(text or ""))


def is_supply_chain(text, title=""):
    """공급망 기사로 볼 수 있는가 — 레지스트리 이름이 있거나 공급망 표현이 있으면."""
    blob = "{} {}".format(title or "", text or "")
    return bool(registries_from_text(blob) or mentions_docker(blob)
                or SUPPLY_CHAIN_RE.search(blob) or _software_supply_chain(blob))


def packages_from_text(text, ecosystems=()):
    """기사에 실제로 적힌 패키지 이름. 없으면 빈 목록 — 지어내지 않는다."""
    blob = text or ""
    names = []
    for match in SCOPED_PKG_RE.finditer(blob):
        names.append(("npm", match.group(0)))
    for match in INSTALL_PKG_RE.finditer(blob):
        npm_name, pip_name, docker_name = match.group(1), match.group(2), match.group(3)
        if npm_name:
            names.append(("npm", npm_name))
        elif pip_name:
            names.append(("pip", pip_name))
        elif docker_name:
            names.append(("docker", docker_name))
    seen, out = set(), []
    for ecosystem, name in names:
        key = (ecosystem, name.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"ecosystem": ecosystem, "name": name})
    return out[:MAX_PACKAGE_LOOKUPS]


# ── 레지스트리 조회 ──────────────────────────────────────────────────────────
def _load_cache():
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_cache(cache):
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    except OSError as error:
        log("[-] 악성 패키지 캐시 저장 실패(조회에는 영향 없음): {}".format(error))


def load_malware_advisories(ecosystem):
    """레지스트리에 등재된 악성 패키지 권고 목록(최신순). 실패하면 빈 목록."""
    cache = _load_cache()
    entry = cache.get(ecosystem) or {}
    fetched = entry.get("fetched_at") or ""
    if fetched:
        try:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(fetched)
            if age < timedelta(hours=CACHE_HOURS):
                return entry.get("advisories") or []
        except ValueError:
            pass

    try:
        rows = _request_json(ADVISORY_URL.format(urllib.parse.quote(ecosystem)),
                             headers={"Accept": "application/vnd.github+json"})
    except Exception as error:
        log("[-] 악성 패키지 권고 조회 실패({}): {}".format(ecosystem, error))
        return entry.get("advisories") or []

    advisories = []
    for row in rows if isinstance(rows, list) else []:
        packages = []
        for item in row.get("vulnerabilities") or []:
            name = ((item.get("package") or {}).get("name") or "").strip()
            if name and name not in packages:
                packages.append(name)
        advisories.append({
            "id": row.get("ghsa_id") or "",
            "published": (row.get("published_at") or "")[:10],
            "summary": " ".join((row.get("summary") or "").split())[:160],
            "url": row.get("html_url") or "",
            "packages": packages,
        })
    cache[ecosystem] = {"fetched_at": datetime.now(timezone.utc).isoformat(),
                        "advisories": advisories}
    _save_cache(cache)
    return advisories


def recent_advisories(advisories, days=RECENT_DAYS):
    """최근 등재분만. 오래된 것은 이미 조치가 끝났을 가능성이 높다."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    return [item for item in advisories if (item.get("published") or "") >= cutoff]


def lookup_package(ecosystem, name):
    """패키지 하나의 현재 상태. 존재 여부와 알려진 문제를 함께 본다."""
    result = {"ecosystem": ecosystem, "name": name, "exists": None,
              "osv_count": 0, "osv_ids": [], "note": ""}

    osv_ecosystem = {"npm": "npm", "pip": "PyPI"}.get(ecosystem)
    if osv_ecosystem:
        try:
            data = _request_json(
                OSV_QUERY_URL,
                payload=json.dumps({"package": {"name": name,
                                                "ecosystem": osv_ecosystem}}).encode())
            vulns = data.get("vulns") or []
            result["osv_count"] = len(vulns)
            result["osv_ids"] = [v.get("id") for v in vulns[:4] if v.get("id")]
        except Exception as error:
            result["note"] = "OSV 조회 실패({})".format(str(error)[:40])
        time.sleep(PAUSE_SECONDS)

    url = None
    if ecosystem == "pip":
        url = PYPI_URL.format(urllib.parse.quote(name))
    elif ecosystem == "npm":
        url = NPM_URL.format(urllib.parse.quote(name, safe="@/"))
    if url:
        try:
            _request_json(url)
            result["exists"] = True
        except Exception as error:
            # 404는 "이미 내려갔다"는 뜻이라 실패가 아니라 결과다.
            result["exists"] = False if "404" in str(error) else None
        time.sleep(PAUSE_SECONDS)
    return result


# ── 조사 ─────────────────────────────────────────────────────────────────────
def _registry_link(ecosystem):
    return ADVISORY_UI_URL.format(urllib.parse.quote(ecosystem))


def analyze(text, title="", iocs=None, targets=None):
    """공급망 트랙. 조사할 것이 없으면 None."""
    blob = "{} {}".format(title or "", text or "")
    ecosystems = registries_from_text(blob)
    packages = analysis_targets.packages(targets or {})
    known = {(p["ecosystem"], p["name"].lower()) for p in packages}
    packages.extend(p for p in packages_from_text(blob)
                    if (p["ecosystem"], p["name"].lower()) not in known)
    packages = packages[:MAX_PACKAGE_LOOKUPS]
    for package in packages:
        if package["ecosystem"] not in ecosystems:
            ecosystems.append(package["ecosystem"])
    docker = mentions_docker(blob)
    if not ecosystems and not docker:
        return None

    steps, findings = [], []
    listed = []
    total_recent = 0

    # A named incident must not inherit unrelated packages from a registry feed.
    for ecosystem in ([] if packages else ecosystems):
        advisories = load_malware_advisories(ecosystem)
        if not advisories:
            steps.append("{} 악성 패키지 권고를 조회했지만 결과를 받지 못했습니다."
                         .format(REGISTRY_LABELS.get(ecosystem, ecosystem)))
            continue
        recent = recent_advisories(advisories)
        total_recent += len(recent)
        packages = [name for item in recent for name in item["packages"]]
        steps.append("{} 악성 패키지 권고 {}건(한 번에 받는 최대치 {})을 받았고, 최근 {}일 "
                     "등재분은 {}건입니다.".format(
                         REGISTRY_LABELS.get(ecosystem, ecosystem), len(advisories),
                         ADVISORY_PAGE_SIZE, RECENT_DAYS, len(recent)))
        if recent:
            newest = recent[0]
            # 한 번에 100건까지만 받아온다. 받은 것이 전부 최근분이면 그 위가 잘렸다는
            # 뜻이라 "100건"이라고 단정하면 실제보다 적게 말하는 것이 된다.
            capped = len(advisories) >= ADVISORY_PAGE_SIZE and len(recent) == len(advisories)
            findings.append(
                "{}에 최근 {}일간 악성 패키지가 {}{}건 등재됐습니다(가장 최근 {} · {}). "
                "레지스트리 배경 통계이며 이번 사건과의 연관성은 확인되지 않았습니다.".format(
                    REGISTRY_LABELS.get(ecosystem, ecosystem), RECENT_DAYS,
                    "최소 " if capped else "", len(recent),
                    newest["published"], newest["packages"][0] if newest["packages"] else newest["id"]))
            if capped:
                findings.append("· 조회는 한 번에 {}건까지만 받으므로 실제 등재는 더 많습니다 "
                                "— 아래 링크에서 전체 목록을 봅니다.".format(ADVISORY_PAGE_SIZE))
            findings.append("· 최근 등재 예: {}{}".format(
                ", ".join(packages[:MAX_LISTED_PACKAGES]),
                " 외 {}건".format(len(packages) - MAX_LISTED_PACKAGES)
                if len(packages) > MAX_LISTED_PACKAGES else ""))
            listed.append({"ecosystem": ecosystem,
                           "label": REGISTRY_LABELS.get(ecosystem, ecosystem),
                           "recent": len(recent), "packages": packages[:60],
                           "url": _registry_link(ecosystem)})

    if docker:
        # Docker Hub는 GitHub Advisory가 다루지 않는다 — 없는 조회를 한 척하지 않는다.
        findings.append(
            "Docker Hub는 GitHub 악성 패키지 권고가 다루지 않아 같은 방식으로 셀 수 "
            "없습니다. 이미지 쪽은 사내에서 쓰는 베이스 이미지의 최종 갱신일과 서명 "
            "여부를 직접 확인해야 합니다.")
        steps.append("Docker Hub 언급을 확인했지만, 등재 현황을 셀 수 있는 공개 목록이 "
                     "없어 조회 대신 확인 절차로 대체했습니다.")

    checked = []
    for item in packages:
        if item["ecosystem"] == "docker":
            continue
        info = lookup_package(item["ecosystem"], item["name"])
        checked.append(info)
        state = ("레지스트리에 아직 있습니다" if info["exists"] is True
                 else "현재 조회되지 않습니다(삭제·차단 여부는 원문과 대조)" if info["exists"] is False
                 else "존재 여부를 확인하지 못했습니다")
        findings.append("기사에 적힌 {} 패키지 {}: {}{}".format(
            REGISTRY_LABELS.get(item["ecosystem"], item["ecosystem"]), item["name"], state,
            " · OSV에 {}건 등록".format(info["osv_count"]) if info["osv_count"] else ""))
    if packages:
        steps.append("기사에 적힌 패키지 {}건을 OSV·레지스트리에서 조회했습니다."
                     .format(len(packages)))
    else:
        # 이 사실 자체가 판단에 필요하다 — 차단할 대상이 기사에 없다는 뜻이다.
        steps.append("기사에 패키지 이름이 적혀 있지 않아 개별 조회는 하지 않았습니다.")
        findings.append(
            "이 기사에는 차단할 패키지 이름이 나오지 않습니다. 그래서 대응은 개별 차단이 "
            "아니라 \"우리 쪽에 무엇이 들어왔는지\"를 확인하는 방향이어야 합니다.")

    if not findings:
        return None
    return {
        "ecosystems": ecosystems,
        "docker": docker,
        "registries": listed,
        "packages": checked,
        "recent_total": total_recent,
        "findings": findings,
        "steps": steps,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


# ── 대응 ─────────────────────────────────────────────────────────────────────
ECOSYSTEM_BINARIES = {
    "npm": ("npm.cmd", "npm.exe", "npx.cmd", "node.exe", "yarn.cmd", "pnpm.cmd"),
    "pip": ("pip.exe", "pip3.exe", "python.exe", "pythonw.exe", "uv.exe", "poetry.exe"),
    "rubygems": ("gem.cmd", "gem.exe", "bundle.cmd", "ruby.exe"),
    "nuget": ("nuget.exe", "dotnet.exe"),
    "maven": ("mvn.cmd", "gradle.bat", "java.exe"),
    "rust": ("cargo.exe",),
    "go": ("go.exe",),
    "composer": ("composer.bat", "php.exe"),
}
DEFAULT_BINARIES = ("npm.cmd", "npm.exe", "pip.exe", "pip3.exe", "python.exe")


def _install_kql(names, ecosystem_label, ecosystem="npm"):
    """개발자 단말에서 그 패키지를 설치한 흔적. 지표가 없어도 이건 만들 수 있다."""
    from response_builder import _kql_list, LOOKBACK
    return {
        "name": "{} 악성 패키지 설치 흔적".format(ecosystem_label),
        "durable": False,
        "note": "등재된 악성 패키지 이름을 그대로 찾는다. 이름은 계속 바뀌므로 이 쿼리는 "
                "오래 못 간다 — 지금 들어온 것이 있는지 확인하는 용도다. 결과가 나오면 "
                "그 단말의 node_modules·site-packages와 사내 아티팩트 저장소를 함께 본다.",
        "query": "\n".join([
            "let badPackages = {};".format(_kql_list(names)),
            "DeviceProcessEvents",
            "| where Timestamp > ago({})".format(LOOKBACK),
            "| where FileName in~ ({})".format(", ".join(
                '"{}"'.format(binary) for binary in
                ECOSYSTEM_BINARIES.get(ecosystem, DEFAULT_BINARIES))),
            "| where ProcessCommandLine has_any (badPackages)",
            "| project Timestamp, DeviceName, AccountName, ProcessCommandLine,"
            " InitiatingProcessFileName",
            "| order by Timestamp desc",
        ]),
    }


def _lockfile_kql():
    """설치 명령을 못 잡았을 때의 두 번째 그물 — 잠금 파일이 바뀐 시점."""
    from response_builder import LOOKBACK
    return {
        "name": "의존성 잠금 파일 변경",
        "durable": True,
        "note": "패키지가 언제 들어왔는지는 잠금 파일이 바뀐 시점에 남는다. 설치 명령을 "
                "CI 러너에서 돌려 단말 로그에 안 남는 경우까지 잡으려는 것이다. "
                "평상시에도 자주 바뀌므로, 위 쿼리에서 나온 단말·시각과 겹치는 것만 본다.",
        "query": "\n".join([
            "DeviceFileEvents",
            "| where Timestamp > ago({})".format(LOOKBACK),
            "| where FileName in~ (\"package-lock.json\", \"yarn.lock\", \"pnpm-lock.yaml\","
            " \"requirements.txt\", \"poetry.lock\", \"Pipfile.lock\")",
            "| where ActionType in (\"FileCreated\", \"FileModified\")",
            "| summarize Changes=count(), Files=make_set(FolderPath, 10)"
            " by DeviceName, AccountName, bin(Timestamp, 1d)",
            "| order by Changes desc",
        ]),
    }


# 사용자 단에서 직접 돌리는 명령. 화면은 이걸 KQL과 따로 그린다 — KQL은 Defender
# 포털에 붙여넣는 것이고 이건 의심 단말의 터미널에서 도는 것이라 대상이 다르다.
# 회사 표준 셸이 PowerShell이라 그쪽으로 쓰고, 리눅스·맥 대응은 note에 적는다.
PS_ARRAY_MAX = 60


def _ps_array(names):
    return "@(" + ", ".join("'{}'".format(name.replace("'", "''"))
                            for name in names[:PS_ARRAY_MAX]) + ")"


def _local_commands(registries):
    """확인 → 제거 → 정리 → 재설치 순서. 제거만으로 끝나지 않는다는 것을 note에 밝힌다."""
    commands = []
    for registry in registries:
        ecosystem = registry.get("ecosystem")
        names = registry.get("packages") or []
        if not names:
            continue

        if ecosystem == "npm":
            commands.append({
                "name": "npm — 설치 여부 확인",
                "shell": "PowerShell",
                "note": "프로젝트 폴더에서 돌린다. 의존성 트리 전체를 보므로 직접 설치하지 "
                        "않고 다른 패키지가 끌어온 경우도 잡힌다. 전역 설치는 -g를 붙여 "
                        "한 번 더 돌린다. macOS·리눅스는 같은 명령을 bash에서 for 문으로 "
                        "바꿔 쓰면 된다.",
                "command": "\n".join([
                    "$bad = " + _ps_array(names),
                    "foreach ($p in $bad) {",
                    "  $found = npm ls $p --depth=Infinity 2>$null",
                    "  if ($LASTEXITCODE -eq 0) { Write-Host \"발견: $p\"; $found }",
                    "}",
                ]),
            })
            commands.append({
                "name": "npm — 제거 후 깨끗이 재설치",
                "shell": "PowerShell",
                "note": "개별 uninstall만으로는 하위 의존성에 남는다. node_modules와 잠금 "
                        "파일을 지우고 npm ci로 다시 세우는 것이 확실하다. 다만 잠금 파일에 "
                        "악성 버전이 고정돼 있으면 그대로 다시 받으므로, 지우기 전에 잠금 "
                        "파일에서 해당 이름을 먼저 확인한다.",
                "command": "\n".join([
                    "$bad = " + _ps_array(names),
                    "# 1) 잠금 파일에 남아 있는지 먼저 본다",
                    "Select-String -Path package-lock.json -Pattern ($bad -join '|')",
                    "# 2) 지목된 패키지를 지운다",
                    "foreach ($p in $bad) { npm uninstall $p 2>$null }",
                    "# 3) 트리와 캐시를 통째로 비우고 다시 세운다",
                    "Remove-Item -Recurse -Force node_modules -ErrorAction SilentlyContinue",
                    "Remove-Item -Force package-lock.json -ErrorAction SilentlyContinue",
                    "npm cache clean --force",
                    "npm install",
                ]),
            })
        elif ecosystem == "pip":
            commands.append({
                "name": "PyPI — 설치 여부 확인",
                "shell": "PowerShell",
                "note": "가상환경마다 따로 돌려야 한다. 전역 파이썬과 각 venv를 모두 본다.",
                "command": "\n".join([
                    "$bad = " + _ps_array(names),
                    "pip list --format=freeze | Select-String -Pattern "
                    "(\"^(\" + ($bad -join '|') + \")==\")",
                ]),
            })
            commands.append({
                "name": "PyPI — 제거 후 깨끗이 재설치",
                "shell": "PowerShell",
                "note": "pip는 의존성을 함께 지우지 않는다. 지운 뒤 requirements.txt로 다시 "
                        "세우되 --no-cache-dir를 붙여 로컬 캐시에 남은 악성 휠을 다시 쓰지 "
                        "않게 한다. 가상환경을 통째로 새로 만드는 편이 더 확실하다.",
                "command": "\n".join([
                    "$bad = " + _ps_array(names),
                    "foreach ($p in $bad) { pip uninstall -y $p }",
                    "pip cache purge",
                    "# 가상환경을 새로 만드는 쪽을 권한다",
                    "# Remove-Item -Recurse -Force .venv; python -m venv .venv; "
                    ".venv" + BS + "Scripts" + BS + "Activate.ps1",
                    "pip install --no-cache-dir -r requirements.txt",
                ]),
            })
    return commands


def response_material(track):
    """공급망 대응 — 확인할 패키지 목록과 유입 흔적 쿼리."""
    if not track:
        return None

    actions, blocklists, queries = [], [], []
    names = []
    # 기사에 적힌 패키지 중 아직 살아 있는 것은 앞에 둔다 — 먼저 볼 대상이다.
    for item in track.get("packages") or []:
        if item.get("name") and item["name"] not in names:
            names.insert(0, item["name"])

    if names:
        actions.append(
            "아래 목록은 이번 기사에서 식별한 조사 대상 패키지다. 차단 목록에 넣기 전에 사내 "
            "아티팩트 저장소(Nexus·Artifactory 등)와 CI 캐시에 이미 받아둔 것이 있는지 "
            "먼저 확인한다 — 이미 들어와 있으면 차단만으로는 끝나지 않는다.")
        # 화면(renderBlocklist)은 label과 문자열 배열을 받는다 — 다른 키 이름이나 객체를
        # 넣으면 "[object Object]"로 찍힌다(실측).
        blocklists.append({
            "label": "확인 대상 — 이번 사건의 패키지",
            "note": "관련 없는 최근 등재 패키지는 제외했습니다. 버전·실행 조건·관측 시기를 원문과 대조합니다.",
            "values": names[:80],
        })
        for registry in incident_registries(track):
            if registry.get("packages"):
                queries.append(_install_kql(registry["packages"][:60], registry["label"],
                                            ecosystem=registry.get("ecosystem") or "npm"))
        queries.append(_lockfile_kql())

    if track.get("docker"):
        actions.append(
            "컨테이너 이미지는 등재 목록으로 셀 수 없다. 사내에서 쓰는 베이스 이미지의 "
            "다이제스트를 고정(pin)했는지, 태그만 보고 받아오고 있지는 않은지 확인한다 — "
            "태그는 같은 이름으로 내용이 바뀔 수 있다.")
    if not track.get("packages"):
        actions.append(
            "기사에 패키지 이름이 없으므로 개별 차단으로는 대응이 끝나지 않는다. "
            "의존성 목록을 뽑아 두면 다음부터 등재분과 자동으로 대조할 수 있다.")

    commands = [c for c in _local_commands(incident_registries(track))
                if "설치 여부 확인" in c["name"]]
    if commands:
        # 제거로 끝난다고 읽히면 안 된다 — 설치 시점에 postinstall 스크립트가 이미
        # 사용자 권한으로 돌았기 때문에, 그때 빠져나간 것은 지운다고 돌아오지 않는다.
        actions.append(
            "설치와 실제 실행·탈취를 구분한다. 실행 버전·조건을 대조하고 패키지·잠금 파일·CI 로그를 "
            "먼저 보존한다. 노출이 확인되거나 배제할 수 없는 자격증명만 범위를 정해 폐기·재발급한다. "
            "오염된 node_modules와 빌드 산출물은 검증한 소스·잠금 파일로 격리 환경에서 재구축한다. "
            "조사 중 npm install·uninstall로 의심 패키지의 수명주기 스크립트를 실행하지 않는다.")
    if not actions and not queries and not commands:
        return None
    return {"actions": actions, "blocklists": blocklists, "kql": queries,
            "commands": commands}


def incident_registries(track):
    grouped = {}
    for item in track.get("packages") or []:
        if item.get("name"):
            ecosystem = item.get("ecosystem") or "npm"
            grouped.setdefault(ecosystem, []).append(item["name"])
    return [{"ecosystem": key, "label": REGISTRY_LABELS.get(key, key), "packages": names}
            for key, names in grouped.items()]


if __name__ == "__main__":
    import argparse
    import sys

    for stream in (sys.stdout, sys.stderr):
        if stream and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="공급망(패키지 레지스트리) 조사")
    parser.add_argument("--text", default="", help="기사 본문")
    parser.add_argument("--title", default="", help="기사 제목")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = analyze(args.text, title=args.title)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=1))
    elif not result:
        print("공급망 기사로 보이지 않습니다.")
    else:
        print("[레지스트리] {}".format(", ".join(
            REGISTRY_LABELS.get(e, e) for e in result["ecosystems"]) or "-"))
        for line in result["findings"]:
            print(("   " if line.startswith("· ") else " ") + line)
        print()
        for line in result["steps"]:
            print(" - " + line)
