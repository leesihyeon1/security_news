# -*- coding: utf-8 -*-
"""브라우저 확장 프로그램을 스토어에 직접 조회한다.

무엇이 빠져 있었나
    공급망 조사는 npm·PyPI·RubyGems 같은 패키지 레지스트리만 조회했다. 그런데 "받아
    쓰는 통로"는 패키지만이 아니다 — 브라우저 확장도 정상 개발자 계정을 인수해 악성
    업데이트를 밀어 넣는 같은 수법의 통로다.

    실측(2026-09-16, 악성 확장 19개 기사): 모델이 주력을 공급망으로 정하고 목표를
    "크롬 웹 스토어와 엣지 애드온 스토어에서 같은 수법의 확장을 식별해 차단 목록을
    만든다"로 세웠는데, 조회는 "레지스트리 이름·패키지로 조회했지만 결과가 없었습니다"
    로 끝났다. 축은 맞게 골랐는데 그 축의 도구가 확장 스토어를 몰랐다.

무엇을 조회하나
    Chrome  확장 업데이트 프로토콜(clients2.google.com/service/update2/crx). 브라우저가
            확장 갱신을 확인할 때 쓰는 그 경로다. 게시 중이면 app status="ok", 내려갔거나
            없는 ID면 status="error-unknownApplication"이 온다. "스토어가 이미 지웠는가"에
            바로 답한다.
    Edge    애드온 스토어의 상세 JSON(getproductdetailsbycrxid). 이름·버전·개발자·설치
            수·최종 갱신일에 더해 manifest 전문이 온다 — permissions와 content_scripts의
            matches까지 들어 있어서, 그 확장이 무엇을 할 수 있는 물건인지가 그대로 보인다.
            없는 ID는 404다.

    둘 다 키가 필요 없다(실측 2026-09-16).

검색은 하지 않는다
    "같은 개발자의 다른 확장을 찾는다"에는 스토어 검색이 필요한데, 두 스토어 모두 검색
    결과가 JS로 그려지는 웹 페이지뿐이고 공개 API가 없다. 페이지를 긁으면 답은 나오지만
    (크롬 검색 페이지 HTML에서 확장 ID 14개가 뽑혔다) 그건 검색엔진 긁기를 ToS 문제로
    접었던 것과 같은 종류의 일이다. 그래서 여기서는 하지 않고, 목표에 그 요구가 있으면
    "이 도구로는 닿지 않는다"고 남긴다. 지어내는 것보다 낫다.

확장 ID
    32자 a-p 문자열이다(크롬이 공개키에서 만들 때 16진수를 a-p로 옮겨 쓴다). 기사 본문과
    1차 자료에서 이 형태를 그대로 뽑는다 — 모델에게 따로 물어보지 않아도 되는, 오인할 수
    없는 형태다.
"""

import json
import re
import time
import urllib.parse
import urllib.request

BS = chr(92)   # 윈도우 경로 구분자. 리터럴에 그대로 쓰면 이스케이프가 꼬인다.
USER_AGENT = "boannews-intel/1.0 (threat research)"
REQUEST_TIMEOUT = 20
PAUSE_SECONDS = 0.5
# 한 기사에서 조회할 확장 수. 19개짜리 기사가 실제로 있어서 그보다 넉넉히 둔다.
MAX_EXTENSIONS = 20
MAX_PERMISSIONS = 10
MAX_MATCHES = 6

# 크롬 확장 ID — 32자, a부터 p까지만 쓴다.
EXTENSION_ID_RE = re.compile(r"(?<![a-z0-9])[a-p]{32}(?![a-z0-9])")

CHROME_UPDATE_URL = (
    "https://clients2.google.com/service/update2/crx?response=updatecheck"
    "&prodversion=120&acceptformat=crx3&x=id%3D{}%26uc")
CHROME_DETAIL_URL = "https://chromewebstore.google.com/detail/{}"
EDGE_DETAIL_API = "https://microsoftedge.microsoft.com/addons/getproductdetailsbycrxid/{}"
EDGE_DETAIL_URL = "https://microsoftedge.microsoft.com/addons/detail/{}"

# 확장은 ID와 같은 이름의 폴더로 풀려 저장된다 — 설치 흔적이 경로에 그대로 남는다.
#
# ID마다 쿼리를 따로 내지 않는다. 확장 11개짜리 사건에서 ID 하나씩 쿼리 3개를 냈더니
# 11개 중 3개만 덮였고, 받는 사람이 어차피 하나로 합쳐 써야 했다(실측 2026-09-18).
# has_any에 전부 넣으면 한 번 돌려 어느 단말에 무엇이 깔렸는지가 같이 나온다.
KQL_TEMPLATE = """let watched = dynamic([{}]);
DeviceFileEvents
| where FolderPath has_any (watched)
| extend ExtensionId = extract(@"([a-p]{{32}})", 1, FolderPath)
| summarize Files = count(), arg_max(Timestamp, FolderPath)
          by DeviceName, InitiatingProcessAccountName, ExtensionId
| order by Timestamp desc"""

# 확장 권한 중 이것이 있으면 "모든 사이트의 내용을 읽고 바꿀 수 있다"는 뜻이다.
BROAD_PERMISSIONS = {
    "<all_urls>", "http://*/*", "https://*/*", "*://*/*",
    "webrequest", "webrequestblocking", "declarativenetrequestwithhostaccess",
    "cookies", "debugger", "proxy", "management", "nativemessaging",
}


def log(message):
    print(message)


def _get(url):
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, "Accept": "*/*"})
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        return response.status, response.read().decode("utf-8", errors="replace")


def ids_from_text(*texts):
    """본문·1차 자료에서 확장 ID를 뽑는다(중복 제거, 등장 순서 유지)."""
    found = []
    for text in texts:
        for match in EXTENSION_ID_RE.findall(str(text or "").lower()):
            if match not in found:
                found.append(match)
    return found[:MAX_EXTENSIONS]


# 확장 ID가 기사에 나오는 이유는 둘이다 — 공격자가 만든 악성 확장이거나, 악성코드가
# 데이터를 훔쳐 가는 정상 확장(지갑·비밀번호 관리자)이다. 형태는 똑같아서 앞뒤 문맥으로
# 가른다.
#
# 실측(2026-09-26, Psychedelic Stealer): Arctic Wolf IOC 표의 "Wallet-Extension Target
# IDs" 아래 MetaMask·Trust Wallet·OKX Wallet ID 6개가 있었다. 역할을 안 보고 전부 악성
# 확장으로 받아 "스토어에 아직 게시 중 — 지금 막지 않으면 계속 설치된다", "GPO로 설치를
# 막는다"를 냈다. 막아도 이 악성코드는 이미 깔린 지갑을 읽어 가므로 공격이 끊기지 않고,
# 정상 지갑 사용만 막는다.
TARGET_CONTEXT_RE = re.compile(
    r"target(?:ed|s|ing)?\s+(?:wallet|extension|id)s?|wallet[-\s]*extension|"
    r"(?:steal|stole|harvest|exfiltrat|collect|grab|target)\w*.{0,80}(?:wallets?|extensions?|password\s+managers?)|"
    r"(?:wallets?|extensions?)\s+(?:it|the\s+(?:malware|stealer))\s+(?:targets|steals|harvests)|"
    r"탈취\s*대상|수집\s*대상|노리는\s*(?:지갑|확장)|대상\s*(?:지갑|확장)|지갑\s*확장", re.I)
MALICIOUS_CONTEXT_RE = re.compile(
    r"malicious\s+(?:browser\s+)?extensions?|rogue\s+extensions?|fake\s+(?:browser\s+)?extensions?|"
    # "installed extensions"(설치돼 있는 확장을 훑는다)는 스틸러 설명에 흔하다 — 공격자가
    # 확장을 심는 동사만 받는다.
    r"(?:installs|drops|side-?loads|deploys|pushes|forces)\s+(?:a|an|the|its|their)?\s*"
    r"(?:own\s+|malicious\s+|rogue\s+|fake\s+)?(?:browser\s+)?extensions?|"
    r"(?:compromised|hijacked|trojani[sz]ed)\s+(?:browser\s+)?extensions?|"
    r"악성\s*확장|가짜\s*확장|확장\s*(?:을|를)?\s*(?:설치|배포|강제)", re.I)
# ID 앞 문맥을 얼마나 볼지. IOC 표는 제목 한 줄 아래 ID가 줄지어 나오므로(ID·이름 한 쌍에
# 50자 안팎), 목록 끝의 ID도 제목에 닿을 만큼 넉넉히 본다.
ROLE_WINDOW_CHARS = 600
# 스토어가 보여 주는 규모. 이만큼 깔린, 개발자가 밝혀진 확장은 문맥이 없을 때 악성으로
# 단정하지 않는다 — 정상 확장 인수 후 악성 업데이트 사례가 있으니 "정상"으로 단정하지도
# 않고 확인 대상으로 둔다.
POPULAR_INSTALLS = 100000
ID_LABEL_RE = re.compile(r"\s*\(([^()]{2,40})\)")


def roles_from_text(*texts):
    """{확장 ID: {"role": "target"|"malicious"|"unknown", "evidence": 문장}}.

    각 등장 위치 앞 ROLE_WINDOW_CHARS자에서 가장 가까운 역할 표현을 쓴다(뒤에 나온 표현이
    그 ID를 설명한다). 등장마다 판정이 갈리면 "unknown" — 강한 쪽으로 몰래 올리지 않는다.
    """
    seen, labels = {}, {}
    for text in texts:
        text = " ".join(str(text or "").split())
        lowered = text.lower()
        for match in EXTENSION_ID_RE.finditer(lowered):
            window_start = max(0, match.start() - ROLE_WINDOW_CHARS)
            window = text[window_start:match.start()]
            hits = [(m.end(), "target", m.start()) for m in TARGET_CONTEXT_RE.finditer(window)]
            hits += [(m.end(), "malicious", m.start()) for m in MALICIOUS_CONTEXT_RE.finditer(window)]
            if hits:
                _, role, hit_start = max(hits)
                # 근거는 역할 표현부터 ID까지 — 표 제목이 멀리 있으면 가운데를 줄인다.
                phrase = text[window_start + hit_start:match.start()]
                if len(phrase) > 180:
                    phrase = phrase[:90] + " … " + phrase[-60:]
                evidence = phrase + text[match.start():match.end() + 40]
            else:
                role, evidence = "unknown", ""
            seen.setdefault(match.group(0), []).append((role, evidence))
            # IOC 표는 ID 뒤에 이름을 괄호로 적는다 — "…gknn (MetaMask)". 스토어가 이름을
            # 못 줄 때(엣지 미게시) 화면에 ID만 남지 않게 받아 둔다.
            named = ID_LABEL_RE.match(text, match.end())
            if named and match.group(0) not in labels:
                labels[match.group(0)] = named.group(1).strip()
    out = {}
    for extension_id, mentions in seen.items():
        roles = {role for role, _ in mentions if role != "unknown"}
        if len(roles) == 1:
            role = roles.pop()
            evidence = next(ev for r, ev in mentions if r == role)
        else:
            role, evidence = "unknown", ("역할 표현이 엇갈립니다" if roles else "")
        out[extension_id] = {"role": role, "evidence": evidence[:240],
                             "label": labels.get(extension_id, "")}
    return out


def lookup_chrome(extension_id):
    """크롬 웹 스토어에 아직 게시돼 있는가. (published, error)"""
    try:
        _, body = _get(CHROME_UPDATE_URL.format(urllib.parse.quote(extension_id)))
    except Exception as error:
        return None, str(error)[:90]
    match = re.search(r'<app[^>]*\bstatus="([^"]+)"', body)
    status = match.group(1) if match else ""
    if not status:
        return None, "응답에서 상태를 찾지 못했습니다"
    # error-unknownApplication은 "그런 확장이 없다" — 내려갔거나 애초에 없는 ID다.
    return status == "ok", ""


def _manifest(raw):
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def lookup_edge(extension_id):
    """엣지 애드온 상세. 없으면 {"found": False}."""
    try:
        _, body = _get(EDGE_DETAIL_API.format(urllib.parse.quote(extension_id)))
    except Exception as error:
        message = str(error)
        if "404" in message:
            return {"found": False, "error": ""}
        return {"found": False, "error": message[:90]}
    try:
        data = json.loads(body)
    except ValueError:
        return {"found": False, "error": "응답을 해석하지 못했습니다"}
    if not isinstance(data, dict) or not data.get("name"):
        return {"found": False, "error": ""}

    manifest = _manifest(data.get("manifest"))
    permissions = [str(p) for p in (manifest.get("permissions") or [])]
    permissions += [str(p) for p in (manifest.get("host_permissions") or [])]
    matches = []
    for script in manifest.get("content_scripts") or []:
        if isinstance(script, dict):
            matches.extend(str(m) for m in (script.get("matches") or []))
    return {
        "found": True,
        "name": str(data.get("name") or "")[:80],
        "version": str(manifest.get("version") or data.get("version") or "")[:24],
        "developer": str(data.get("developer") or data.get("publisherName") or "")[:60],
        "installs": data.get("activeInstallCount") or 0,
        "rating": data.get("averageRating") or 0,
        "permissions": permissions[:MAX_PERMISSIONS],
        "matches": matches[:MAX_MATCHES],
        "error": "",
    }


def broad_permissions(permissions, matches):
    """모든 사이트를 읽고 바꿀 수 있게 하는 권한만 추린다."""
    risky = []
    for value in list(permissions or []) + list(matches or []):
        low = str(value).strip().lower()
        if low in BROAD_PERMISSIONS or low.endswith("://*/*"):
            if value not in risky:
                risky.append(value)
    return risky


def _resolve_role(context_role, edge):
    """문맥 역할 + 스토어 사실 -> "malicious" | "target" | "review" | "unknown".

    문맥이 역할을 밝혔으면 그것을 따른다(악성 확장이 인기 확장을 인수한 경우도 원문이
    "malicious"라고 쓴다). 문맥이 없을 때만 스토어 규모를 본다 — 많이 깔리고 개발자가
    밝혀진 확장은 악성으로 단정하지 않고 확인 대상(review)으로 둔다.
    """
    if context_role in ("malicious", "target"):
        return context_role
    if (edge.get("found") and int(edge.get("installs") or 0) >= POPULAR_INSTALLS
            and edge.get("developer")):
        return "review"
    return "unknown"


def analyze(extension_ids, objective="", roles=None):
    """확장 조회 트랙. 볼 ID가 없으면 None.

    roles는 roles_from_text()의 결과. 차단 후보(live_ids·removed_ids)에는 원문이 악성
    확장이라고 밝힌 것과, 역할 표현도 없고 대형 정상 확장으로도 안 보이는 것만 넣는다
    (예전 동작). 원문이 탈취 대상이라고 밝힌 확장은 target_ids, 문맥 없이 대형 정상
    확장으로 보이는 것은 review_ids로 따로 둔다 — 둘 다 차단 대상이 아니다.
    """
    extension_ids = [e for e in (extension_ids or []) if EXTENSION_ID_RE.fullmatch(e or "")]
    if not extension_ids:
        return None
    roles = roles or {}

    findings, steps, live, removed = [], [], [], []
    targets, review = [], []
    steps.append("기사에서 확장 프로그램 ID {}개를 찾아 크롬·엣지 스토어에 직접 "
                 "조회했습니다 — 아직 게시 중인지, 무엇을 할 수 있는 물건인지 "
                 "보려는 것입니다.".format(len(extension_ids)))

    for extension_id in extension_ids:
        published, error = lookup_chrome(extension_id)
        time.sleep(PAUSE_SECONDS)
        edge = lookup_edge(extension_id)
        time.sleep(PAUSE_SECONDS)
        short = extension_id[:16] + "…"
        context = roles.get(extension_id) or {}
        name = edge.get("name") or context.get("label") or ""
        label = "{}({})".format(name, short) if name else short
        role = _resolve_role(context.get("role") or "unknown", edge)

        if role in ("target", "review"):
            entry = {"id": extension_id, "name": name, "developer": edge.get("developer") or "",
                     "installs": int(edge.get("installs") or 0),
                     "listed": bool(published) or bool(edge.get("found")),
                     "evidence": context.get("evidence") or ""}
            scale = "{}{}".format(
                " · 개발자 " + entry["developer"] if entry["developer"] else "",
                " · 설치 {:,}건".format(entry["installs"]) if entry["installs"] else "")
            if role == "target":
                targets.append(entry)
                findings.append(
                    "확장 {}는 악성 확장이 아니라 이 악성코드가 데이터를 노리는 대상입니다 — "
                    "원문이 탈취 대상 목록에 올렸습니다{}. 차단할 대상이 아니라, 감염 단말에서 "
                    "이 확장을 썼는지로 피해 범위를 가르는 값입니다.".format(label, scale))
            else:
                review.append(entry)
                findings.append(
                    "확장 {}는 원문이 역할을 밝히지 않았고 스토어상 대형 정상 확장입니다{} — "
                    "악성으로 단정하지 않고 차단 목록에서 뺐습니다. 원문에서 이 확장이 왜 "
                    "나오는지(탈취 대상인지, 인수 후 악성 업데이트인지) 확인이 필요합니다."
                    .format(label, scale))
            continue

        if error:
            steps.append("확장 {}를 크롬 스토어에 조회하지 못했습니다 — {}.".format(short, error))
        elif published:
            live.append(extension_id)
            findings.append(
                "확장 {}는 크롬 웹 스토어에 아직 게시돼 있습니다 — 기사가 나온 뒤에도 "
                "내려가지 않았다는 뜻이라, 지금 막지 않으면 계속 설치됩니다.".format(label))
        else:
            removed.append(extension_id)
            # 크롬 업데이트 응답은 "내려갔다"와 "원래 크롬에 없던 ID다"를 같은
            # error-unknownApplication으로 준다. 구분할 방법이 없으니 단정하지 않는다
            # (실측: 엣지에만 있는 확장이 "내려갔다"로 잘못 읽혔다).
            findings.append(
                "확장 {}는 크롬 웹 스토어에서 조회되지 않습니다 — 내려갔거나 애초에 크롬에 "
                "올라온 적이 없는 ID입니다. 내려간 경우라도 이미 설치된 브라우저에서 "
                "자동으로 지워지지는 않으므로 단말 점검은 따로 필요합니다.".format(label))

        if edge.get("error"):
            steps.append("확장 {}를 엣지 스토어에 조회하지 못했습니다 — {}.".format(
                short, edge["error"]))
        elif edge.get("found"):
            if extension_id not in live:
                live.append(extension_id)
            findings.append(
                "· 엣지 애드온에도 같은 ID로 게시돼 있습니다 — {}{} · 설치 {:,}건{}.".format(
                    edge["name"], " " + edge["version"] if edge["version"] else "",
                    int(edge["installs"] or 0),
                    " · 개발자 " + edge["developer"] if edge["developer"] else ""))
            risky = broad_permissions(edge["permissions"], edge["matches"])
            if risky:
                findings.append(
                    "· 요구 권한 {} — 모든 사이트의 내용을 읽고 바꿀 수 있는 범위입니다. "
                    "악성 업데이트 하나로 세션 탈취까지 가능한 구성입니다.".format(
                        ", ".join(risky[:5])))
            elif edge["permissions"]:
                findings.append("· 요구 권한: {}.".format(", ".join(edge["permissions"][:6])))

    if objective and ("다른" in objective or "추가" in objective or "식별" in objective):
        steps.append("같은 개발자·수법의 다른 확장을 스토어에서 더 찾는 것은 이 도구로는 "
                     "닿지 않습니다 — 두 스토어 모두 검색 결과가 스크립트로 그려지는 "
                     "웹 페이지뿐이고 공개 API가 없습니다.")

    if not findings:
        return None
    from datetime import datetime, timezone
    if targets or review:
        steps.append("확장 ID {}개 중 탈취 대상 {}개·확인 필요 {}개는 차단 후보에서 뺐습니다 — "
                     "원문 문맥과 스토어 규모로 역할을 가렸습니다.".format(
                         len(extension_ids), len(targets), len(review)))
    return {
        "findings": findings,
        "steps": steps,
        "live_ids": live,
        "removed_ids": removed,
        "target_ids": targets,
        "review_ids": review,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _ps_array(values):
    return "@(" + ", ".join("'{}'".format(str(v).replace("'", "''")) for v in values) + ")"


def local_commands(extension_ids):
    """단말에서 직접 칠 확인 명령.

    "이미 설치된 단말을 찾는다"고 안내해 놓고 찾는 방법을 안 주면 그 조치는 절반이다.
    MDE 쿼리는 관리 콘솔에서 돌리는 것이고, 눈앞의 PC 한 대를 지금 확인하는 것은 다른
    일이다 — 확장은 ID와 같은 이름의 폴더로 풀리므로 그 폴더만 보면 된다.

    경로에 역슬래시를 쓰지 않고 Join-Path로 만든다. PowerShell은 슬래시도 경로
    구분자로 받고, 그래야 이 파일과 화면·복사 사이에서 이스케이프가 꼬이지 않는다.
    """
    if not extension_ids:
        return []
    lines = [
        "$bad = " + _ps_array(extension_ids),
        "$roots = @(",
        "  (Join-Path $env:LOCALAPPDATA 'Google/Chrome/User Data'),",
        "  (Join-Path $env:LOCALAPPDATA 'Microsoft/Edge/User Data')",
        ")",
        "foreach ($root in $roots) {",
        "  if (-not (Test-Path $root)) { continue }",
        "  Get-ChildItem $root -Recurse -Directory -Filter 'Extensions' -ErrorAction SilentlyContinue |",
        "    ForEach-Object {",
        "      Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue |",
        "        Where-Object { $bad -contains $_.Name } |",
        "        Select-Object @{n='ExtensionId';e={$_.Name}}, FullName, LastWriteTime",
        "    }",
        "}",
    ]
    return [{
        "name": "이 단말에 악성 확장이 깔려 있는지 확인",
        "shell": "PowerShell",
        "note": "사용자 권한으로 돌아간다. 결과가 나오면 그 확장을 제거하고, 광범위 권한을 "
                "가진 확장이었다면 해당 계정의 세션도 무효화해야 한다 — 제거만으로는 이미 "
                "빠져나간 토큰이 끊기지 않는다. 결과가 없으면 이 단말에는 없다는 뜻이고, "
                "나머지 단말은 위 MDE 쿼리로 한 번에 본다.",
        "command": chr(10).join(lines),
    }]



def response_material(block):
    """대응 재료. 다른 hunter와 같은 형식(actions는 문장, blocklists·kql은 목록)이다."""
    block = block or {}
    live = block.get("live_ids") or []
    removed = block.get("removed_ids") or []
    targets = block.get("target_ids") or []
    review = block.get("review_ids") or []
    if not (live or removed or targets or review):
        return None
    actions, blocklists, queries = [], [], []

    def names(entries):
        return ", ".join(e.get("name") or e["id"][:16] + "…" for e in entries[:6])

    if targets:
        # 탈취 대상 확장은 막는 대상이 아니라 피해 범위를 가리는 값이다.
        blocklists.append({
            "label": "차단 금지 — 탈취 대상 확장(정상 확장)",
            "note": "악성코드가 데이터를 훔쳐 가는 대상이다. 설치를 막아도 이미 깔린 확장의 "
                    "데이터는 계속 읽히므로 공격이 끊기지 않는다 — 감염 단말의 피해 범위를 "
                    "가르는 데 쓴다.",
            "values": ["{} ({})".format(e["id"], e["name"]) if e.get("name") else e["id"]
                       for e in targets],
        })
        actions.append(
            "탈취 대상 확장 {}건({})은 차단하지 않는다. 감염이 확인된 단말에서 이 확장을 "
            "썼다면 저장된 비밀값(지갑 시드·개인키·로그인 세션)이 노출된 것으로 보고, 깨끗한 "
            "단말에서 새 지갑을 만들어 자산을 옮기고 연결된 계정 세션을 재발급한다."
            .format(len(targets), names(targets)))
        queries.append({
            "name": "탈취 대상 확장을 쓰는 단말 {}건(피해 범위 산정)".format(len(targets)),
            "platform": "mde_kql",
            "query": KQL_TEMPLATE.format(", ".join('"{}"'.format(e["id"]) for e in targets)),
            "what": "악성 확장 탐지가 아니다. 감염 단말 목록과 겹치는 단말이 지갑·세션 "
                    "교체 대상이다 — 겹치지 않는 단말은 이 확장만으로 조치할 필요가 없다.",
        })
    if review:
        blocklists.append({
            "label": "검토 결과 — 역할 미확인 대형 확장(차단 보류)",
            "note": "원문이 역할을 밝히지 않았고 스토어상 대형 정상 확장이다. 탈취 대상인지, "
                    "인수 후 악성 업데이트인지 원문을 확인한 뒤 판단한다.",
            "values": ["{} ({})".format(e["id"], e["name"]) if e.get("name") else e["id"]
                       for e in review],
        })
    if not (live or removed):
        return {"actions": actions, "blocklists": blocklists, "kql": queries, "commands": []}

    if live:
        blocklists.append({
            "label": "차단 대상 — 확장 프로그램 ID(스토어에 아직 게시 중)",
            "note": "도메인이 아니라 확장 ID다. 그룹 정책으로 설치를 막는다.",
            "values": list(live),
        })
        actions.append(
            "그룹 정책 ExtensionInstallBlocklist에 확장 ID {}건을 넣어 신규 설치를 "
            "막는다 — 스토어가 내리기를 기다리는 동안에도 설치는 계속된다.".format(len(live)))
    actions.append(
        "이미 설치된 단말을 찾는다. 스토어에서 내려가도 설치된 브라우저에서 자동으로 "
        "지워지지 않는다 — 광범위 권한을 가진 확장이었다면 제거 후 해당 계정의 세션을 "
        "무효화해야 탈취된 토큰이 끊긴다.")

    watched = live + [e for e in removed if e not in live]
    if watched:
        queries.append({
            "name": "사내 단말에 설치된 악성 확장 {}건 일괄 탐지".format(len(watched)),
            "platform": "mde_kql",
            "query": KQL_TEMPLATE.format(
                ", ".join('"{}"'.format(value) for value in watched)),
            "what": "확장 ID와 같은 이름의 폴더가 만들어졌는지 — 설치 흔적이다. "
                    "어느 단말에 어느 확장이 깔렸는지 ExtensionId 열로 갈린다.",
        })
    return {"actions": actions, "blocklists": blocklists, "kql": queries,
            "commands": local_commands(live + [e for e in removed if e not in live])}
