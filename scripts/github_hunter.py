# -*- coding: utf-8 -*-
"""기사가 지목한 GitHub 저장소·계정·파일을 직접 조회한다.

무엇이 빠져 있었나
    공급망 기사에서 IOC가 저장소 주소 하나뿐인 경우가 흔한데, 우리는 그 주소의
    도메인(github.com)만 보고 끝냈다. 실측("무심코 방치한 API 키의 역습" 기사):
    IOC가 https://github.com/pierrenade/short-video-generator-AI 하나였고, 조사는
    github.com이 10년 된 정상 인프라라는 것만 확인했다. 정작 봐야 할 저장소·계정·
    파일은 열지 않았다.

    같은 기사의 종합 판단이 스스로 물었다 — "src/fs.py의 해시는 무엇인가",
    "공격자 계정의 다른 저장소에도 유사 악성코드가 있는가". 둘 다 무료 GitHub API로
    답할 수 있는 질문이었다.

무엇을 조회하나
    저장소 메타데이터(생성일·스타·최근 푸시·보관 여부), 계정의 다른 저장소, 그리고
    기사가 지목한 파일의 내용이다. 파일을 받으면 SHA-256을 계산해 둔다 — 그 해시가
    후속 조회의 입력이 되어 VirusTotal로 이어진다.

404도 결과다
    저장소가 없으면 GitHub가 이미 내렸다는 뜻이다. 그건 "위험이 사라졌다"와 다르다 —
    내려가기 전에 클론해 간 사본은 개발자 머신과 CI 캐시에 그대로 남는다. 그 구분을
    findings에 명시한다.

한도
    비인증 시간당 60회다. 저장소 1건 + 계정 1건 + 저장소 목록 1건 + 파일 몇 건이면
    한 기사에 5~6회다. 캐시는 두지 않는다 — 저장소 상태는 시간마다 바뀌는 값이라
    묵은 값을 쓰면 "아직 살아 있다"를 잘못 말한다.
"""

import hashlib
import json
import re
import time
import urllib.parse
import urllib.request

REPO_URL = "https://api.github.com/repos/{}/{}"
USER_URL = "https://api.github.com/users/{}"
USER_REPOS_URL = "https://api.github.com/users/{}/repos?per_page={}&sort=updated"
CONTENTS_URL = "https://api.github.com/repos/{}/{}/contents/{}"
REPO_WEB_URL = "https://github.com/{}/{}"

REQUEST_TIMEOUT = 25
PAUSE_SECONDS = 1.0
MAX_OTHER_REPOS = 10
MAX_FILES = 3
# 파일 본문은 해시 계산과 짧은 인용에만 쓴다. 전체를 판단 재료로 넣으면 프롬프트가
# 소스 코드로 가득 찬다.
MAX_FILE_BYTES = 200000
MAX_SNIPPET_CHARS = 400

# 기사·분석문에서 저장소 주소를 찾는다. 조직/저장소 두 토막까지만 본다.
REPO_RE = re.compile(
    r"github\.com/([A-Za-z0-9][A-Za-z0-9._-]{0,38})/([A-Za-z0-9][A-Za-z0-9._-]{0,99})",
    re.I)
# 저장소 이름이 아닌 경로들 — 이걸 저장소로 보면 없는 것을 조회한다.
NOT_REPO = {
    "features", "pricing", "topics", "collections", "sponsors", "about", "login",
    "settings", "marketplace", "explore", "notifications", "orgs", "apps",
    "security", "readme", "blog", "site", "issues", "pulls", "search",
}
# 파일 경로처럼 보이는 값(조사 대상의 "파일" 줄에서 온다).
PATHISH_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$")


def log(message):
    print(message)


def _request(url):
    request = urllib.request.Request(url, headers={
        "User-Agent": "boannews-intel/1.0 (threat research)",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
        raw = response.read()
        return response.status, json.loads(raw.decode("utf-8", errors="replace"))


def _get(url):
    """(상태, 데이터). 404는 오류가 아니라 결과다 — 내려갔다는 뜻."""
    try:
        return _request(url)
    except urllib.error.HTTPError as error:
        return error.code, None
    except Exception as error:
        log("    [-] GitHub 조회 실패: {}".format(str(error)[:70]))
        return 0, None


def refs_from(iocs=None, text="", targets=None):
    """조회할 저장소 목록. 기사에 적힌 것만 — 지어내지 않는다."""
    blob = " ".join(
        [text or ""]
        + [str(item.get("value") or "") for item in (iocs or [])]
        + [str(v) for values in (targets or {}).values()
           if isinstance(values, list) for v in values])
    found, seen = [], set()
    for match in REPO_RE.finditer(blob):
        owner, repo = match.group(1), match.group(2)
        repo = re.sub(r"\.git$", "", repo).rstrip(".,)\"'")
        if owner.lower() in NOT_REPO or not repo or repo.lower() in NOT_REPO:
            continue
        key = (owner.lower(), repo.lower())
        if key in seen:
            continue
        seen.add(key)
        found.append({"owner": owner, "repo": repo})
    return found


def file_paths_from(targets):
    """조사 대상의 "파일" 줄에서 저장소 안 경로로 보이는 것만."""
    out = []
    for value in (targets or {}).get("files") or []:
        value = str(value).strip().strip("`\"'")
        if PATHISH_RE.match(value) and value not in out:
            out.append(value)
    return out[:MAX_FILES]


def lookup_repo(owner, repo):
    """저장소 상태. 없으면 gone=True."""
    status, data = _get(REPO_URL.format(urllib.parse.quote(owner), urllib.parse.quote(repo)))
    time.sleep(PAUSE_SECONDS)
    if status == 404:
        return {"owner": owner, "repo": repo, "gone": True}
    if not isinstance(data, dict):
        return {"owner": owner, "repo": repo, "error": status}
    return {
        "owner": owner, "repo": repo, "gone": False,
        "created": (data.get("created_at") or "")[:10],
        "pushed": (data.get("pushed_at") or "")[:10],
        "stars": data.get("stargazers_count"),
        "forks": data.get("forks_count"),
        "archived": bool(data.get("archived")),
        "description": " ".join(str(data.get("description") or "").split())[:160],
        "default_branch": data.get("default_branch") or "main",
        "url": data.get("html_url") or REPO_WEB_URL.format(owner, repo),
    }


def lookup_owner(owner):
    """계정 상태와 그 계정의 다른 저장소. 같은 수법이 여러 곳에 뿌려졌는지 본다."""
    status, data = _get(USER_URL.format(urllib.parse.quote(owner)))
    time.sleep(PAUSE_SECONDS)
    info = {"owner": owner, "gone": status == 404}
    if isinstance(data, dict):
        info.update({
            "created": (data.get("created_at") or "")[:10],
            "public_repos": data.get("public_repos"),
            "followers": data.get("followers"),
            "url": data.get("html_url") or "",
        })
    status, repos = _get(USER_REPOS_URL.format(urllib.parse.quote(owner), MAX_OTHER_REPOS))
    time.sleep(PAUSE_SECONDS)
    others = []
    if isinstance(repos, list):
        for item in repos:
            if not isinstance(item, dict):
                continue
            others.append({"name": item.get("name") or "",
                           "created": (item.get("created_at") or "")[:10],
                           "stars": item.get("stargazers_count"),
                           "url": item.get("html_url") or ""})
    info["others"] = others
    return info


def fetch_file(owner, repo, path):
    """저장소 안 파일의 내용과 SHA-256. 해시는 후속 조회(VT)의 입력이 된다."""
    status, data = _get(CONTENTS_URL.format(
        urllib.parse.quote(owner), urllib.parse.quote(repo),
        urllib.parse.quote(path.lstrip("/"))))
    time.sleep(PAUSE_SECONDS)
    if status == 404 or not isinstance(data, dict):
        return {"path": path, "gone": True}
    import base64
    raw = b""
    if data.get("encoding") == "base64" and data.get("content"):
        try:
            raw = base64.b64decode(data["content"])
        except Exception:
            raw = b""
    if not raw or len(raw) > MAX_FILE_BYTES:
        return {"path": path, "gone": False, "size": data.get("size"),
                "sha256": "", "snippet": ""}
    text = raw.decode("utf-8", errors="replace")
    return {
        "path": path, "gone": False, "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "snippet": " ".join(text.split())[:MAX_SNIPPET_CHARS],
        "url": data.get("html_url") or "",
    }


SEARCH_URL = "https://api.github.com/search/repositories?q={}&per_page={}&sort=updated"
MAX_SEARCH_TERMS = 2
MAX_SEARCH_RESULTS = 5
# 검색어가 짧으면 무관한 저장소가 쏟아진다.
MIN_TERM_CHARS = 5


def search_terms(targets):
    """저장소를 찾을 검색어 — 악성코드·캠페인 이름과 CVE 번호."""
    out = []
    for key in ("malware", "cves"):
        for value in (targets or {}).get(key) or []:
            value = str(value).strip()
            if len(value) >= MIN_TERM_CHARS and value not in out:
                out.append(value)
    return out[:MAX_SEARCH_TERMS]


def search_repos(term):
    """이름으로 GitHub 저장소를 찾는다. 대응에 쓸 완화 패치·IOC 목록이 여기 있다.

    실측(StyleSmuggler): 검색 한 번에 IOC 툴킷, 근본 원인 패치, 긴급 완화 모듈,
    Adobe 공식 패치를 composer로 배포하는 저장소가 나왔다. 기사에는 하나도 없었고,
    그중 하나의 설명에서 Adobe 권고 번호(APSB26-146)까지 확인됐다.

    다만 이 결과는 그대로 쓰면 안 된다 — 가짜 패치·가짜 스캐너를 올려 두는 수법이
    실제로 있다. 확인 대상으로만 넘긴다.
    """
    status, data = _get(SEARCH_URL.format(
        urllib.parse.quote(term), MAX_SEARCH_RESULTS))
    time.sleep(PAUSE_SECONDS)
    if not isinstance(data, dict):
        return []
    out = []
    for item in data.get("items") or []:
        if not isinstance(item, dict):
            continue
        out.append({
            "name": item.get("full_name") or "",
            "stars": item.get("stargazers_count"),
            "created": (item.get("created_at") or "")[:10],
            "description": " ".join(str(item.get("description") or "").split())[:140],
            "url": item.get("html_url") or "",
        })
    return out


def analyze(iocs=None, text="", targets=None):
    """GitHub 트랙. 조회할 저장소가 없으면 None."""
    refs = refs_from(iocs, text, targets)
    terms = search_terms(targets)
    if not refs and not terms:
        return None

    paths = file_paths_from(targets)
    findings, steps, repos, files = [], [], [], []
    seen_owners = set()

    for ref in refs[:2]:      # 한 기사에 저장소가 여러 개인 경우는 드물다
        info = lookup_repo(ref["owner"], ref["repo"])
        repos.append(info)
        label = "{}/{}".format(ref["owner"], ref["repo"])
        if info.get("gone"):
            steps.append("저장소 {}를 GitHub API로 조회했더니 404였습니다.".format(label))
            findings.append(
                "저장소 {}는 GitHub에서 이미 내려갔습니다(404). 다만 내려가기 전에 클론해 "
                "간 사본은 개발자 머신과 CI 캐시에 그대로 남습니다 — 위험이 사라진 것이 "
                "아니라 새로 받는 경로만 막힌 것입니다.".format(label))
        elif info.get("error"):
            steps.append("저장소 {} 조회가 HTTP {}로 실패했습니다.".format(label, info["error"]))
        else:
            steps.append("저장소 {}의 메타데이터를 조회했습니다(생성·푸시·스타·보관 여부)."
                         .format(label))
            findings.append(
                "저장소 {}는 아직 살아 있습니다 — {} 생성, 마지막 푸시 {}, 스타 {}개{}. "
                "지금도 새로 클론될 수 있으니 프록시에서 이 경로를 막아야 합니다.".format(
                    label, info.get("created") or "?", info.get("pushed") or "?",
                    info.get("stars"), ", 보관됨" if info.get("archived") else ""))
            # 생성이 최근인데 스타가 많으면 신뢰도를 꾸민 흔적이다. 기사가 그렇게
            # 주장하더라도 우리가 본 수치로 확인해 준다.
            if isinstance(info.get("stars"), int) and info["stars"] >= 100 and info.get("created"):
                findings.append("· 생성일({})에 비해 스타가 {}개입니다 — 신규 저장소에 스타가 "
                                "몰리는 것은 신뢰도를 꾸미는 흔한 수법입니다.".format(
                                    info["created"], info["stars"]))

        if ref["owner"].lower() not in seen_owners:
            seen_owners.add(ref["owner"].lower())
            owner_info = lookup_owner(ref["owner"])
            steps.append("계정 {}와 그 계정의 다른 저장소를 조회했습니다.".format(ref["owner"]))
            if owner_info.get("gone"):
                findings.append("계정 {}도 사라졌습니다 — GitHub가 계정 단위로 정지했다는 "
                                "뜻이라, 같은 계정의 다른 저장소도 함께 내려갔습니다."
                                .format(ref["owner"]))
            elif owner_info.get("others"):
                names = [o["name"] for o in owner_info["others"] if o.get("name")]
                findings.append(
                    "계정 {}에 다른 공개 저장소가 {}건 있습니다({}). 같은 수법이 여러 곳에 "
                    "뿌려졌는지 확인해야 합니다 — 하나만 막으면 나머지로 다시 들어옵니다."
                    .format(ref["owner"], len(names), ", ".join(names[:6])))
            elif not owner_info.get("gone"):
                findings.append("계정 {}에 남아 있는 공개 저장소는 없습니다.".format(ref["owner"]))

        # 기사가 지목한 파일을 받아 해시를 만든다 — 이 해시가 후속 조회로 VT까지 간다.
        if not info.get("gone") and not info.get("error"):
            for path in paths:
                got = fetch_file(ref["owner"], ref["repo"], path)
                files.append(dict(got, repo=label))
                if got.get("gone"):
                    steps.append("파일 {}는 그 저장소에 없습니다.".format(path))
                elif got.get("sha256"):
                    steps.append("파일 {}를 받아 SHA-256을 계산했습니다({}자)."
                                 .format(path, got.get("size")))
                    findings.append(
                        "기사가 지목한 파일 {}의 SHA-256은 {}입니다 — 이 값으로 "
                        "VirusTotal·사내 EDR을 조회하면 실행 흔적을 찾을 수 있습니다."
                        .format(path, got["sha256"]))

    # 이름으로 저장소를 찾는다 — 다른 사람이 이미 만들어 둔 완화 패치·IOC 목록이
    # 대응에 바로 쓰인다. 기사에는 대개 나오지 않는다.
    community = []
    for term in terms:
        hits = search_repos(term)
        if not hits:
            steps.append("\"{}\"로 GitHub 저장소를 검색했지만 결과가 없었습니다.".format(term))
            continue
        steps.append("\"{}\"로 GitHub 저장소를 검색해 {}건을 찾았습니다 — 완화 패치·IOC "
                     "목록이 올라와 있는지 보려는 것입니다.".format(term, len(hits)))
        community.extend(hits)
        findings.append(
            "\"{}\" 이름으로 공개된 저장소가 {}건 있습니다: {}. 완화 패치·IOC 목록이 "
            "섞여 있어 대응에 바로 쓸 수 있지만, 그대로 신뢰하면 안 됩니다 — 가짜 패치를 "
            "올려 두는 수법이 실제로 있어 코드를 읽고 검증한 뒤 써야 합니다.".format(
                term, len(hits),
                ", ".join("{}({}★)".format(h["name"], h["stars"]) for h in hits[:3])))
        for hit in hits[:2]:
            if hit["description"]:
                findings.append("· {} — {}".format(hit["name"], hit["description"]))

    if not findings:
        return None
    from datetime import datetime, timezone
    return {
        "repos": repos, "files": files, "community": community,
        "findings": findings, "steps": steps,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def response_material(track):
    """GitHub 대응 — 막을 것은 저장소 경로이지 github.com이 아니다."""
    if not track:
        return None
    from response_builder import LOOKBACK

    live = [r for r in track.get("repos") or [] if not r.get("gone") and not r.get("error")]
    hashes = [f["sha256"] for f in track.get("files") or [] if f.get("sha256")]
    actions, blocklists, queries = [], [], []

    if live:
        paths = ["{}/{}".format(r["owner"], r["repo"]) for r in live]
        actions.append(
            "막을 대상은 저장소 경로다 — github.com을 막으면 개발이 멈춘다. 프록시·SWG에 "
            "URL 규칙으로 {} 경로만 차단하고, 사내 Git 미러·아티팩트 저장소에서도 같은 "
            "경로를 금지 목록에 넣는다.".format(", ".join(paths)))
        blocklists.append({
            "label": "차단 대상 — 저장소 경로(도메인 아님)",
            "note": "URL 단위로 막는다. 도메인·IP를 막으면 GitHub 전체가 막힌다.",
            "values": [r.get("url") or "https://github.com/{}/{}".format(r["owner"], r["repo"])
                       for r in live],
        })
    if hashes:
        actions.append(
            "저장소에서 받은 파일의 해시를 확보했다 — 이 값으로 EDR에서 실행 흔적을 "
            "찾는 것이 사내 영향 여부를 확정하는 가장 빠른 길이다.")

    if track.get("repos"):
        from response_builder import _kql_list
        names = [r["repo"] for r in track["repos"] if r.get("repo")]
        queries.append({
            "name": "저장소 클론·빌드 흔적",
            "durable": False,
            "note": "이름이 명령줄에 남는다. git clone 외에 pip install git+, npm install "
                    "github: 형태로도 들어오므로 명령줄 전체를 본다. 저장소가 이미 내려갔어도 "
                    "과거에 클론한 흔적은 이 쿼리로 남는다.",
            "query": "\n".join([
                "let repoNames = {};".format(_kql_list(names)),
                "DeviceProcessEvents",
                "| where Timestamp > ago({})".format(LOOKBACK),
                "| where ProcessCommandLine has_any (repoNames)",
                "| project Timestamp, DeviceName, AccountName, FileName,"
                " ProcessCommandLine, InitiatingProcessFileName",
                "| order by Timestamp desc",
            ]),
        })
    if not actions and not queries:
        return None
    return {"actions": actions, "blocklists": blocklists, "kql": queries}
