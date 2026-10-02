"""Content-level investigation identities, separate from blocking decisions."""

import hashlib
import json
import re
from urllib.parse import urlsplit, urlunsplit


SHARED_HOSTS = {"chatgpt.com", "chat.openai.com", "sites.google.com", "docs.google.com",
                "gemini.google.com", "claude.ai", "copilot.microsoft.com"}
HASH_RE = re.compile(r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\Z")
URL_RE = re.compile(r"https?://[^\s<>\"'`]+", re.I)


def web_url(value):
    value = str(value or "").strip().replace("[.]", ".").replace("hxxp", "http").replace("[:]", ":")
    if "://" not in value and "/" in value and "." in value.split("/", 1)[0]:
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        if (parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or any(c.isspace() for c in value)):
            return ""
        parsed.port
        return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/",
                           parsed.query, ""))
    except ValueError:
        return ""


def shared(value):
    host = urlsplit(web_url(value)).hostname if web_url(value) else str(value).lower()
    return host in SHARED_HOSTS


def content_url(value):
    url = web_url(value)
    if not url:
        return ""
    path = urlsplit(url).path
    return url if path not in {"", "/"} else ""


def identity(value):
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def exact_query(value):
    url = web_url(value)
    quoted = json.dumps(url, ensure_ascii=False)
    return '(task.url.keyword:{} OR page.url.keyword:{})'.format(quoted, quoted)


def scan_matches(scan, value):
    expected = web_url(value)
    return bool(expected and expected in {
        web_url((scan.get("task") or {}).get("url")),
        web_url((scan.get("page") or {}).get("url"))})


# 원문은 공유 주소를 스킴 없이 무력화 표기로 쓰는 경우가 많다(sites.google[.]com/view/...).
BARE_SHARED_RE = re.compile(
    r"(?<![\w/.])(?:" + "|".join(re.escape(h) for h in sorted(SHARED_HOSTS, key=len, reverse=True))
    + r")/[^\s<>\"'`]+", re.I)


def shared_urls(text):
    plain = str(text or "").replace("[.]", ".").replace("hxxp", "http").replace("[:]", ":")
    found = [match.group(0) for match in URL_RE.finditer(plain)]
    found += ["https://" + match.group(0) for match in BARE_SHARED_RE.finditer(plain)]
    return list(dict.fromkeys(url for raw in found
                             if (url := content_url(raw.rstrip(".,;)]}"))) and shared(url)))


def urls(targets, iocs=()):
    values = list((targets or {}).get("urls") or [])
    values += [i.get("value") for i in iocs or []
               if str(i.get("type") or "").lower() == "url"]
    return list(dict.fromkeys(url for value in values if (url := web_url(value))
                             and (not shared(url) or content_url(url))))


def sample_order(hashes, evidence="", limit=2):
    """Prefer complementary sample roles; retain all unselected hashes for follow-up."""
    valid = list(dict.fromkeys(str(v).lower() for v in hashes or [] if HASH_RE.fullmatch(str(v))))
    roles = [("payload", r"final|payload|\bRAT\b|최종|페이로드"),
             ("loader", r"loader|로더|sideload|\.dll\b"),
             ("installer", r"installer|설치|\.msi\b|dropper")]
    grouped = {name: [] for name, _ in roles}
    for value in valid:
        position = evidence.lower().find(value)
        context = evidence[max(0, position - 180):position + len(value) + 120] if position >= 0 else ""
        role = next((name for name, pattern in roles if re.search(pattern, context, re.I)), "")
        if role:
            grouped[role].append(value)
    selected = [rows[0] for rows in grouped.values() if rows]
    return list(dict.fromkeys(selected + valid))[:limit]
