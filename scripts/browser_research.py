"""Question-led web investigation using archived scans and an optional isolated browser.

The dashboard API is public and the worker may run on an analyst's PC. Live browsing
therefore requires an explicitly isolated worker with network egress controls.
"""

import hashlib
import os
import re
from urllib.parse import parse_qsl, urlsplit

import network_safety

QUESTION_RE = re.compile(
    r"clickfix|붙여넣|클립보드|유포지|피싱|가짜.{0,5}(?:인증|캡차)|"
    r"페이지|스크립트|브라우저|리다이렉트|redirect|dom|http|웹 요청|유입 경로",
    re.I,
)
INTERNAL_QUESTION_RE = re.compile(r"(?:사내|내부|우리.{0,3}조직).{0,16}(?:로그|EDR|프록시|이력)", re.I)
ACTION_RE = re.compile(r"verify|human|captcha|copy|continue|확인|인증|복사|계속", re.I)
SIGNAL_RE = re.compile(r"clipboard|writeText|execCommand|powershell|mshta|"
                       r"Win\s*\+\s*R|Ctrl\s*\+\s*V|붙여넣|captcha", re.I)
MAX_REQUESTS = 100
MAX_RESPONSES = 60
MAX_DOM_BYTES = 512_000


def _flag(name):
    """Accept the .env form (`1`, quotes and surrounding whitespace included)."""
    value = str(os.environ.get(name, "")).strip().strip('"\'').lower()
    return value in {"1", "true", "yes", "on"}


def _digest(value):
    if isinstance(value, str):
        value = value.encode("utf-8", errors="replace")
    return hashlib.sha256(value).hexdigest()


def _url_fact(url):
    try:
        parsed = urlsplit(str(url))
        return {"host": (parsed.hostname or "").lower(), "path": (parsed.path or "/")[:160],
                "query_keys": list(dict.fromkeys(key for key, _ in parse_qsl(
                    parsed.query, keep_blank_values=True)))[:8]}
    except ValueError:
        return {"host": "", "path": "", "query_keys": []}


def _command_fact(command):
    destinations = []
    for match in re.finditer(r"https?://[^\s'\"<>]+", str(command), re.I):
        fact = _url_fact(match.group(0))
        if fact["host"] and fact not in destinations:
            destinations.append(fact)
    executable = re.search(r"\b(?:powershell|pwsh|cmd|mshta|curl|certutil)(?:\.exe)?\b",
                           str(command), re.I)
    return {"sha256": _digest(command), "length": len(command),
            "executable": executable.group(0).lower() if executable else "",
            "destinations": destinations[:4],
            "encoded": bool(re.search(r"-enc(?:odedcommand)?\b|FromBase64String", command, re.I))}


def _initiator_fact(event):
    initiator = event.get("initiator") or {}
    frames = (initiator.get("stack") or {}).get("callFrames") or []
    source = initiator.get("url") or (frames[0].get("url") if frames else "")
    fact = _url_fact(source)
    return {"type": initiator.get("type") or "", "host": fact["host"], "path": fact["path"]}


def _snapshot(page):
    dom = page.content()[:MAX_DOM_BYTES]
    labels = page.locator("button, [role='button']").all_text_contents()
    return {"dom_sha256": _digest(dom),
            "signals": sorted(set(match.group(0).lower() for match in SIGNAL_RE.finditer(dom)))[:12],
            "buttons": [" ".join(label.split())[:80] for label in labels[:12] if label.strip()],
            "scripts": [entry[:180] for entry in
                        page.locator("script[src]").evaluate_all(
                            "nodes => nodes.map(node => node.src).slice(0, 20)")]}


def capture(url):
    """Observe one page and one lure-like button; never execute a copied command."""
    network_safety.check_public_url(url)
    from playwright.sync_api import sync_playwright

    requests, responses, clipboard = [], [], []
    initiators = {}
    phase = "before"
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--no-first-run",
            ],
        )
        try:
            context = browser.new_context(
                accept_downloads=False,
                service_workers="block",
                permissions=[],
            )
            context.add_init_script("""
                window.__researchClipboard = [];
                try {
                    Object.defineProperty(navigator, 'clipboard', {configurable: true,
                        value: {writeText: async text => {
                            window.__researchClipboard.push(String(text));
                        }}});
                } catch (e) {}
            """)

            def guard(route):
                try:
                    network_safety.check_public_url(route.request.url)
                except (network_safety.UnsafeUrlError, ValueError):
                    route.abort()
                    return
                route.continue_()

            context.route("**/*", guard)
            page = context.new_page()
            page.on("dialog", lambda dialog: dialog.dismiss())
            cdp = context.new_cdp_session(page)
            cdp.on("Network.requestWillBeSent", lambda event: initiators.setdefault(
                (event.get("request") or {}).get("url") or "", _initiator_fact(event)))
            cdp.send("Network.enable")

            def on_request(request):
                if len(requests) < MAX_REQUESTS:
                    requests.append({"phase": phase, "method": request.method,
                                     "_raw_url": request.url,
                                     **_url_fact(request.url)})

            page.on("request", on_request)
            page.on("response", lambda response: responses.append((response, phase))
                    if len(responses) < MAX_RESPONSES else None)
            page.goto(url, wait_until="domcontentloaded", timeout=15000)
            page.wait_for_timeout(800)
            before = _snapshot(page)
            action = "none"
            action_label = ""
            buttons = page.locator("button, [role='button']").filter(has_text=ACTION_RE)
            if buttons.count():
                try:
                    action_label = " ".join(buttons.first.inner_text(timeout=1000).split())[:80]
                except Exception:
                    pass
                phase = "after"
                try:
                    buttons.first.click(timeout=4000, no_wait_after=True)
                    page.wait_for_timeout(800)
                    action = "clicked_lure_control"
                except Exception:
                    action = "click_failed"
            after = _snapshot(page)
            try:
                clipboard = page.evaluate("window.__researchClipboard || []")[:4]
            except Exception:
                clipboard = []
            http = []
            for response, response_phase in responses:
                row = {"phase": response_phase, **_url_fact(response.url), "status": response.status,
                       "initiator": initiators.get(response.url) or {},
                       "mime": response.headers.get("content-type", "")[:80]}
                if "javascript" in row["mime"] or "text/html" in row["mime"]:
                    try:
                        content_length = response.headers.get("content-length")
                        length = int(content_length) if content_length else -1
                        if 0 <= length <= MAX_DOM_BYTES:
                            body = response.body()
                            if len(body) <= MAX_DOM_BYTES:
                                row["body_sha256"] = _digest(body)
                                row["signals"] = sorted(set(
                                    match.group(0).lower() for match in
                                    SIGNAL_RE.finditer(body.decode("utf-8", errors="replace"))))[:8]
                    except Exception:
                        pass
                http.append(row)
            for row in requests:
                row["initiator"] = initiators.get(row.pop("_raw_url")) or {}
            return {"url": _url_fact(url), "action": action, "action_label": action_label,
                    "before": before, "after": after,
                    "requests": requests, "responses": http,
                    "clipboard": [_command_fact(value) for value in clipboard]}
        finally:
            browser.close()


def enabled():
    return _flag("BROWSER_RESEARCH_ENABLED") and _flag("BROWSER_RESEARCH_ISOLATED_WORKER")


def disabled_reason():
    if not _flag("BROWSER_RESEARCH_ENABLED"):
        return "BROWSER_RESEARCH_ENABLED가 1이 아닙니다"
    if not _flag("BROWSER_RESEARCH_ISOLATED_WORKER"):
        return "BROWSER_RESEARCH_ISOLATED_WORKER가 1이 아닙니다"
    return ""


def investigate(targets, block, route):
    """Give each relevant question an evidence trail and a bounded browser attempt."""
    questions = [q for q in (targets or {}).get("questions") or []
                 if QUESTION_RE.search(q) and not INTERNAL_QUESTION_RE.search(q)]
    seeds = (block or {}).get("seeds") or []
    if not questions or not seeds:
        return None
    results = []
    for seed in seeds[:2]:
        if not seed.get("in_urlscan"):
            continue
        observed = {"domain": seed.get("domain") or "", "scan_url": seed.get("urlscan") or "",
                    "scan_time": seed.get("scanned_at") or "", "dom_status": seed.get("dom_status") or "unobserved",
                    "http": (seed.get("http") or [])[:12], "markers": seed.get("dom_markers") or {}}
        observed["evidence_id"] = "urlscan:" + _digest(
            observed["domain"] + observed["scan_url"] + observed["scan_time"])[:16]
        results.append({"source": "archived_scan", "status": "observed", "evidence": observed})

    candidate = next((seed for seed in seeds if seed.get("scan_url") and
                      (seed.get("dom_markers") or seed.get("dom_confirmed"))), None)
    if not candidate:
        candidate = next((seed for seed in seeds if seed.get("scan_url")), None)
    if candidate:
        target = _url_fact(candidate["scan_url"])
        if enabled():
            try:
                captured = capture(candidate["scan_url"])
                captured["evidence_id"] = "browser:" + captured["after"]["dom_sha256"][:16]
                results.append({"source": "isolated_browser", "status": "observed", "evidence": captured})
            except Exception as error:
                results.append({"source": "isolated_browser", "status": "failed", "target": target,
                                "reason": type(error).__name__})
        else:
            results.append({"source": "isolated_browser", "status": "deferred", "target": target,
                            "reason": "격리 브라우저 조사 워커가 비활성화되었습니다: {}".format(
                                disabled_reason())})
    else:
        results.append({"source": "isolated_browser", "status": "deferred",
                         "reason": "페이지 행동을 확인할 스캔 URL이 없습니다"})
    return {"questions": questions[:6], "results": results}
