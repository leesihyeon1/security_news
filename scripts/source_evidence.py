"""Keep publication references separate from actionable indicators."""

from urllib.parse import parse_qs, urlsplit, urlunsplit


def article_url(value):
    value = str(value or "").strip()
    for _ in range(3):
        parsed = urlsplit(value)
        if parsed.path != "/api/click":
            break
        inner = parse_qs(parsed.query).get("url")
        if not inner:
            break
        value = inner[0]
    return value


def canonical_url(value):
    parsed = urlsplit(article_url(value))
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(),
                       parsed.path.rstrip("/"), parsed.query, ""))


def reference_hosts(urls):
    return {urlsplit(article_url(url)).hostname.lower()
            for url in urls if urlsplit(article_url(url)).hostname}


def filter_iocs(iocs, urls):
    """Exclude exact source URLs and bare source hosts, not other paths on a host.

    A publication reference is not evidence that its entire host is safe.
    Explicit indicators on another path remain available for investigation.
    """
    references = {canonical_url(url) for url in urls if url}
    hosts = reference_hosts(urls)
    kept, removed = [], []
    for item in iocs or []:
        kind = str(item.get("type") or "").lower()
        value = str(item.get("value") or "").strip()
        source = ((kind == "url" and canonical_url(value) in references)
                  or (kind == "domain" and value.lower().rstrip(".") in hosts))
        (removed if source else kept).append(item)
    return kept, removed


def filter_targets(targets, urls):
    result = dict(targets or {})
    for key, kind in (("urls", "url"), ("domains", "domain")):
        if key in result:
            kept, _ = filter_iocs([{"type": kind, "value": v} for v in result[key]], urls)
            result[key] = [item["value"] for item in kept]
    return result
