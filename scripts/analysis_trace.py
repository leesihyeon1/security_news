"""Observed execution metadata for a single deep-analysis run, never model thoughts."""

import contextlib
import functools
import hashlib
import inspect
import json
import re
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_active = ContextVar("analysis_trace", default=None)
_parent = ContextVar("analysis_trace_parent", default=None)
MAX_EVENTS = 1000
PUBLIC_BYTES = 32000
SECRET = re.compile(r"token|password|secret|authorization|api.?key|signature|credential", re.I)
TEXT_FIELDS = {"prompt", "body", "article", "analysis", "text", "raw", "raw_html", "html",
               "primary", "extra", "history", "evidence", "materials"}
PUBLIC_FIELDS = {"url", "source_url", "article_url", "value", "type", "role", "actionable",
                 "id", "status", "kind", "primary", "subtype", "decision_status", "verdict",
                 "tracks", "questions", "objective", "reason", "disposition", "question",
                 "goal", "action", "incident_label", "query", "name", "title", "hash_value",
                 "hashes", "domains", "urls", "uuid", "page_host", "origin"}


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_text(value):
    value = str(value)
    if value.startswith(("https://", "http://")):
        try:
            parts = urlsplit(value)
            host = parts.hostname or ""
            if parts.port:
                host += ":" + str(parts.port)
            query = [(key, "[redacted]" if SECRET.search(key) else val)
                     for key, val in parse_qsl(parts.query, keep_blank_values=True)]
            value = urlunsplit((parts.scheme, host, parts.path, urlencode(query), ""))
        except ValueError:
            return "[invalid URL]"
    value = re.sub(r"(?i)(bearer\s+)[\w.\-]+", r"\1[redacted]", value)
    return value[:240]


def describe(value, field="", depth=0):
    """Allow-listed summaries keep prompts, headers and private objects out of exports."""
    if SECRET.search(field):
        return "[redacted]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if field in TEXT_FIELDS or field not in PUBLIC_FIELDS:
            return {"chars": len(value), "sha256": hashlib.sha256(value.encode()).hexdigest()[:16]}
        return safe_text(value)
    if isinstance(value, (list, tuple)):
        result = {"count": len(value)}
        if depth < 2 and value:
            result["sample"] = [describe(row, field, depth + 1) for row in value[:3]]
            if len(value) > 3:
                result["sample_omitted"] = len(value) - 3
        return result
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if SECRET.search(str(key)):
                continue
            if key in PUBLIC_FIELDS:
                result[key] = describe(item, key, depth + 1)
            elif isinstance(item, (list, tuple)):
                result[key] = {"count": len(item)}
        return dict(list(result.items())[:16])
    if hasattr(value, "status_code"):
        return {"http_status": value.status_code, "url": safe_text(getattr(value, "url", ""))}
    return {"type": type(value).__name__}


class Trace:
    def __init__(self):
        self.started_at = now()
        self.events = []
        self.total = 0
        self.kind_counts = {}

    def export(self):
        events = [dict(row) for row in self.events]
        data = {"version": 1, "started_at": self.started_at, "completed_at": now(),
                "total_events": self.total, "events": events, "kind_counts": dict(self.kind_counts),
                "omitted_events": self.total - len(events)}
        size = lambda: len(json.dumps(data, ensure_ascii=False).encode("utf-8"))
        if size() > PUBLIC_BYTES:
            # Keep every operation before reducing the timeline itself.
            for row in events:
                for key in ("inputs", "output"):
                    if key in row and len(json.dumps(row[key], ensure_ascii=False)) > 180:
                        row[key] = _counts_only(row[key])
                        row["detail_limited"] = True
        while events and size() > PUBLIC_BYTES:
            events.pop(len(events) // 2)
            data["omitted_events"] += 1
        return data


def _counts_only(value):
    if isinstance(value, dict):
        return {key: _counts_only(item) for key, item in value.items() if key != "sample"}
    return value


@contextlib.contextmanager
def session():
    trace = Trace()
    token = _active.set(trace)
    parent_token = _parent.set(None)
    try:
        yield trace
    finally:
        _parent.reset(parent_token)
        _active.reset(token)


@contextlib.contextmanager
def span(label, stage=None, kind="code", function="", inputs=None):
    trace = _active.get()
    if trace is None:
        yield {}
        return
    parent = _parent.get()
    trace.total += 1
    trace.kind_counts[kind] = trace.kind_counts.get(kind, 0) + 1
    row = {"id": "e" + str(trace.total), "stage": stage or (parent or {}).get("stage") or "summary",
           "kind": kind, "label": label, "function": function, "started_at": now(),
           "status": "completed"}
    if parent:
        row["parent_id"] = parent["id"]
    if inputs:
        row["inputs"] = inputs
    if len(trace.events) < MAX_EVENTS:
        trace.events.append(row)
    token = _parent.set(row)
    started = time.monotonic()
    try:
        yield row
    except Exception as error:
        row.update(status="failed", error=type(error).__name__)
        raise
    finally:
        row["duration_ms"] = round((time.monotonic() - started) * 1000)
        _parent.reset(token)


def note(label, stage=None, kind="code", status="completed", **facts):
    with span(label, stage, kind) as row:
        row.update(status=status, output={key: describe(value, key) for key, value in facts.items()})


def step(label, stage=None, kind="code", inputs=(), empty="empty"):
    def decorate(function):
        signature = inspect.signature(function)

        @functools.wraps(function)
        def wrapped(*args, **kwargs):
            if _active.get() is None:
                return function(*args, **kwargs)
            values = signature.bind_partial(*args, **kwargs).arguments
            with span(label, stage, kind, function.__module__ + "." + function.__name__,
                      {key: describe(values[key], key) for key in inputs if key in values}) as row:
                result = function(*args, **kwargs)
                row["output"] = describe(result)
                if result is None or result == "" or result == []:
                    row["status"] = empty
                return result
        return wrapped
    return decorate


def capture(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        with session() as trace:
            result = function(*args, **kwargs)
        if isinstance(result, dict):
            result["execution_trace"] = trace.export()
        return result
    return wrapped


def llm_request(post, url, *, payload, headers=None, timeout=None, provider=""):
    """Record each actual HTTP attempt, including retries, without request content."""
    kwargs = {"json": payload, "timeout": timeout}
    if headers is not None:
        kwargs["headers"] = headers
    if _active.get() is None:
        return post(url, **kwargs)
    with span("LLM API 요청", kind="llm_attempt", inputs={
        "provider": provider, "model": str(payload.get("model") or ""),
        "max_tokens": payload.get("max_tokens"),
        "json_format": bool(payload.get("response_format") or payload.get("format")),
    }) as row:
        response = post(url, **kwargs)
        row["http_status"] = response.status_code
        if response.status_code != 200:
            row["status"] = "failed"
        else:
            try:
                data = response.json() or {}
                choice = (data.get("choices") or [{}])[0]
                row["finish_reason"] = choice.get("finish_reason") or data.get("done_reason") or ""
                usage = data.get("usage") or {}
                row["usage"] = {key: usage[key] for key in ("prompt_tokens", "completion_tokens", "total_tokens")
                                if isinstance(usage.get(key), int)}
                if row["finish_reason"] == "length":
                    row["status"] = "partial"
            except (ValueError, TypeError, AttributeError, IndexError):
                row["status"] = "partial"
        return response
