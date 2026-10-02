"""Private checkpoints and recoverable Redis queue operations for the analysis worker."""

import hashlib
import json
import time
from contextvars import ContextVar


STAGE_PREFIX = "worker-progress:"
PROCESSING_KEY = "worker-progress:processing"
RETRY_KEY = "worker-progress:retry"
STAGE_TTL_SECONDS = 6 * 60 * 60
LEASE_SECONDS = 30 * 60
MAX_RETRIES = 2
_active = ContextVar("worker_progress_active", default=(None, ""))


def activate(client, ref):
    return _active.set((client, ref or ""))


def reset(token):
    _active.reset(token)


def current():
    return _active.get()


def fingerprint(*parts):
    raw = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _stage_key(ref, stage):
    return STAGE_PREFIX + "stage:" + fingerprint(ref) + ":" + stage


def load(client, ref, stage, digest):
    if client is None or not ref:
        return None
    try:
        raw = client.get(_stage_key(ref, stage))
        data = json.loads(raw) if raw else {}
        return data.get("value") if data.get("digest") == digest else None
    except Exception:
        return None


def save(client, ref, stage, digest, value):
    if client is None or not ref:
        return False
    try:
        client.set(_stage_key(ref, stage), json.dumps({"digest": digest, "value": value},
                   ensure_ascii=False, default=str), ex=STAGE_TTL_SECONDS)
        return True
    except Exception:
        return False


def clear(client, ref, stage):
    if client is not None and ref:
        try:
            client.delete(_stage_key(ref, stage))
        except Exception:
            pass


def _lease_key(raw):
    return STAGE_PREFIX + "lease:" + fingerprint(raw)


def claim(client, queue_key):
    """LMOVE keeps a job in Redis until completion; legacy test clients use LPOP."""
    if hasattr(client, "lmove"):
        raw = client.lmove(queue_key, PROCESSING_KEY, "LEFT", "RIGHT")
        if raw is not None:
            client.set(_lease_key(raw), str(time.time()), ex=LEASE_SECONDS * 2)
        return raw
    return client.lpop(queue_key)


def release(client, raw):
    if raw is not None and hasattr(client, "lrem"):
        client.lrem(PROCESSING_KEY, 1, raw)
        client.delete(_lease_key(raw))


def recover_expired(client, queue_key, now=None):
    if not hasattr(client, "lmove"):
        return 0
    now = time.time() if now is None else now
    recovered = 0
    for raw in client.lrange(PROCESSING_KEY, 0, -1):
        stamp = client.get(_lease_key(raw))
        try:
            fresh = stamp is not None and now - float(stamp) < LEASE_SECONDS
        except (TypeError, ValueError):
            fresh = False
        if not fresh and _move_expired(client, queue_key, raw):
            client.delete(_lease_key(raw))
            recovered += 1
    return recovered


def _move_expired(client, queue_key, raw):
    if hasattr(client, "eval"):
        return client.eval(
            "if redis.call('LREM', KEYS[1], 1, ARGV[1]) > 0 then "
            "redis.call('LPUSH', KEYS[2], ARGV[1]); return 1 end return 0",
            2, PROCESSING_KEY, queue_key, raw)
    if client.lrem(PROCESSING_KEY, 1, raw):
        client.lpush(queue_key, raw)
        return 1
    return 0


def defer_retry(client, job, now=None):
    count = int(job.get("_retry_count") or 0)
    if count >= MAX_RETRIES or not hasattr(client, "zadd"):
        return False
    retry = dict(job, _retry_count=count + 1)
    delay = 60 * (3 ** count)
    client.zadd(RETRY_KEY, {json.dumps(retry, ensure_ascii=False):
                            (time.time() if now is None else now) + delay})
    return True


def promote_retries(client, queue_key, now=None):
    if not hasattr(client, "zrangebyscore"):
        return 0
    due = client.zrangebyscore(RETRY_KEY, "-inf", time.time() if now is None else now,
                              start=0, num=20)
    promoted = 0
    for raw in due:
        if _promote_one(client, queue_key, raw):
            promoted += 1
    return promoted


def _promote_one(client, queue_key, raw):
    if hasattr(client, "eval"):
        return client.eval(
            "if redis.call('ZREM', KEYS[1], ARGV[1]) > 0 then "
            "redis.call('RPUSH', KEYS[2], ARGV[1]); return 1 end return 0",
            2, RETRY_KEY, queue_key, raw)
    if client.zrem(RETRY_KEY, raw):
        client.rpush(queue_key, raw)
        return 1
    return 0
