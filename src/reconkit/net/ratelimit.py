"""Cross-process per-key minimum-interval rate limiter.

A politeness floor that is shared across every worker/process via Redis, so N
workers honour ONE global budget per key (per API host, per tenant, whatever you
key on) instead of each hammering the target at the full rate. Only calls that
share a key serialize; independent keys never wait on each other.

- Redis-backed and atomic (a Lua CAS), so two processes cannot both slip a call
  through inside the same interval.
- Degrades gracefully: if Redis is unreachable it falls back to a per-process
  in-memory floor; if you disable it entirely it is a no-op.
- Zero opinion about *what* you rate-limit — you pass the key and the interval.

    from reconkit.net.ratelimit import RateLimiter

    rl = RateLimiter(redis_url="redis://localhost:6379/0", intervals={
        "api.example.com": 1.0,   # >= 1s between calls to this host, globally
        "api.slowvendor.io": 15.0,
    })
    rl.acquire("api.example.com")   # blocks just long enough to stay polite
    resp = requests.get("https://api.example.com/...")
"""

from __future__ import annotations
import logging
import threading
import time
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Atomic "space calls to this key by >= interval". Returns milliseconds to wait.
# Serializes across every process that shares this Redis. Stored value is the
# next-allowed epoch-ms; a 60s PX keeps idle keys from lingering.
_LUA = """
local last = tonumber(redis.call('get', KEYS[1]) or '0')
local now = tonumber(ARGV[1])
local interval = tonumber(ARGV[2])
local nxt = last + interval
if nxt <= now then
  redis.call('set', KEYS[1], now, 'PX', 60000)
  return 0
else
  redis.call('set', KEYS[1], nxt, 'PX', 60000)
  return nxt - now
end
"""


class RateLimiter:
    """Per-key minimum-interval limiter, shared across processes via Redis.

    Parameters
    ----------
    intervals:
        Mapping of key -> minimum seconds between two acquisitions of that key.
        A key not present (or interval <= 0) means "no limit".
    redis_url:
        Redis connection URL. If omitted or unreachable, the limiter uses a
        per-process in-memory floor instead (still correct within one process).
    enabled:
        Set False to make ``acquire`` a no-op.
    key_prefix:
        Namespace for the Redis keys (default ``"rl:"``).
    default_interval:
        Interval used for keys not in ``intervals`` (default 0 = no limit).
    """

    def __init__(self, intervals: Optional[Dict[str, float]] = None,
                 redis_url: Optional[str] = None, enabled: bool = True,
                 key_prefix: str = "rl:", default_interval: float = 0.0):
        self.intervals = dict(intervals or {})
        self.redis_url = redis_url
        self.enabled = enabled
        self.key_prefix = key_prefix
        self.default_interval = default_interval
        self._client = None
        self._script = None
        self._init_attempted = False
        self._mem_last: Dict[str, float] = {}
        self._mem_lock = threading.Lock()

    def _get(self):
        if self._client is not None:
            return self._client
        if self._init_attempted or not self.redis_url:
            return None
        self._init_attempted = True
        try:
            import redis
            c = redis.Redis.from_url(self.redis_url, socket_connect_timeout=1.5,
                                     socket_timeout=1.5, decode_responses=True)
            c.ping()
            self._client = c
            self._script = c.register_script(_LUA)
            logger.info("RateLimiter: connected to %s", self.redis_url)
        except Exception as e:
            logger.warning("RateLimiter: redis unavailable (%s); in-memory fallback", e)
            self._client = None
        return self._client

    def interval_for(self, key: str) -> float:
        return self.intervals.get(key, self.default_interval)

    def acquire(self, key: str) -> float:
        """Block until ``key`` is free under its interval. Returns seconds waited."""
        if not self.enabled:
            return 0.0
        interval = self.interval_for(key)
        if interval <= 0:
            return 0.0

        c = self._get()
        if c is not None:
            try:
                now_ms = int(time.time() * 1000)
                wait_ms = int(self._script(keys=[self.key_prefix + key],
                                           args=[now_ms, int(interval * 1000)]))
                if wait_ms > 0:
                    time.sleep(min(wait_ms / 1000.0, interval))
                    return wait_ms / 1000.0
                return 0.0
            except Exception as e:
                logger.debug("RateLimiter redis error (%s); in-memory fallback", e)

        # Per-process in-memory fallback.
        with self._mem_lock:
            now = time.monotonic()
            nxt = self._mem_last.get(key, 0.0) + interval
            wait = max(0.0, nxt - now)
            self._mem_last[key] = max(now, nxt)
        if wait > 0:
            time.sleep(min(wait, interval))
        return wait
