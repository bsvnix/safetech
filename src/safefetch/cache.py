"""Fail-open Redis cache for outbound HTTP GETs.

Drop it in front of repeat requests (CT logs, WHOIS/RDAP, archive queries, any
idempotent third-party GET) to soak duplicate calls across runs and processes.

Design contract: **any** Redis error is a cache MISS, never an exception — with
Redis down the wrapped call simply executes live, so enabling the cache can
never change behaviour, only latency.

    from safefetch import HttpCache

    cache = HttpCache(redis_url="redis://localhost:6379/1")
    body = cache.get("https://crt.sh/?q=%.example.com&output=json",
                     namespace="crtsh", ttl=86400)
    # body -> {"status": int, "text": str, "json": Any|None, "headers": dict} or None
"""

from __future__ import annotations
import functools
import hashlib
import json
import logging
from typing import Any, Callable, Iterable, Optional

logger = logging.getLogger(__name__)


class HttpCache:
    def __init__(self, redis_url: str = "redis://localhost:6379/0",
                 enabled: bool = True, key_prefix: str = "safefetch:cache:",
                 default_ttl: int = 7200, max_body_bytes: int = 1_000_000):
        self.redis_url = redis_url
        self.enabled = enabled
        self.key_prefix = key_prefix
        self.default_ttl = default_ttl
        self.max_body_bytes = max_body_bytes
        self._client = None
        self._init_attempted = False

    def _get_client(self):
        if not self.enabled:
            return None
        if self._client is not None:
            return self._client
        if self._init_attempted:
            return None
        self._init_attempted = True
        try:
            import redis
            c = redis.Redis.from_url(self.redis_url, socket_connect_timeout=1.5,
                                     socket_timeout=1.5, decode_responses=False)
            c.ping()
            self._client = c
            logger.info("HttpCache: connected to %s", self.redis_url)
        except Exception as e:
            logger.warning("HttpCache: redis unavailable (%s); cache disabled", e)
            self._client = None
        return self._client

    def _make_key(self, namespace: str, args: tuple, kwargs: dict,
                  key_args: Optional[Iterable[str]] = None) -> str:
        if key_args:
            payload = {k: kwargs.get(k) for k in key_args}
        else:
            payload = {"a": args, "k": {k: v for k, v in kwargs.items() if k != "headers"}}
        blob = json.dumps(payload, default=str, sort_keys=True).encode("utf-8")
        h = hashlib.sha256(blob).hexdigest()[:24]
        return f"{self.key_prefix}{namespace}:{h}"

    def get(self, url: str, namespace: str, ttl: Optional[int] = None,
            **req_kwargs) -> Optional[dict]:
        """Cached ``requests.get`` → body dict, or None on network error.

        Returns ``{"status", "text", "json", "headers"}``. Only 2xx responses are
        cached. Cache key = URL + a stable repr of request kwargs (excluding
        headers). ``ttl`` defaults to ``default_ttl``.
        """
        import requests
        ttl = self.default_ttl if ttl is None else ttl
        client = self._get_client()
        cacheable = {k: v for k, v in req_kwargs.items() if k != "headers"}
        key = self._make_key(namespace, (url,), cacheable)
        if client is not None and ttl > 0:
            try:
                hit = client.get(key)
                if hit is not None:
                    return json.loads(hit)
            except Exception:
                pass
        try:
            r = requests.get(url, **req_kwargs)
        except Exception:
            return None
        body = {
            "status": r.status_code,
            "text": r.text[: self.max_body_bytes],
            "headers": {k.lower(): v for k, v in r.headers.items() if k.lower() in (
                "content-type", "etag", "last-modified", "x-ratelimit-remaining"
            )},
        }
        try:
            body["json"] = r.json()
        except Exception:
            body["json"] = None
        if 200 <= r.status_code < 300 and client is not None and ttl > 0:
            try:
                client.setex(key, ttl, json.dumps(body, default=str))
            except Exception:
                pass
        return body

    def memoize(self, namespace: str, key_args: Optional[Iterable[str]] = None,
                ttl: Optional[int] = None) -> Callable:
        """Decorator caching a function's JSON-serialisable return value.
        Unserialisable returns are silently bypassed (function still runs)."""
        eff_ttl = self.default_ttl if ttl is None else ttl

        def deco(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                client = self._get_client()
                if client is None or eff_ttl <= 0:
                    return fn(*args, **kwargs)
                key = self._make_key(namespace, args, kwargs, key_args)
                try:
                    hit = client.get(key)
                    if hit is not None:
                        return json.loads(hit)
                except Exception:
                    pass
                value = fn(*args, **kwargs)
                try:
                    client.setex(key, eff_ttl, json.dumps(value, default=str))
                except (TypeError, ValueError):
                    pass
                except Exception:
                    pass
                return value
            return wrapper
        return deco
