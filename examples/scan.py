"""Minimal example: SSRF-safe fetch with a shared rate limiter and a cache.

    pip install "reconkit[http,redis]"
    python examples/scan.py https://example.com
"""
import sys
from urllib.parse import urlparse

from reconkit.net import validate_url, safe_get, RateLimiter, HttpCache


def main(url: str) -> int:
    ok, why = validate_url(url)
    print(f"validate_url -> ok={ok} reason={why!r}")
    if not ok:
        return 1

    host = urlparse(url).hostname or ""
    # A polite floor of 1 req/s per host (in-memory here; pass redis_url to share
    # it across processes).
    rl = RateLimiter(intervals={host: 1.0})
    rl.acquire(host)

    resp = safe_get(url, timeout=10)
    if resp is None:
        print("fetch blocked or failed (fail-closed)")
        return 1
    print(f"GET {url} -> {resp.status_code}, {len(resp.content)} bytes")

    # Optional: cache an idempotent GET (no-op without Redis).
    cache = HttpCache(redis_url="redis://localhost:6379/0", enabled=False)
    body = cache.get(url, namespace="example", ttl=3600)
    print(f"cache.get -> {'hit/miss body' if body else 'disabled/none'}")
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    raise SystemExit(main(target))
