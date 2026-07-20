"""Minimal example: SSRF-safe fetch with a block hook, a rate limiter, a cache.

    pip install "safefetch[http]"
    python examples/fetch.py https://example.com
"""
import sys
from urllib.parse import urlparse

from safefetch import Guard, RateLimiter, HttpCache


def main(url: str) -> int:
    # A guard that logs every block (wire this to your metrics in real code).
    guard = Guard(on_block=lambda u, why: print(f"  blocked {u!r}: {why}"))

    ok, why = guard.check(url)
    print(f"check -> ok={ok} reason={why!r}")
    if not ok:
        return 1

    host = urlparse(url).hostname or ""
    # A polite floor of 1 req/s per host (in-memory here; pass redis_url to
    # share it across processes).
    rl = RateLimiter(intervals={host: 1.0})
    rl.acquire(host)

    resp = guard.get(url, timeout=10)
    if resp is None:
        print("fetch blocked or failed (fail-closed)")
        return 1
    print(f"GET {url} -> {resp.status_code}, {len(resp.content)} bytes")

    # Optional: cache an idempotent GET (disabled here, no-op without Redis).
    cache = HttpCache(redis_url="redis://localhost:6379/0", enabled=False)
    body = cache.get(url, namespace="example", ttl=3600)
    print(f"cache.get -> {'hit/miss body' if body else 'disabled/none'}")
    return 0


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    raise SystemExit(main(target))
