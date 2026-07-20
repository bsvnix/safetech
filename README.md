# reconkit

Small, dependency-light building blocks for any Python service that makes
outbound HTTP requests it does **not** fully control — webhooks, link previews,
image/URL proxies, scrapers, oEmbed/RSS/avatar fetchers, and recon tooling.

Zero required dependencies. `requests` and `redis` are optional extras, pulled
in only for the features that use them.

```bash
pip install reconkit            # core
pip install "reconkit[http,redis]"   # + safe_get/safe_post + Redis-backed features
```

## `reconkit.net` — the first module

### 1. SSRF guard that survives redirects

Most SSRF guards validate a URL once, then hand it to `requests`, which happily
follows a `302 Location: http://169.254.169.254/` into cloud metadata. This one
re-validates **every redirect hop** and fails closed.

```python
from reconkit.net import validate_url, safe_get

ok, why = validate_url("http://internal.local/")     # (False, "blocked TLD: .local")
ok, why = validate_url("https://api.github.com/")     # (True, None)

resp = safe_get("https://some-webhook-target.example/callback")
# None if any hop resolves to a private / loopback / link-local / reserved address
```

Blocks: non-http(s) schemes, literal private IPs, reserved TLDs (`.local`,
`.internal`, `.localhost`, `.lan`, `.test`, `.example`, `.invalid`), and any
hostname whose DNS resolution includes a non-public address (DNS-rebinding
defense — if *any* A/AAAA answer is private, the hostname is rejected).

### 2. Cross-process rate limiter

A politeness floor shared across all your workers via Redis, so N processes
honour **one** global budget per key instead of each running at the full rate.
Only same-key calls serialize; independent keys never block each other. Falls
back to a per-process in-memory floor if Redis is down.

```python
from reconkit.net import RateLimiter

rl = RateLimiter(redis_url="redis://localhost:6379/0", intervals={
    "api.example.com": 1.0,      # >= 1s between calls to this host, globally
    "api.slowvendor.io": 15.0,
})
rl.acquire("api.example.com")    # blocks just long enough to stay polite
```

### 3. Fail-open HTTP cache

Redis cache for idempotent outbound GETs. Any Redis error is a cache *miss*,
never an exception — enabling it can only change latency, never behaviour.

```python
from reconkit.net import HttpCache

cache = HttpCache(redis_url="redis://localhost:6379/1")
body = cache.get("https://crt.sh/?q=%.example.com&output=json",
                 namespace="crtsh", ttl=86400)
# {"status": int, "text": str, "json": Any|None, "headers": dict} or None
```

## Design principles

- **Fail closed for security, fail open for caching.** The SSRF guard returns
  `None`/`False` on any doubt; the cache degrades to a live call on any Redis
  hiccup.
- **No global state, no env-var coupling.** You construct `RateLimiter` /
  `HttpCache` with explicit config.
- **Optional dependencies.** Core imports nothing beyond the stdlib.

## License

[Apache-2.0](LICENSE). Contributions under the [DCO](CONTRIBUTING.md) (sign your
commits with `git commit -s`). Security policy: [SECURITY.md](SECURITY.md).
