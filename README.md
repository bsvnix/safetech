# safefetch

**Safe outbound HTTP for Python services: SSRF-proof through redirects, with
allowlist mode and a block hook.**

Any service that fetches a URL it didn't fully choose — a webhook target, a link
preview, an avatar URL, an RSS/oEmbed link, an "import from URL" box — is one
redirect away from hitting `http://169.254.169.254/` or your internal network.
`safefetch` closes that gap and fails closed.

```bash
pip install "safefetch[http]"
```

Zero required dependencies for the guard's URL validation; `requests` is an
optional extra (`[http]`) for the fetch helpers, `redis` (`[redis]`) for the
rate limiter and cache.

## The problem

Most SSRF guards validate the URL **once**, then hand it to `requests`, which
happily follows redirects:

```python
# The common, broken pattern:
if is_public(url):                 # checks example.com -> looks fine
    resp = requests.get(url)       # 302 -> http://169.254.169.254/ -> pwned
```

The check passed for `example.com`. The redirect went somewhere else. `requests`
followed it. The guard never saw the second hop.

## The fix

`safefetch` disables redirect-following and **re-validates every hop**, failing
closed (returning `None`) the moment any hop resolves to a private, loopback,
link-local, CGNAT, or reserved address.

### 1. Drop-in safe GET

```python
from safefetch import safe_get

resp = safe_get("https://some-webhook-target.example/callback")
if resp is None:
    ...  # blocked or network error — never a private-network request
```

`safe_get` / `safe_post` are shaped like `requests.get` / `requests.post` and
take the same kwargs (`timeout`, `headers`, `data`, ...). They return a
`requests.Response`, or `None` on any block or error.

### 2. Allowlist mode — only these, nothing else

For corporate deployments, "block the bad" is often the wrong default; you want
"allow only these vendors and our own internal API." Pass `allow_hosts` and/or
`allow_cidrs` and everything else — including a redirect that tries to leave —
is blocked. `allow_cidrs` may name private ranges; that's the point.

```python
from safefetch import Guard

corp = Guard(
    allow_hosts=["api.stripe.com", "*.googleapis.com"],
    allow_cidrs=["10.20.0.0/16"],     # our internal service mesh
)
resp = corp.get("https://api.stripe.com/v1/charges")   # ok
resp = corp.get("https://anything-else.example/")      # None
```

### 3. A block hook for metrics and logs

Security tooling you can't observe is dead. Every block — including each rejected
redirect hop — calls `on_block(url, reason)`:

```python
from safefetch import Guard

guard = Guard(on_block=lambda url, reason: statsd.incr(
    "ssrf.block", tags=[f"reason:{reason.split(':')[0]}"]))
resp = guard.get(user_supplied_url)
```

`safe_get`/`safe_post` accept `on_block=` too. A hook that raises is swallowed —
an observability bug can never open the guard.

### Pre-flight validation only

Need to check a URL without fetching it (e.g. at form-submit time)?

```python
from safefetch import validate_url

ok, reason = validate_url("http://internal.local/")   # (False, "blocked TLD: .local")
ok, reason = validate_url("https://api.github.com/")   # (True, None)
```

`validate_url` is a **pre-flight check only** — it does not cover redirects. If
you validate and then call bare `requests`, you've reintroduced the redirect
gap. Use `safe_get`/`safe_post` (or `Guard.get`/`.post`) for the real fetch.

## Threat model

**In scope — what the guard stops:**

| Vector | Defense |
| --- | --- |
| Redirect to internal/metadata (`302 → 169.254.169.254`) | Every hop re-validated; fail closed |
| Literal private/loopback/link-local IPs | Rejected before any request |
| CGNAT `100.64.0.0/10`, NAT64, TEST-NET, benchmarking ranges | Explicit block list, version-independent |
| Encoded IP literals (`http://2130706433/`, octal, hex) | Resolved via the OS resolver, then IP-checked |
| IPv4-mapped IPv6 (`::ffff:127.0.0.1`) | Classified private by `ipaddress` |
| DNS rebinding (mixed public/private answers) | If *any* A/AAAA answer is private, the whole host is rejected |
| Reserved TLDs (`.local`, `.internal`, `.localhost`, ...) | Blocked before DNS |
| Non-HTTP schemes (`file:`, `gopher:`, `data:`) | Only `http`/`https` allowed |

**Out of scope — you own these:**

- **TOCTOU between DNS and connect.** The guard resolves, validates, then lets
  `requests` resolve again to connect. A racing rebind between those two
  resolutions is *mitigated* (any private answer rejects the host) but not
  *eliminated*. Pin-and-connect at the socket layer is a caller concern.
- **Response-side risks.** Body size limits, decompression bombs, and content
  sniffing are not handled — cap `stream=`/reads yourself.
- **Egress at the network layer.** This is application-layer defense in depth,
  not a substitute for a locked-down egress firewall or a forward proxy.
- **Non-HTTP protocols and non-`requests` clients** (raw sockets, `urllib`,
  `httpx`) are not wrapped.

See [SECURITY.md](SECURITY.md) to report a bypass.

## Also included

Two companions for services that fetch a lot. Both are optional and independent
of the guard.

**Cross-process rate limiter** — a politeness floor shared across all workers via
Redis, so N processes honour one global budget per key. Falls back to a
per-process in-memory floor if Redis is down.

```python
from safefetch import RateLimiter

rl = RateLimiter(redis_url="redis://localhost:6379/0", intervals={"api.example.com": 1.0})
rl.acquire("api.example.com")   # blocks just long enough to stay polite
```

**Fail-open HTTP cache** — for idempotent outbound GETs. Any Redis error is a
cache *miss*, never an exception, so enabling it can only change latency, never
behaviour.

```python
from safefetch import HttpCache

cache = HttpCache(redis_url="redis://localhost:6379/1")
body = cache.get("https://crt.sh/?q=%.example.com&output=json", namespace="crtsh", ttl=86400)
```

## Design principles

- **Fail closed for security, fail open for caching.** The guard returns
  `None`/`False` on any doubt; the cache degrades to a live call on any Redis
  hiccup.
- **No global state, no env-var coupling.** Construct `Guard` / `RateLimiter` /
  `HttpCache` with explicit config.
- **Optional dependencies.** URL validation is pure stdlib.

## Roadmap

- `httpx` backend (sync + async) for `Guard` — track it in
  [issues](https://github.com/bsvnix/safefetch/issues).

## License

[Apache-2.0](LICENSE). Contributions under the [DCO](CONTRIBUTING.md) (sign your
commits with `git commit -s`). Security policy: [SECURITY.md](SECURITY.md).
Changes: [CHANGELOG.md](CHANGELOG.md).
