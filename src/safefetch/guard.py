"""SSRF guard — resolve a hostname, reject private / reserved ranges, and follow
redirects safely by re-validating every hop.

Most SSRF guards published for Python validate a URL once and then let
``requests`` follow redirects — so a pre-approved public host that answers with
``302 Location: http://169.254.169.254/`` (or ``http://127.0.0.1/``, or a
private LAN address) walks the fetcher straight into the thing the guard was
supposed to stop. ``safe_get`` / ``safe_post`` disable redirect-following and
re-validate each ``Location`` target, failing closed (returning ``None``) on the
first hop that resolves to a non-public address.

Two policies:

* **Blocklist mode (default).** Allow any public host; reject private, loopback,
  link-local, CGNAT, reserved and other non-globally-routable targets, plus
  reserved TLDs. This is what you want for user-supplied URLs.
* **Allowlist mode.** Pass ``allow_hosts`` and/or ``allow_cidrs`` to permit
  *only* those. Anything else is blocked, including via a redirect. This is
  usually what a corporate deployment wants — "these three vendors and our
  internal ``10.20.0.0/16`` API, nothing else."

Every block is reported to an optional ``on_block(url, reason)`` hook so you can
wire it to metrics or logs.

    from safefetch import safe_get, validate_url, Guard

    resp = safe_get("https://some-webhook-target.example/callback")

    corp = Guard(allow_hosts=["api.stripe.com", "*.googleapis.com"],
                 allow_cidrs=["10.20.0.0/16"],
                 on_block=lambda url, why: metrics.incr("ssrf.block"))
    resp = corp.get("https://api.stripe.com/v1/charges")
"""

from __future__ import annotations
import ipaddress
import logging
import socket
from urllib.parse import urlparse, urljoin
from typing import Any, Callable, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

OnBlock = Callable[[str, str], None]

# Hostnames that are always rejected in blocklist mode. Keep this to loopback
# aliases; anything that resolves is handled by the IP checks below.
BLOCKED_HOSTS = frozenset({
    "localhost",
})

# Reserved / non-routable TLDs (RFC 2606, 6761, 6762). Blocked BEFORE DNS so a
# split-horizon resolver or a misconfigured local resolver can never turn these
# into "public" addresses. ``foo.localhost`` is caught here; bare ``localhost``
# is caught by BLOCKED_HOSTS.
BLOCKED_TLDS = frozenset({
    ".local",      # mDNS / Bonjour (RFC 6762)
    ".internal",   # de-facto internal use (host.docker.internal, *.svc.cluster.internal)
    ".localhost",  # loopback (RFC 6761)
    ".lan",        # de-facto home network
    ".test",       # reserved (RFC 2606)
    ".example",    # reserved (RFC 2606)
    ".invalid",    # reserved (RFC 2606)
})

# Ranges that ``ipaddress`` does not consistently flag as private/reserved
# across CPython versions, but which are not globally routable and are classic
# SSRF pivots. We reject them explicitly so the guard behaves the same on every
# supported Python.
_EXTRA_BLOCKED_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",        # "this network" (RFC 1122)
    "100.64.0.0/10",    # CGNAT / shared address space (RFC 6598)
    "192.0.0.0/24",     # IETF protocol assignments (RFC 6890)
    "198.18.0.0/15",    # benchmarking (RFC 2544)
    "192.0.2.0/24",     # TEST-NET-1 (RFC 5737)
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",   # TEST-NET-3
    "64:ff9b::/96",     # NAT64 (RFC 6052) — can embed a private IPv4
    "64:ff9b:1::/48",   # local-use NAT64 (RFC 8215)
))

# Back-compat alias (pre-0.2 name).
ALLOWED_INTERNAL_HOSTS = BLOCKED_HOSTS

DEFAULT_MAX_REDIRECTS = 5


def _is_public_ip(ip: str) -> bool:
    """True only for a genuinely globally-routable address.

    Fails closed: anything we cannot classify, or that lands in a private /
    reserved / CGNAT / NAT64 range, is treated as non-public.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (
        addr.is_private          # 10/8, 172.16/12, 192.168/16, fc00::/7, ::ffff:*
        or addr.is_loopback      # 127/8, ::1
        or addr.is_link_local    # 169.254/16, fe80::/10 (cloud metadata etc.)
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return False
    for net in _EXTRA_BLOCKED_NETS:
        if addr.version == net.version and addr in net:
            return False
    return True


def _norm_host(host: Optional[str]) -> str:
    return (host or "").strip().lower().rstrip(".")


def _host_matches(host: str, patterns: Sequence[str]) -> bool:
    """Match ``host`` against allowlist entries.

    ``"api.example.com"`` matches only that host; ``"*.example.com"`` matches any
    subdomain (but not the apex).
    """
    for p in patterns:
        p = _norm_host(p)
        if p.startswith("*."):
            if host.endswith(p[1:]):   # ".example.com"
                return True
        elif host == p:
            return True
    return False


class Guard:
    """A reusable SSRF policy.

    Parameters
    ----------
    allow_hosts / allow_cidrs:
        If either is non-empty the guard runs in **allowlist mode**: a target is
        permitted only if its hostname matches ``allow_hosts`` or every resolved
        address falls inside ``allow_cidrs``. Everything else — including a
        redirect that leaves the allowlist — is blocked. ``allow_cidrs`` may name
        private ranges (that is the point of an allowlist).
    on_block:
        Called ``on_block(url, reason)`` for every blocked target, including each
        rejected redirect hop. Exceptions from the hook are swallowed so an
        observability bug can never open the guard.
    max_redirects:
        Redirect hops to follow (each re-validated). Default 5.
    timeout:
        Default per-request timeout in seconds.
    """

    def __init__(
        self,
        *,
        allow_hosts: Optional[Iterable[str]] = None,
        allow_cidrs: Optional[Iterable[str]] = None,
        blocked_tlds: Iterable[str] = BLOCKED_TLDS,
        blocked_hosts: Iterable[str] = BLOCKED_HOSTS,
        on_block: Optional[OnBlock] = None,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        timeout: float = 10,
    ) -> None:
        self.allow_hosts: List[str] = [_norm_host(h) for h in (allow_hosts or [])]
        self.allow_nets = tuple(
            ipaddress.ip_network(c, strict=False) for c in (allow_cidrs or [])
        )
        self.allowlist_mode = bool(self.allow_hosts or self.allow_nets)
        self.blocked_tlds = frozenset(blocked_tlds)
        self.blocked_hosts = frozenset(_norm_host(h) for h in blocked_hosts)
        self.on_block = on_block
        self.max_redirects = max_redirects
        self.timeout = timeout

    # -- validation --------------------------------------------------------

    def _report(self, url: str, reason: str) -> None:
        if self.on_block is None:
            return
        try:
            self.on_block(url, reason)
        except Exception:
            logger.exception("safefetch on_block hook raised; ignoring")

    def _resolve(self, host: str) -> Tuple[Optional[List[str]], Optional[str]]:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as e:
            return None, f"dns failure: {e}"
        return [sa[0] for *_x, sa in infos], None

    def _check_allowlist(self, host: str) -> Tuple[bool, Optional[str]]:
        if self.allow_hosts and _host_matches(host, self.allow_hosts):
            return True, None
        if not self.allow_nets:
            return False, "host not in allowlist"
        # Every resolved address must fall inside an allowed CIDR.
        try:
            ips: List[str] = [str(ipaddress.ip_address(host))]
        except ValueError:
            resolved, why = self._resolve(host)
            if resolved is None:
                return False, why
            ips = resolved
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if not any(addr.version == n.version and addr in n
                       for n in self.allow_nets):
                return False, f"{ip} not in allowed CIDRs"
        return True, None

    def _check_blocklist(self, host: str) -> Tuple[bool, Optional[str]]:
        if host in self.blocked_hosts:
            return False, "blocked hostname"
        for tld in self.blocked_tlds:
            if host.endswith(tld):
                return False, f"blocked TLD: {tld}"
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            public = _is_public_ip(host)
            return public, None if public else f"literal private/reserved IP: {host}"
        ips, why = self._resolve(host)
        if ips is None:
            return False, why
        for ip in ips:
            if not _is_public_ip(ip):
                return False, f"resolves to private/reserved: {ip}"
        return True, None

    def check(self, url: str) -> Tuple[bool, Optional[str]]:
        """Return ``(ok, reason_if_blocked)`` and fire ``on_block`` when blocked."""
        if not url or not isinstance(url, str):
            self._report(str(url), "empty url")
            return False, "empty url"
        try:
            parsed = urlparse(url)
        except Exception as e:
            self._report(url, f"parse error: {e}")
            return False, f"parse error: {e}"
        if parsed.scheme not in ("http", "https"):
            reason = f"scheme not allowed: {parsed.scheme}"
            self._report(url, reason)
            return False, reason
        host = _norm_host(parsed.hostname)
        if not host:
            self._report(url, "no hostname")
            return False, "no hostname"

        if self.allowlist_mode:
            ok, reason = self._check_allowlist(host)
        else:
            ok, reason = self._check_blocklist(host)
        if not ok:
            self._report(url, reason or "blocked")
        return ok, reason

    # -- fetching ----------------------------------------------------------

    def request(self, method: str, url: str, *,
                timeout: Optional[float] = None,
                max_redirects: Optional[int] = None, **kwargs: Any):
        """Walk redirects, re-validating each hop. Returns a ``requests.Response``
        or ``None`` (fail-closed). ``allow_redirects`` is managed internally and
        ignored if passed."""
        try:
            import requests
        except ImportError:
            logger.error("safefetch: the 'requests' package is not installed "
                         "(pip install 'safefetch[http]')")
            return None

        kwargs.pop("allow_redirects", None)
        timeout = self.timeout if timeout is None else timeout
        max_redirects = self.max_redirects if max_redirects is None else max_redirects

        current = url
        for hop in range(max_redirects + 1):
            ok, why = self.check(current)
            if not ok:
                logger.info("SSRF block (hop %d) %s: %s", hop, current[:120], why)
                return None
            try:
                resp = requests.request(method, current, timeout=timeout,
                                        allow_redirects=False, **kwargs)
            except Exception as e:
                logger.debug("safefetch %s %s: %s", method, current[:120], e)
                return None
            if 300 <= resp.status_code < 400 and "Location" in resp.headers:
                if hop >= max_redirects:
                    self._report(url, "too many redirects")
                    logger.info("safefetch: too many redirects from %s", url[:120])
                    return None
                current = urljoin(current, resp.headers["Location"])
                continue
            return resp
        return None

    def get(self, url: str, **kwargs: Any):
        """SSRF-safe drop-in for ``requests.get``. Returns Response or None."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any):
        """SSRF-safe drop-in for ``requests.post``. Returns Response or None."""
        return self.request("POST", url, **kwargs)


# ---------------------------------------------------------------------------
# Module-level convenience API backed by a default (blocklist-mode) Guard.
# ---------------------------------------------------------------------------

_DEFAULT = Guard()


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Return ``(ok, reason_if_blocked)`` using the default blocklist policy.

    Blocks non-http(s) schemes, private/loopback/link-local/CGNAT/reserved
    hostnames, reserved TLDs, literal private IPs, and any hostname whose DNS
    resolution includes a non-public address (a DNS-rebinding defense: if *any*
    A/AAAA answer is private, the whole hostname is rejected).

    ``validate_url`` is a pre-flight check only. The authoritative defense is
    ``safe_get``/``safe_post``, which re-validate every redirect hop.
    """
    return _DEFAULT.check(url)


def safe_get(url: str, *, timeout: float = 10,
             max_redirects: int = DEFAULT_MAX_REDIRECTS,
             on_block: Optional[OnBlock] = None, **kwargs: Any):
    """SSRF-safe drop-in for ``requests.get``. Returns Response or None."""
    guard = _DEFAULT if on_block is None else Guard(on_block=on_block)
    return guard.request("GET", url, timeout=timeout,
                         max_redirects=max_redirects, **kwargs)


def safe_post(url: str, *, timeout: float = 10,
              max_redirects: int = DEFAULT_MAX_REDIRECTS,
              on_block: Optional[OnBlock] = None, **kwargs: Any):
    """SSRF-safe drop-in for ``requests.post``. Returns Response or None."""
    guard = _DEFAULT if on_block is None else Guard(on_block=on_block)
    return guard.request("POST", url, timeout=timeout,
                         max_redirects=max_redirects, **kwargs)
