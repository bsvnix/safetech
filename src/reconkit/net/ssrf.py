"""SSRF guard — resolve a hostname and reject private / reserved ranges, and
follow redirects safely by re-validating every hop.

Most SSRF guards published for Python validate a URL once and then let
``requests`` follow redirects — so a pre-approved public host that answers with
``302 Location: http://169.254.169.254/`` (or ``http://127.0.0.1/``, or a
private LAN address) walks the fetcher straight into the thing the guard was
supposed to stop. ``safe_get`` / ``safe_post`` disable redirect-following and
re-validate each ``Location`` target, failing closed (returning ``None``) on the
first hop that resolves to a non-public address.

Use it anywhere you fetch a URL you did not fully control: webhooks, link
previews, image/URL proxies, scrapers, oEmbed, RSS, avatar fetchers.
"""

from __future__ import annotations
import ipaddress
import logging
import socket
from urllib.parse import urlparse, urljoin
from typing import Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Hostnames the caller's own app may legitimately reach. Keep this empty for
# anything that parses user-supplied data. Callers can extend it if they know
# what they are doing.
ALLOWED_INTERNAL_HOSTS = frozenset({
    "localhost",
})

# Reserved / non-routable TLDs (RFC 2606, 6761, 6762). Blocked BEFORE DNS so a
# split-horizon resolver or a misconfigured local resolver can never turn these
# into "public" addresses. ``foo.localhost`` is caught here; bare ``localhost``
# is caught by ALLOWED_INTERNAL_HOSTS.
BLOCKED_TLDS = frozenset({
    ".local",      # mDNS / Bonjour (RFC 6762)
    ".internal",   # de-facto internal use (host.docker.internal, *.svc.cluster.internal)
    ".localhost",  # loopback (RFC 6761)
    ".lan",        # de-facto home network
    ".test",       # reserved (RFC 2606)
    ".example",    # reserved (RFC 2606)
    ".invalid",    # reserved (RFC 2606)
})


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Reject everything that is not globally routable.
    return not (
        addr.is_private         # 10/8, 172.16/12, 192.168/16, fc00::/7
        or addr.is_loopback     # 127/8, ::1
        or addr.is_link_local   # 169.254/16, fe80::/10 (cloud metadata etc.)
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """Return ``(ok, reason_if_blocked)``.

    Blocks non-http(s) schemes, private/loopback/link-local hostnames, reserved
    TLDs, literal private IPs, and any hostname whose DNS resolution includes a
    non-public address (a DNS-rebinding defense: if *any* A/AAAA answer is
    private, the whole hostname is rejected).
    """
    if not url or not isinstance(url, str):
        return False, "empty url"
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"parse error: {e}"
    if parsed.scheme not in ("http", "https"):
        return False, f"scheme not allowed: {parsed.scheme}"
    host = parsed.hostname
    if not host:
        return False, "no hostname"
    host = host.strip().lower().rstrip(".")
    if host in ALLOWED_INTERNAL_HOSTS:
        return False, "internal hostname blocked"
    for tld in BLOCKED_TLDS:
        if host.endswith(tld):
            return False, f"blocked TLD: {tld}"
    # Literal IP in the URL?
    try:
        ipaddress.ip_address(host)
        public = _is_public_ip(host)
        return (public, None if public else f"literal private/reserved IP: {host}")
    except ValueError:
        pass
    # Resolve and check every A / AAAA record.
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, f"dns failure: {e}"
    for _fam, _s, _p, _c, sa in infos:
        ip = sa[0]
        if not _is_public_ip(ip):
            return False, f"resolves to private/reserved: {ip}"
    return True, None


# ---------------------------------------------------------------------------
# safe_get / safe_post — drop-in wrappers that re-validate every redirect hop.
# ---------------------------------------------------------------------------

DEFAULT_MAX_REDIRECTS = 5


def _safe_request(method: str, url: str, *, timeout: float = 10,
                  max_redirects: int = DEFAULT_MAX_REDIRECTS,
                  **kwargs: Any):
    """Walk redirects, re-validating each hop. Returns a ``requests.Response``
    or ``None`` (fail-closed). ``allow_redirects`` is managed internally and
    ignored if passed."""
    try:
        import requests
    except ImportError:
        logger.error("safe_request: the 'requests' package is not installed")
        return None

    kwargs.pop("allow_redirects", None)

    current = url
    for hop in range(max_redirects + 1):
        ok, why = validate_url(current)
        if not ok:
            logger.info("SSRF block (hop %d) %s: %s", hop, current[:120], why)
            return None
        try:
            resp = requests.request(method, current, timeout=timeout,
                                    allow_redirects=False, **kwargs)
        except Exception as e:
            logger.debug("safe_request %s %s: %s", method, current[:120], e)
            return None
        if 300 <= resp.status_code < 400 and "Location" in resp.headers:
            if hop >= max_redirects:
                logger.info("safe_request: too many redirects from %s", url[:120])
                return None
            current = urljoin(current, resp.headers["Location"])
            continue
        return resp
    logger.info("safe_request: redirect loop exhausted from %s", url[:120])
    return None


def safe_get(url: str, *, timeout: float = 10,
             max_redirects: int = DEFAULT_MAX_REDIRECTS, **kwargs: Any):
    """SSRF-safe drop-in for ``requests.get``. Returns Response or None."""
    return _safe_request("GET", url, timeout=timeout,
                         max_redirects=max_redirects, **kwargs)


def safe_post(url: str, *, timeout: float = 10,
              max_redirects: int = DEFAULT_MAX_REDIRECTS, **kwargs: Any):
    """SSRF-safe drop-in for ``requests.post``. Returns Response or None."""
    return _safe_request("POST", url, timeout=timeout,
                         max_redirects=max_redirects, **kwargs)
