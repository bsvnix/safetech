"""safefetch — safe outbound HTTP for Python services.

SSRF-proof through redirects, with allowlist mode and a block hook. Plus two
companions for services that fetch a lot: a cross-process rate limiter and a
fail-open HTTP cache.

    from safefetch import safe_get, validate_url, Guard

    resp = safe_get("https://some-webhook-target.example/callback")
    # None if any redirect hop resolves to a private / reserved address
"""
from .guard import (
    Guard,
    validate_url,
    safe_get,
    safe_post,
    BLOCKED_TLDS,
    BLOCKED_HOSTS,
    ALLOWED_INTERNAL_HOSTS,
    DEFAULT_MAX_REDIRECTS,
)
from .ratelimit import RateLimiter
from .cache import HttpCache

__all__ = [
    "Guard",
    "validate_url",
    "safe_get",
    "safe_post",
    "BLOCKED_TLDS",
    "BLOCKED_HOSTS",
    "ALLOWED_INTERNAL_HOSTS",
    "DEFAULT_MAX_REDIRECTS",
    "RateLimiter",
    "HttpCache",
]

__version__ = "0.2.0"
