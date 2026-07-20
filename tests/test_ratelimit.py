"""Tests for reconkit.net.ratelimit — in-memory fallback behaviour (no Redis)."""
import time

from reconkit.net.ratelimit import RateLimiter


def test_same_key_serializes():
    rl = RateLimiter(intervals={"h": 0.3})  # no redis_url -> in-memory
    t0 = time.monotonic()
    assert rl.acquire("h") == 0.0            # first call is free
    w = rl.acquire("h")                       # second waits ~interval
    assert w > 0
    assert time.monotonic() - t0 >= 0.25


def test_independent_keys_do_not_block():
    rl = RateLimiter(intervals={"a": 0.5, "b": 0.5})
    rl.acquire("a")
    t0 = time.monotonic()
    rl.acquire("b")                           # different key -> no wait
    assert time.monotonic() - t0 < 0.1


def test_unlisted_key_no_limit():
    rl = RateLimiter(intervals={"a": 1.0})
    assert rl.acquire("not-listed") == 0.0
    assert rl.acquire("not-listed") == 0.0


def test_disabled_is_noop():
    rl = RateLimiter(intervals={"a": 5.0}, enabled=False)
    t0 = time.monotonic()
    rl.acquire("a"); rl.acquire("a")
    assert time.monotonic() - t0 < 0.1


def test_default_interval_applies():
    rl = RateLimiter(default_interval=0.3)
    assert rl.acquire("x") == 0.0
    assert rl.acquire("x") > 0
