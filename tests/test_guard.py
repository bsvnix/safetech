"""Tests for safefetch.guard — the SSRF guard, incl. redirect re-validation,
allowlist mode, and the on_block hook."""
from unittest.mock import patch, MagicMock

import pytest

from safefetch.guard import (
    Guard, validate_url, safe_get, safe_post, _is_public_ip,
    BLOCKED_TLDS, BLOCKED_HOSTS,
)


def _gai(*ips):
    """Fake socket.getaddrinfo return value for the given IP strings."""
    out = []
    for ip in ips:
        fam = 10 if ":" in ip else 2
        out.append((fam, 1, 6, "", (ip, 0)))
    return out


class TestBlockedTLDs:
    @pytest.mark.parametrize("host", [
        "http://anything.local/x", "http://x.internal/y", "http://a.localhost/",
        "http://h.lan/", "http://h.test/", "http://h.example/", "http://h.invalid/",
    ])
    def test_reserved_tlds_blocked(self, host):
        ok, why = validate_url(host)
        assert ok is False
        assert "blocked TLD" in (why or "")

    def test_tld_list_is_frozen(self):
        assert ".local" in BLOCKED_TLDS and ".internal" in BLOCKED_TLDS


class TestSchemeAndShape:
    @pytest.mark.parametrize("url,reason", [
        ("", "empty url"),
        ("ftp://example.com/", "scheme not allowed"),
        ("file:///etc/passwd", "scheme not allowed"),
        ("gopher://x/", "scheme not allowed"),
        ("data:text/plain,hi", "scheme not allowed"),
        ("http://", "no hostname"),
    ])
    def test_bad_shapes(self, url, reason):
        ok, why = validate_url(url)
        assert ok is False
        assert reason in (why or "")

    def test_non_string_url(self):
        ok, why = validate_url(None)  # type: ignore[arg-type]
        assert ok is False and "empty url" in (why or "")

    def test_localhost_hostname_blocked(self):
        ok, why = validate_url("http://localhost/")
        assert ok is False and "blocked hostname" in (why or "")
        assert "localhost" in BLOCKED_HOSTS


class TestLiteralIPs:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/", "http://127.0.0.2/", "http://10.0.0.5/",
        "http://192.168.1.1/", "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://[::1]/", "http://0.0.0.0/", "http://0.0.0.1/",
        "http://100.64.0.1/",       # CGNAT (RFC 6598)
        "http://100.127.255.1/",    # CGNAT upper
        "http://198.18.0.1/",       # benchmarking
        "http://192.0.2.5/",        # TEST-NET-1
        "http://203.0.113.9/",      # TEST-NET-3
        "http://240.0.0.1/",        # reserved / class E
        "http://[::ffff:127.0.0.1]/",   # IPv4-mapped loopback
        "http://[64:ff9b::7f00:1]/",     # NAT64-embedded 127.0.0.1
    ])
    def test_private_reserved_literals_blocked(self, url):
        ok, why = validate_url(url)
        assert ok is False, f"{url} should be blocked, got {why!r}"

    @pytest.mark.parametrize("url", [
        "http://1.1.1.1/", "http://8.8.8.8/", "http://93.184.216.34/",
        "http://[2606:4700:4700::1111]/",  # public IPv6
    ])
    def test_public_literal_allowed(self, url):
        ok, why = validate_url(url)
        assert ok is True and why is None

    def test_cgnat_helper_is_not_public(self):
        # Regression: ipaddress does not flag 100.64/10 as private.
        assert _is_public_ip("100.64.0.1") is False
        assert _is_public_ip("8.64.0.1") is True


class TestDNSResolution:
    @patch("safefetch.guard.socket.getaddrinfo")
    def test_hostname_resolving_private_blocked(self, gai):
        gai.return_value = _gai("10.1.2.3")
        ok, why = validate_url("http://sneaky.example.com/")
        assert ok is False and "private/reserved" in (why or "")

    @patch("safefetch.guard.socket.getaddrinfo")
    def test_hostname_resolving_public_allowed(self, gai):
        gai.return_value = _gai("93.184.216.34")
        ok, why = validate_url("http://public.example.com/")
        assert ok is True and why is None

    @patch("safefetch.guard.socket.getaddrinfo")
    def test_any_private_answer_rejects_all(self, gai):
        # DNS-rebinding defense: one private answer poisons the whole hostname.
        gai.return_value = _gai("93.184.216.34", "127.0.0.1")
        ok, _ = validate_url("http://rebind.example.com/")
        assert ok is False

    @patch("safefetch.guard.socket.getaddrinfo")
    def test_dns_failure_fails_closed(self, gai):
        import socket as _s
        gai.side_effect = _s.gaierror("no such host")
        ok, why = validate_url("http://nxdomain.example.com/")
        assert ok is False and "dns failure" in (why or "")


class TestEncodedIPForms:
    """Decimal / octal / hex IP literals are not IP-literals to urlparse, so
    they take the DNS path; the OS resolver expands them to 127.0.0.1, which the
    IP check then rejects."""

    @pytest.mark.parametrize("url", [
        "http://2130706433/",     # decimal 127.0.0.1
        "http://0177.0.0.1/",     # octal
        "http://0x7f.0.0.1/",     # hex
    ])
    def test_encoded_loopback_blocked(self, url):
        with patch("safefetch.guard.socket.getaddrinfo",
                   return_value=_gai("127.0.0.1")):
            ok, _ = validate_url(url)
        assert ok is False


class TestSafeGetRedirects:
    @patch("safefetch.guard.socket.getaddrinfo")
    def test_redirect_to_metadata_blocked(self, gai):
        # First host is public; it 302s to the cloud-metadata IP.
        gai.return_value = _gai("93.184.216.34")
        redirect = MagicMock(status_code=302,
                             headers={"Location": "http://169.254.169.254/"})
        with patch("requests.request", return_value=redirect) as req:
            resp = safe_get("http://example.com/redirector")
        assert resp is None  # fail-closed on the private hop
        assert req.called

    @patch("safefetch.guard.socket.getaddrinfo")
    def test_relative_redirect_followed(self, gai):
        gai.return_value = _gai("93.184.216.34")
        hop1 = MagicMock(status_code=302, headers={"Location": "/next"})
        hop2 = MagicMock(status_code=200, headers={})
        with patch("requests.request", side_effect=[hop1, hop2]):
            resp = safe_get("http://example.com/start")
        assert resp is not None and resp.status_code == 200

    @patch("safefetch.guard.socket.getaddrinfo")
    def test_too_many_redirects_blocked(self, gai):
        gai.return_value = _gai("93.184.216.34")
        loop = MagicMock(status_code=302,
                         headers={"Location": "http://example.com/again"})
        with patch("requests.request", return_value=loop):
            resp = safe_get("http://example.com/", max_redirects=3)
        assert resp is None

    @patch("safefetch.guard.socket.getaddrinfo")
    def test_terminal_response_returned(self, gai):
        gai.return_value = _gai("93.184.216.34")
        ok = MagicMock(status_code=200, headers={})
        with patch("requests.request", return_value=ok):
            resp = safe_get("http://example.com/")
        assert resp is not None and resp.status_code == 200

    @patch("safefetch.guard.socket.getaddrinfo")
    def test_allow_redirects_kwarg_is_ignored(self, gai):
        gai.return_value = _gai("93.184.216.34")
        ok = MagicMock(status_code=200, headers={})
        with patch("requests.request", return_value=ok) as req:
            safe_post("http://example.com/", allow_redirects=True, data={"a": 1})
        # Internal call always forces allow_redirects=False.
        assert req.call_args.kwargs["allow_redirects"] is False


class TestOnBlockHook:
    def test_hook_fires_on_block(self):
        seen = []
        g = Guard(on_block=lambda url, why: seen.append((url, why)))
        ok, _ = g.check("http://127.0.0.1/")
        assert ok is False
        assert seen and seen[0][0] == "http://127.0.0.1/"
        assert "private" in seen[0][1]

    def test_hook_not_fired_on_allow(self):
        seen = []
        g = Guard(on_block=lambda url, why: seen.append(url))
        with patch("safefetch.guard.socket.getaddrinfo",
                   return_value=_gai("93.184.216.34")):
            ok, _ = g.check("http://example.com/")
        assert ok is True and seen == []

    def test_broken_hook_does_not_open_guard(self):
        def boom(url, why):
            raise RuntimeError("metrics down")
        g = Guard(on_block=boom)
        ok, _ = g.check("http://127.0.0.1/")  # must not raise
        assert ok is False

    @patch("safefetch.guard.socket.getaddrinfo")
    def test_hook_fires_per_redirect_hop(self, gai):
        gai.return_value = _gai("93.184.216.34")
        seen = []
        redirect = MagicMock(status_code=302,
                             headers={"Location": "http://10.0.0.1/"})
        with patch("requests.request", return_value=redirect):
            safe_get("http://example.com/r", on_block=lambda u, w: seen.append(w))
        assert any("private" in w for w in seen)


class TestAllowlistMode:
    def test_host_allowlist_permits_listed(self):
        g = Guard(allow_hosts=["api.stripe.com"])
        assert g.allowlist_mode is True
        ok, _ = g.check("https://api.stripe.com/v1/charges")
        assert ok is True

    def test_host_allowlist_blocks_unlisted(self):
        g = Guard(allow_hosts=["api.stripe.com"])
        ok, why = g.check("https://evil.example.com/")
        assert ok is False and "not in allowlist" in (why or "")

    def test_wildcard_matches_subdomain_not_apex(self):
        g = Guard(allow_hosts=["*.googleapis.com"])
        assert g.check("https://storage.googleapis.com/x")[0] is True
        assert g.check("https://googleapis.com/x")[0] is False

    def test_cidr_allowlist_permits_internal(self):
        # Allowlisting a private range is the whole point of allowlist mode.
        g = Guard(allow_cidrs=["10.20.0.0/16"])
        with patch("safefetch.guard.socket.getaddrinfo",
                   return_value=_gai("10.20.1.5")):
            ok, _ = g.check("http://internal-api.corp/")
        assert ok is True

    def test_cidr_allowlist_blocks_outside(self):
        g = Guard(allow_cidrs=["10.20.0.0/16"])
        with patch("safefetch.guard.socket.getaddrinfo",
                   return_value=_gai("10.99.0.1")):
            ok, why = g.check("http://other.corp/")
        assert ok is False and "not in allowed CIDRs" in (why or "")

    def test_cidr_allowlist_literal_ip(self):
        g = Guard(allow_cidrs=["10.20.0.0/16"])
        assert g.check("http://10.20.0.7/")[0] is True
        assert g.check("http://10.21.0.7/")[0] is False

    def test_allowlist_blocks_redirect_escape(self):
        g = Guard(allow_hosts=["api.stripe.com"])
        redirect = MagicMock(status_code=302,
                             headers={"Location": "https://evil.example.com/"})
        with patch("requests.request", return_value=redirect):
            resp = g.get("https://api.stripe.com/start")
        assert resp is None

    def test_allowlist_still_blocks_bad_scheme(self):
        g = Guard(allow_hosts=["api.stripe.com"])
        ok, why = g.check("file:///etc/passwd")
        assert ok is False and "scheme" in (why or "")
