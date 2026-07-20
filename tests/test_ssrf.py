"""Tests for reconkit.net.ssrf — the SSRF guard, incl. redirect re-validation."""
from unittest.mock import patch, MagicMock

import pytest

from reconkit.net.ssrf import validate_url, safe_get, BLOCKED_TLDS


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
        ("http://", "no hostname"),
    ])
    def test_bad_shapes(self, url, reason):
        ok, why = validate_url(url)
        assert ok is False
        assert reason in (why or "")


class TestLiteralIPs:
    @pytest.mark.parametrize("url", [
        "http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://[::1]/", "http://0.0.0.0/",
    ])
    def test_private_reserved_literals_blocked(self, url):
        ok, _ = validate_url(url)
        assert ok is False

    def test_public_literal_allowed(self):
        ok, why = validate_url("http://1.1.1.1/")
        assert ok is True and why is None


class TestDNSResolution:
    @patch("reconkit.net.ssrf.socket.getaddrinfo")
    def test_hostname_resolving_private_blocked(self, gai):
        gai.return_value = [(2, 1, 6, "", ("10.1.2.3", 0))]
        ok, why = validate_url("http://sneaky.example.com/")
        assert ok is False and "private/reserved" in (why or "")

    @patch("reconkit.net.ssrf.socket.getaddrinfo")
    def test_hostname_resolving_public_allowed(self, gai):
        gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        ok, why = validate_url("http://example.com/")
        assert ok is True and why is None

    @patch("reconkit.net.ssrf.socket.getaddrinfo")
    def test_any_private_answer_rejects_all(self, gai):
        # DNS-rebinding defense: one private answer poisons the whole hostname.
        gai.return_value = [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]
        ok, _ = validate_url("http://rebind.example.com/")
        assert ok is False


class TestSafeGetRedirects:
    @patch("reconkit.net.ssrf.socket.getaddrinfo")
    def test_redirect_to_metadata_blocked(self, gai):
        # First host is public; it 302s to the cloud-metadata IP.
        gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        redirect = MagicMock(status_code=302,
                             headers={"Location": "http://169.254.169.254/"})
        with patch("requests.request", return_value=redirect) as req:
            resp = safe_get("http://example.com/redirector")
        assert resp is None  # fail-closed on the private hop
        assert req.called

    @patch("reconkit.net.ssrf.socket.getaddrinfo")
    def test_terminal_response_returned(self, gai):
        gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        ok = MagicMock(status_code=200, headers={})
        with patch("requests.request", return_value=ok):
            resp = safe_get("http://example.com/")
        assert resp is not None and resp.status_code == 200
