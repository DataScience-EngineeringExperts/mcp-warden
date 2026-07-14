"""Tests for res_dns — DNS-resolution SSRF bypass detection (DSE-58)."""

from __future__ import annotations

import socket

from mcp_warden.res_dns import extract_dns_candidates, resolve_ssrf_hits

# ---------------------------------------------------------------------------
# extract_dns_candidates
# ---------------------------------------------------------------------------


def test_extract_candidates_from_https_url():
    hosts = extract_dns_candidates("fetch https://evil.callback.io/data")
    assert "evil.callback.io" in hosts


def test_extract_candidates_from_http_url():
    hosts = extract_dns_candidates("see http://internal.corp.example.com/meta")
    assert "internal.corp.example.com" in hosts


def test_extract_candidates_skips_raw_ipv4_literal():
    # Raw IP literals are already handled by WRD-RES-EXFIL-IP-LITERAL.
    hosts = extract_dns_candidates("https://169.254.169.254/latest/meta-data")
    assert hosts == []


def test_extract_candidates_skips_raw_ipv6_literal():
    hosts = extract_dns_candidates("https://[::1]/admin")
    assert hosts == []


def test_extract_candidates_deduplicates():
    text = "https://foo.example.com/a and https://foo.example.com/b"
    hosts = extract_dns_candidates(text)
    assert hosts.count("foo.example.com") == 1


def test_extract_candidates_multiple_distinct_hosts():
    text = "https://a.example.com/x https://b.example.com/y"
    hosts = extract_dns_candidates(text)
    assert "a.example.com" in hosts and "b.example.com" in hosts


def test_extract_candidates_no_urls_returns_empty():
    assert extract_dns_candidates("no URLs here at all") == []


def test_extract_candidates_returns_sorted():
    text = "https://z.example.com/1 https://a.example.com/2"
    hosts = extract_dns_candidates(text)
    assert hosts == sorted(hosts)


# ---------------------------------------------------------------------------
# resolve_ssrf_hits — mocked socket.getaddrinfo
# ---------------------------------------------------------------------------


def _addrinfo(ip: str, family: int = socket.AF_INET) -> list:
    """Minimal getaddrinfo result for a single IP."""
    return [(family, socket.SOCK_STREAM, 0, "", (ip, 0))]


def test_resolve_detects_link_local_metadata_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p: _addrinfo("169.254.169.254"))
    hits = resolve_ssrf_hits(["bypass.nip.io"])
    assert hits == [("bypass.nip.io", "169.254.169.254", "link-local")]


def test_resolve_detects_loopback(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p: _addrinfo("127.0.0.1"))
    hits = resolve_ssrf_hits(["loopback-bypass.example.com"])
    assert hits and hits[0][2] == "loopback"


def test_resolve_detects_rfc1918_10_block(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p: _addrinfo("10.1.2.3"))
    hits = resolve_ssrf_hits(["internal.corp"])
    assert hits and "RFC1918" in hits[0][2]


def test_resolve_detects_rfc1918_172_block(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p: _addrinfo("172.16.0.1"))
    hits = resolve_ssrf_hits(["vpn-internal.example.com"])
    assert hits and "RFC1918" in hits[0][2]


def test_resolve_detects_rfc1918_192_168(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p: _addrinfo("192.168.1.100"))
    hits = resolve_ssrf_hits(["router.local"])
    assert hits and "RFC1918" in hits[0][2]


def test_resolve_detects_ipv6_loopback(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda h, p: [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("::1", 0, 0, 0))]
    )
    hits = resolve_ssrf_hits(["loopback6.example.com"])
    assert hits and "loopback" in hits[0][2]


def test_resolve_public_ip_produces_no_hits(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p: _addrinfo("8.8.8.8"))
    hits = resolve_ssrf_hits(["public.example.com"])
    assert hits == []


def test_resolve_fail_open_on_nxdomain(monkeypatch):
    def _raise(host, port):
        raise OSError("NXDOMAIN")

    monkeypatch.setattr(socket, "getaddrinfo", _raise)
    hits = resolve_ssrf_hits(["nonexistent.invalid"])
    assert hits == []


def test_resolve_empty_input_returns_empty():
    assert resolve_ssrf_hits([]) == []


def test_resolve_result_is_sorted(monkeypatch):
    # Return same IP for any host so all hits land in the result.
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p: _addrinfo("10.0.0.1"))
    hosts = ["z.example.com", "a.example.com", "m.example.com"]
    hits = resolve_ssrf_hits(hosts)
    assert hits == sorted(hits)


def test_resolve_multiple_hosts_all_private(monkeypatch):
    def _multi(host, port):
        ip = "10.0.0.1" if "a" in host else "127.0.0.1"
        return _addrinfo(ip)

    monkeypatch.setattr(socket, "getaddrinfo", _multi)
    hits = resolve_ssrf_hits(["alpha.example.com", "beta.example.com"])
    assert len(hits) == 2
