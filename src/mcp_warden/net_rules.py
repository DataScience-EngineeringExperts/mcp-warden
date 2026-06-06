"""Network + host helpers for http-request policy evaluation.

Holds the SSRF deny-range table (POLICY_MODEL.md §2.3, verbatim) and the
host-extraction / IP-parsing / host-glob helpers. Split from ``policy_eval`` to
keep that module focused and under the LOC budget. **No DNS resolution** happens
here (POLICY_MODEL.md §5).
"""

from __future__ import annotations

import fnmatch
import ipaddress

# SSRF deny ranges (POLICY_MODEL.md §2.3, verbatim).
SSRF_DENY_CIDRS: list[tuple[str, str]] = [
    ("169.254.0.0/16", "link-local"),
    ("127.0.0.0/8", "loopback"),
    ("10.0.0.0/8", "RFC1918 (10)"),
    ("172.16.0.0/12", "RFC1918 (172.16-31)"),
    ("192.168.0.0/16", "RFC1918 (192.168)"),
    ("::1/128", "IPv6 loopback"),
    ("fc00::/7", "IPv6 ULA"),
    ("fe80::/10", "IPv6 link-local"),
]

SSRF_NETWORKS = [(ipaddress.ip_network(c), label) for c, label in SSRF_DENY_CIDRS]


def extract_host(raw: str) -> str:
    """Extract the host from a URL or bare host string (no DNS).

    Args:
        raw: A URL (``https://host:port/path``) or bare ``host``/``host:port``.

    Returns:
        The host label or IP literal (port, scheme, userinfo, path stripped).
    """
    rest = raw.split("://", 1)[1] if "://" in raw else raw
    rest = rest.split("/", 1)[0]
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]
    if rest.startswith("["):  # IPv6 literal in brackets
        end = rest.find("]")
        if end != -1:
            return rest[1:end]
    if rest.count(":") == 1:  # host:port (non-bracketed)
        rest = rest.split(":", 1)[0]
    return rest


def parse_ip(host: str) -> ipaddress._BaseAddress | None:
    """Parse a host as an IP literal, or ``None`` if it is a DNS name.

    Args:
        host: The host string.

    Returns:
        An ``ip_address`` object, or ``None`` for a DNS name.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def host_glob_match(host: str, pattern: str) -> bool:
    """Match a host against an ``*.example.com`` glob or exact host (§2.3).

    Args:
        host: The destination host.
        pattern: An allow-host pattern; ``host:port`` ignores the port.

    Returns:
        True if the host matches the pattern.
    """
    pat = pattern.split(":", 1)[0]
    if pat.startswith("*."):
        suffix = pat[1:]  # ".example.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return fnmatch.fnmatch(host, pat)
