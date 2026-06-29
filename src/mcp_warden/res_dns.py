"""DNS-resolution SSRF bypass detection for runtime result inspection.

Resolves extracted hostnames at runtime to catch the class of SSRF bypass
where a non-literal host resolves to a private/loopback/metadata IP — a gap
``WRD-RES-EXFIL-IP-LITERAL`` cannot close (that rule only matches raw IP
literals already present in result text).

Design constraints (POLICY_MODEL.md §5):
- All DNS IO is isolated here; callers that are pure (``inspect_result``)
  receive pre-resolved hits, not raw hostnames to resolve themselves.
- Fail-open: any ``OSError``, timeout, or unexpected error returns no hits for
  the affected host — the guard continues normally.
- Raw IP literals are skipped (already handled by ``WRD-RES-EXFIL-IP-LITERAL``).
- Resolution is bounded by ``timeout`` seconds across ALL hosts combined.
"""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Sequence

from .net_rules import SSRF_NETWORKS, parse_ip
from .res_net import extract_urls


def _resolve_ips(host: str) -> list[str]:
    """Return string-form IPs from ``getaddrinfo`` for ``host``, or ``[]``.

    Any ``OSError`` (NXDOMAIN, refused, unreachable) silently returns empty.

    Args:
        host: A DNS hostname (never a raw IP literal).

    Returns:
        IP address strings for all addresses ``getaddrinfo`` returns.
    """
    try:
        return [info[4][0] for info in socket.getaddrinfo(host, None)]
    except OSError:
        return []


def extract_dns_candidates(text: str) -> list[str]:
    """Return unique non-IP-literal hostnames from ``scheme://`` URLs in ``text``.

    Only scheme-qualified URLs (``https://``, ``http://``, etc.) are
    considered — bare hostname tokens are not resolved (too noisy). Raw IP
    literals are filtered out (already handled by ``WRD-RES-EXFIL-IP-LITERAL``).

    Args:
        text: Raw result text.

    Returns:
        Sorted, de-duplicated list of DNS name candidates.
    """
    seen: set[str] = set()
    for host, _path, _full in extract_urls(text):
        if parse_ip(host) is None and host not in seen:
            seen.add(host)
    return sorted(seen)


def resolve_ssrf_hits(
    hosts: Sequence[str],
    *,
    timeout: float = 1.0,
) -> list[tuple[str, str, str]]:
    """Resolve ``hosts`` and return those whose IPs fall in ``SSRF_NETWORKS``.

    DNS lookups run in a :class:`concurrent.futures.ThreadPoolExecutor` so the
    total wall-clock is bounded by ``timeout`` seconds (``wait`` semantics: any
    host not resolved within the budget is silently skipped — fail-open).

    Args:
        hosts: DNS name candidates (no raw IP literals; use
            :func:`extract_dns_candidates` to derive these from result text).
        timeout: Max seconds to wait for ALL resolutions combined (default 1.0).

    Returns:
        Sorted ``(host, resolved_ip_str, range_label)`` for every host that
        resolved to at least one IP inside a deny range. Empty on timeout or
        error.
    """
    if not hosts:
        return []
    workers = min(len(hosts), 8)
    hits: list[tuple[str, str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
        futs: dict[concurrent.futures.Future[list[str]], str] = {
            exe.submit(_resolve_ips, h): h for h in hosts
        }
        done, _ = concurrent.futures.wait(futs, timeout=timeout)
        for fut in done:
            host = futs[fut]
            try:
                ips = fut.result()
            except Exception:  # pragma: no cover — _resolve_ips already swallows
                continue
            for ip_str in ips:
                ip = parse_ip(ip_str)
                if ip is None:
                    continue
                for net, label in SSRF_NETWORKS:
                    if ip in net:
                        hits.append((host, ip_str, label))
                        break  # first matching range wins per resolved IP
    return sorted(hits)
