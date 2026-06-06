"""Exfil-domain + URL primitives for result inspection (RESULT_INSPECTION.md §3.3, §5.1).

Exact, host-anchored, case-insensitive matching — NEVER a heuristic "looks like a
URL" and never regex over the denylist. Holds the seed exfil denylist (bare-host
and path-qualified) and the deterministic URL/host extractors used by
``WRD-RES-EXFIL-DOMAIN`` and the ``WRD-RES-URL`` note.
"""

from __future__ import annotations

import re

#: Seed exfil denylist (RESULT_INSPECTION.md §3.3). Org-extensible at runtime.
SEED_EXFIL_DENYLIST: tuple[str, ...] = (
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "pastebin.com",
    "paste.ee",
    "dpaste.com",
    "hastebin.com",
    "ghostbin.com",
    "transfer.sh",
    "file.io",
    "0x0.st",
    "temp.sh",
    "oshi.at",
    "requestbin.com",
    "requestbin.net",
    "pipedream.net",
    "webhook.site",
    "beeceptor.com",
    "hookbin.com",
    "burpcollaborator.net",
    "oast.fun",
    "oast.live",
    "oast.pro",
    "oast.site",
    "interact.sh",
    "canarytokens.com",
    "serveo.net",
    "localhost.run",
    "localtunnel.me",
    "loca.lt",
)

#: Path-qualified denylist entries (host + path-prefix). Bare-host match does
#: NOT apply to these (so normal discord.com links are not flagged).
SEED_EXFIL_PATH_QUALIFIED: tuple[tuple[str, str], ...] = (
    ("discord.com", "/api/webhooks"),
    ("discordapp.com", "/api/webhooks"),
)

#: A scheme://authority[/path] match. Authority stops at '/', '?', '#', whitespace.
_URL_RE = re.compile(
    r"(?P<scheme>https?|ftp|wss?)://(?P<authority>[^/?#\s]+)(?P<path>[^\s\"'<>]*)",
    re.IGNORECASE,
)

#: A bare dotted host-like token (no scheme/path) for exact denylist token match.
_BARE_HOST_RE = re.compile(r"(?<![A-Za-z0-9._/-])([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def _host_from_authority(authority: str) -> str:
    """Strip userinfo + port from a ``host[:port]`` (or ``user@host:port``)."""
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):  # IPv6 literal
        end = authority.find("]")
        if end != -1:
            return authority[1:end].lower()
    if authority.count(":") == 1:
        authority = authority.split(":", 1)[0]
    return authority.lower()


def host_matches_domain(host: str, domain: str) -> bool:
    """Host-anchored, case-insensitive eTLD+1/subdomain match (§3.3).

    ``host`` matches ``domain`` if it equals ``domain`` or ends with
    ``"." + domain``. e.g. ``abc.ngrok.io`` matches ``ngrok.io`` but
    ``myngrok.io`` does NOT (no leading-dot boundary).

    Args:
        host: The candidate host.
        domain: A denylist domain literal.

    Returns:
        True on an exact or subdomain match.
    """
    h = host.lower().rstrip(".")
    d = domain.lower().rstrip(".")
    return h == d or h.endswith("." + d)


def extract_urls(text: str) -> list[tuple[str, str, str]]:
    """Extract ``scheme://`` URLs deterministically.

    Args:
        text: The inspected result text.

    Returns:
        ``(host, path, full_match)`` per ``scheme://`` authority found.
    """
    out: list[tuple[str, str, str]] = []
    for m in _URL_RE.finditer(text):
        host = _host_from_authority(m.group("authority"))
        path = m.group("path") or ""
        out.append((host, path, m.group(0)))
    return out


def _bare_host_tokens(text: str) -> list[str]:
    """Extract bare dotted host-like tokens (for exact denylist token match)."""
    return [m.group(1).lower() for m in _BARE_HOST_RE.finditer(text)]


def match_exfil(
    text: str,
    denylist: tuple[str, ...] | list[str],
    path_qualified: tuple[tuple[str, str], ...] | list[tuple[str, str]],
) -> list[str]:
    """Return the denylist domains the result text hits (§3.3).

    Matches ``scheme://`` URL hosts (exact/subdomain), path-qualified entries
    (host + path-prefix), and bare host tokens that exactly equal or are a
    subdomain of a bare-host denylist entry.

    Args:
        text: The inspected result text.
        denylist: Bare-host denylist domains (seed + org).
        path_qualified: ``(host, path_prefix)`` entries.

    Returns:
        A sorted, de-duplicated list of matched identifiers (bare domain, or
        ``"host+path"`` for a path-qualified hit).
    """
    hits: set[str] = set()
    for host, path, _full in extract_urls(text):
        for domain in denylist:
            if host_matches_domain(host, domain):
                hits.add(domain)
        for q_host, q_path in path_qualified:
            if host_matches_domain(host, q_host) and path.startswith(q_path):
                hits.add(f"{q_host}{q_path}")
    for token in _bare_host_tokens(text):
        for domain in denylist:
            if host_matches_domain(token, domain):
                hits.add(domain)
    return sorted(hits)
