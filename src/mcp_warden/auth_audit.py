"""Static MCP auth-posture audit (WRD-AUTH-*) — DSE-1258.

Audits MCP client/server configuration files for weak authentication posture
without running anything: no server spawn, no DNS, no network. It parses the
declarative config (Claude Desktop ``claude_desktop_config.json``, ``.mcp.json``,
``mcp.json`` — all sharing the ``{"mcpServers": {...}}`` shape) and flags
remote servers reachable without auth, credential literals committed into
config, cleartext transport, and inline secrets that should reference a
manager instead.

Deliberately static and conservative: it reasons only about what the config
declares. Runtime capability brokering is a separate concern (DSE-725); this
module stays in warden's fail-closed static lane so it is immune to the churn
in the MCP auth spec.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .checks_secret import scan_field
from .models import Finding

#: Header keys whose values carry auth material worth scanning for literals.
_AUTH_HEADER_KEYS = {"authorization", "x-api-key", "api-key", "apikey", "token"}

#: Substrings that mark ANY config key (env or header) as auth-bearing.
_AUTH_KEY_SUBSTRINGS = ("token", "api_key", "apikey", "secret", "auth", "password", "passwd")


def _is_auth_key(key: str) -> bool:
    """Whether a config key name signals it holds authentication material."""
    k = key.lower()
    return k in _AUTH_HEADER_KEYS or any(s in k for s in _AUTH_KEY_SUBSTRINGS)

#: Hosts that are not remotely reachable, so a missing auth header is not an
#: exposure on its own.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _is_local_host(host: str) -> bool:
    return host.split(":", 1)[0].lower() in _LOCAL_HOSTS


def _host_of(url: str) -> str:
    """Extract the bare host[:port] from an http(s) URL without a full parse.

    Any ``user:password@`` userinfo is dropped: a credential embedded in the URL
    must never reach a finding snippet (see :func:`_safe_url`).
    """
    rest = url.split("://", 1)[-1]
    authority = rest.split("/", 1)[0]
    return authority.rsplit("@", 1)[-1]


def _safe_url(url: str) -> str:
    """Render a URL for a finding snippet with any userinfo credential stripped.

    ``https://user:tok@host/path`` -> ``https://host`` — the audit must not widen
    exposure of the very credential it is reporting.
    """
    scheme, sep, rest = url.partition("://")
    if not sep:
        return _host_of(url)
    return f"{scheme}://{_host_of(url)}"


def _looks_like_secret_ref(value: str) -> bool:
    """True when the value is an env/secret-manager reference, not a literal.

    ``${TOKEN}``, ``$TOKEN``, and ``{{ secret }}`` are references — the operator
    is doing the right thing and we must not flag them.
    """
    v = value.strip()
    return (
        (v.startswith("${") and v.endswith("}"))
        or (v.startswith("$") and v[1:].isidentifier())
        or (v.startswith("{{") and v.endswith("}}"))
    )


def _server_has_auth(server: dict[str, Any]) -> bool:
    """Whether the server declares ANY authentication material."""
    headers = server.get("headers") or {}
    if isinstance(headers, dict):
        for key in headers:
            if key.lower() in _AUTH_HEADER_KEYS:
                return True
    env = server.get("env") or {}
    if isinstance(env, dict):
        for key in env:
            k = key.lower()
            if "token" in k or "api_key" in k or "apikey" in k or "auth" in k or "secret" in k:
                return True
    return False


def _scan_mapping_for_literals(mapping: dict[str, Any], target: str) -> list[Finding]:
    """Flag secret literals sitting directly in an env/headers mapping.

    An auth-bearing key whose value is a literal (not a ``${VAR}`` reference)
    is a credential committed into config: high severity. Values are also run
    through the vendor secret scanner so a stray ``sk-``/``ghp_``/AKIA literal
    anywhere in the mapping is caught even under a non-obvious key.
    """
    findings: list[Finding] = []
    if not isinstance(mapping, dict):
        return findings
    for key, value in mapping.items():
        if not isinstance(value, str) or not value:
            continue
        if _is_auth_key(key) and not _looks_like_secret_ref(value):
            findings.append(
                Finding(
                    rule_id="WRD-AUTH-TOKEN-IN-CONFIG",
                    severity="high",
                    target=target,
                    message=(
                        f"auth key '{key}' holds a literal credential in config; "
                        "reference a secret manager (${VAR}) instead"
                    ),
                    snippet=_redact(value),
                )
            )
        # Value-level secret scan (already redacts).
        findings.extend(scan_field(value, target))
    return findings


def _redact(value: str) -> str:
    """Redact a credential literal to a short, non-recoverable hint."""
    v = value.strip()
    if len(v) <= 8:
        return "***"
    return f"{v[:4]}...{v[-2:]}"


def audit_server(name: str, server: dict[str, Any]) -> list[Finding]:
    """Audit one MCP server entry; return sorted WRD-AUTH-* findings."""
    findings: list[Finding] = []
    target = f"mcpServers/{name}"

    url = server.get("url")
    transport = str(server.get("type") or server.get("transport") or "").lower()
    is_remote = bool(url) or transport in {"http", "sse", "streamable-http", "websocket"}

    if isinstance(url, str) and url:
        host = _host_of(url)
        remote = not _is_local_host(host)
        authority = url.partition("://")[2].split("/", 1)[0]
        if "@" in authority:
            findings.append(
                Finding(
                    rule_id="WRD-AUTH-URL-CREDENTIAL",
                    severity="high",
                    target=target,
                    message=(
                        "MCP endpoint URL embeds a userinfo credential; move it to a "
                        "header referencing a secret manager"
                    ),
                    snippet=_safe_url(url),
                )
            )
        if url.lower().startswith("http://") and remote:
            findings.append(
                Finding(
                    rule_id="WRD-AUTH-PLAINTEXT-HTTP",
                    severity="high",
                    target=target,
                    message=f"remote MCP endpoint '{host}' uses cleartext http://; use https://",
                    snippet=_safe_url(url),
                )
            )
        if remote and not _server_has_auth(server):
            findings.append(
                Finding(
                    rule_id="WRD-AUTH-NOAUTH",
                    severity="medium",
                    target=target,
                    message=(
                        f"remote MCP endpoint '{host}' declares no authentication "
                        "(no Authorization/token header or env)"
                    ),
                    snippet=host,
                )
            )
    elif is_remote and not _server_has_auth(server):
        findings.append(
            Finding(
                rule_id="WRD-AUTH-NOAUTH",
                severity="medium",
                target=target,
                message=f"{transport or 'remote'} MCP server declares no authentication material",
                snippet=name,
            )
        )

    findings.extend(_scan_mapping_for_literals(server.get("headers") or {}, target))
    findings.extend(_scan_mapping_for_literals(server.get("env") or {}, target))

    return sorted(findings, key=lambda f: (f.target, f.rule_id, f.snippet))


def audit_config(doc: dict[str, Any]) -> list[Finding]:
    """Audit a parsed MCP config document (``{"mcpServers": {...}}``)."""
    servers = doc.get("mcpServers")
    if not isinstance(servers, dict):
        return []
    findings: list[Finding] = []
    for name, server in servers.items():
        if isinstance(server, dict):
            findings.extend(audit_server(str(name), server))
    return sorted(findings, key=lambda f: (f.target, f.rule_id, f.snippet))


class AuthAuditError(ValueError):
    """Raised on an unreadable or malformed config file (fail closed)."""


def audit_path(path: Path) -> list[Finding]:
    """Read + audit one config file. Raises AuthAuditError on parse failure."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AuthAuditError(f"cannot read {path}: {exc}") from exc
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AuthAuditError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise AuthAuditError(f"{path}: top-level config must be a JSON object")
    return audit_config(doc)
