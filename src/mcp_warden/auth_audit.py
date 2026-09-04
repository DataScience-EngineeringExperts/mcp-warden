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
import re
from pathlib import Path
from typing import Any

from .checks_secret import scan_field
from .models import Finding
from .redact import redact_secret

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


#: An env/secret-manager reference anywhere in the value: ``${TOKEN}``,
#: ``${TOKEN:-default}`` / ``${TOKEN:?msg}`` (shell expansion forms, one level of
#: nesting), ``$TOKEN``, ``{{ secret }}``, and ``%TOKEN%`` (Windows).
_SECRET_REF = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:[:\-+?](?:[^{}]|\$\{[^{}]*\})*)?\}"
    r"|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|\{\{[^}]+\}\}"
    r"|%[A-Za-z_][A-Za-z0-9_]*%"
)
#: ``${VAR:-D}`` / ``${VAR:+D}`` (colon optional): D is *substituted text* and is a
#: literal unless it is empty, itself a reference, or itself a placeholder (CSO F1 —
#: ``${TOKEN:-aB3x…}`` is a committed credential wearing a reference). ``${VAR:?msg}``
#: names an error message, never a value, and stays a plain reference.
_REF_WITH_DEFAULT = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-+]((?:[^{}]|\$\{[^{}]*\})*)\}")

#: A path segment / URI segment that is itself token-shaped: mixed-case
#: alphanumeric, 16+ chars. ``op://…/aB3xK9mQ7pL2wR5tY8vN`` and
#: ``~/.config/aB3xK9mQ7pL2wR5tY8vN`` carry the secret; they do not point at it.
_TOKENISH_SEGMENT = re.compile(r"(?=.*[a-z])(?=.*[A-Z])[A-Za-z0-9]{16,}")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")

#: Secret-manager reference URIs — the value names where the secret lives rather
#: than carrying it. Requires a ``/``-separated path of >= 2 segments after the
#: scheme, none of them token-shaped (CSO F5).
_SECRET_URI = re.compile(
    r"^(?:op|vault|awssm|gcpsm|azkv|secretref|keyring|pass)://(\S+)$", re.IGNORECASE
)
#: A filesystem path pointing at a credential file. Every branch (``~/``, ``./``,
#: ``../``, ``/``, ``C:\``) needs >= 2 path-safe segments, none token-shaped, so a
#: base64 blob that happens to start with ``/`` stays a literal (CSO F5).
_PATH_PREFIX = re.compile(r"^(?:~/|\./|\.\./|/|[A-Za-z]:[\\/])")


def _segments_are_a_locator(rest: str) -> bool:
    segs = [seg for seg in re.split(r"[\\/]+", rest) if seg]
    if len(segs) < 2:
        return False
    return all(_PATH_SEGMENT.fullmatch(seg) and not _TOKENISH_SEGMENT.fullmatch(seg) for seg in segs)


def _is_secret_locator(v: str) -> bool:
    """A secret-manager URI or credential-file path: names where a secret lives."""
    m = _SECRET_URI.match(v)
    if m:
        return _segments_are_a_locator(m.group(1).split("#", 1)[0])
    m = _PATH_PREFIX.match(v)
    return bool(m) and _segments_are_a_locator(v[m.end():])


#: Strong placeholder tokens — a value is a fill-me-in only if at least one of
#: these is present as a WHOLE token and every other token is filler (CSO F2).
_PLACEHOLDER_TOKENS = frozenset({
    "your", "yours", "placeholder", "example", "changeme", "todo", "tbd", "here",
    "insert", "replace", "dummy", "sample", "fake", "fill", "redacted",
    "abc123", "12345", "123456", "1234567890",
})
#: Filler that may accompany a strong token without making the value a secret:
#: the thing being named (``key``, ``token``), connectives, and vendor names.
_FILLER_TOKENS = frozenset({
    "key", "api", "apikey", "token", "secret", "password", "pass", "access", "auth",
    "id", "value", "string", "goes", "me", "in", "the", "a", "an", "to", "with", "my",
    "name", "bearer", "github", "gitlab", "openai", "anthropic", "slack", "aws",
    "google", "azure", "notion", "stripe", "brave", "tavily", "exa", "firecrawl",
})
#: Multi-token placeholder phrases, matched as whole consecutive tokens.
_PLACEHOLDER_PHRASES = ("change-me", "goes-here", "add-your", "put-your", "api-key-here")
#: Whole-value placeholders that do not tokenise usefully.
_PLACEHOLDER_EXACT = frozenset({"n/a", "none", "null", "-"})
#: Default credentials are real, working secrets (CSO F4). They never take the
#: short-bare-word downgrade; ``changeme`` is a strong placeholder token instead.
_DEFAULT_CREDENTIALS = frozenset({
    "changeit", "raspberry", "postgres", "grafana", "elastic", "letmein", "guest",
    "toor", "admin", "password", "root", "secret", "test",
})
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_X_RUN = re.compile(r"^x{3,}$")
#: ``<token>`` / ``<your-api-key>`` — an angle-bracketed slot.
_ANGLE_SLOT = re.compile(r"<[^<>]{1,64}>")
#: A short bare word: purely alphabetic with ``-``/``_``, no digits or other
#: punctuation (``basic``, ``api-key``). A scheme/type token, not a credential.
#: ``hunter2!`` and ``p@ssword`` are NOT matched and stay high severity.
_SHORT_BARE_WORD = re.compile(r"^[a-z][a-z_-]{0,10}$")
#: Auth scheme words that may sit beside a reference or a slot and still count as
#: "no literal here". A closed set (CSO F3): any other alphabetic run — including
#: a short alphabetic secret such as ``correcthorse`` — is a literal.
_SCHEME_WORDS = frozenset({"bearer", "token", "basic", "apikey", "negotiate", "digest"})


def _only_scheme_words(text: str) -> bool:
    return all(tok.lower() in _SCHEME_WORDS for tok in text.split())


def _looks_like_placeholder(value: str) -> bool:
    """True when the value is an obvious fill-me-in, not a real credential.

    Bounded on purpose (CSO F2): a value of 16+ characters that contains a digit
    and any non-placeholder token is never downgraded, whatever else it says.
    """
    v = value.strip().lower()
    if not v:
        return False
    tokens = [t for t in _TOKEN_SPLIT.split(v) if t]
    strong = [t for t in tokens if t in _PLACEHOLDER_TOKENS or _X_RUN.match(t)]
    if len(v) >= 16 and any(ch.isdigit() for ch in v) and len(strong) < len(tokens):
        return False
    if v in _PLACEHOLDER_EXACT or v == "..." or v.endswith("..."):
        return True
    if _ANGLE_SLOT.search(v) and _only_scheme_words(_ANGLE_SLOT.sub(" ", v)):
        return True
    if not tokens:
        return False
    joined = "-" + "-".join(tokens) + "-"
    phrase_tokens: set[str] = set()
    for phrase in _PLACEHOLDER_PHRASES:
        if f"-{phrase}-" in joined:
            phrase_tokens.update(phrase.split("-"))
    filler_ok = all(
        t in _PLACEHOLDER_TOKENS or t in _FILLER_TOKENS or t in phrase_tokens or _X_RUN.match(t)
        for t in tokens
    )
    if filler_ok and (strong or phrase_tokens or (tokens[0] == "my" and len(tokens) > 1)):
        return True
    return bool(_SHORT_BARE_WORD.match(v)) and v not in _DEFAULT_CREDENTIALS


def _looks_like_secret_ref(value: str) -> bool:
    """True when the value carries its secret by reference, not as a literal.

    The operator is doing the right thing and must not be flagged. Crucially this
    accepts a reference *embedded* in a header value — ``Bearer ${TOKEN}`` is the
    single most common correct shape for an Authorization header, and treating it
    as a committed credential is a false positive that gets the whole gate
    switched off.

    Conservative by construction: a reference must be present; once every
    reference is removed, whatever remains may only be auth scheme words
    (``Bearer ${T}`` passes; ``Bearer abc123 ${T}`` and ``correcthorse ${T}`` do
    not); and a ``${VAR:-default}`` counts only when the default is empty, itself
    a reference, or itself a placeholder.
    """
    v = value.strip()
    if _is_secret_locator(v):
        return True
    if not _SECRET_REF.search(v):
        return False
    for default in _REF_WITH_DEFAULT.findall(v):
        d = default.strip()
        if d and not _SECRET_REF.fullmatch(d) and not _looks_like_placeholder(d):
            return False
    remainder = _SECRET_REF.sub(" ", v)
    return _only_scheme_words(remainder)


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
        # Value-level secret scan (already redacts). Computed first: a value the
        # vendor patterns or entropy heuristic recognise as a secret is a
        # credential no matter how it is dressed up, and is never downgraded to
        # a placeholder or excused as a reference.
        vendor = scan_field(value, target)
        if _is_auth_key(key) and (vendor or not _looks_like_secret_ref(value)):
            if not vendor and _looks_like_placeholder(value):
                # A template's fill-me-in slot is a real (low) finding — shipping
                # a config that cannot work — but calling it a committed
                # credential is false and is what gets the gate switched off.
                findings.append(
                    Finding(
                        rule_id="WRD-AUTH-PLACEHOLDER-SECRET",
                        severity="low",
                        target=target,
                        message=(
                            f"auth key '{key}' holds a placeholder, not a working "
                            "credential; wire it to a secret reference (${VAR})"
                        ),
                        snippet=_redact(value),
                    )
                )
            else:
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
        findings.extend(vendor)
    return findings


def _redact(value: str) -> str:
    """Redact a credential literal with the house redactor (prefix + length, no suffix)."""
    return redact_secret(value.strip())


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
