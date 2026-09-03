"""The ``doctor`` funnel: hostile-input-safe text and the redacted ``pin`` command — DSE-1516.

Split from ``doctor.py`` to keep each module under the LOC budget. Everything
a config controls and a terminal renders passes through :func:`safe_text`
first; everything that goes into the copy-pasteable ``pin`` line passes
through the masking rules below. See ``docs/DOCTOR.md`` §2–§3.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .auth_audit import _is_auth_key, _looks_like_secret_ref
from .checks_secret import scan_field, shannon_entropy

#: Everything a terminal or a copy buffer can be tricked by: C0 + DEL, the C1
#: range (U+009B is CSI and U+009D is OSC on xterm-family terminals in UTF-8
#: mode), NEL, zero-width and directional marks (U+200B–U+200F), the Unicode
#: line/paragraph separators, and both bidi-override blocks (Trojan Source,
#: CVE-2021-42574 — a reordered ``pin`` line still runs in source order).
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def safe_text(s: object, max_len: int = 200) -> str:
    """Neutralise control / bidi / separator characters (U+FFFD) and cap length."""
    t = _CONTROL.sub("�", str(s))
    return t if len(t) <= max_len else t[: max_len - 1] + "…"


# --- lock naming -------------------------------------------------------------


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "server"


def lock_filename(name: str, taken: set[str]) -> str:
    """``<slug>.warden.lock``; a slug collision gets a short hash of the raw name."""
    base = slug(name)
    fn = f"{base}.warden.lock"
    if fn in taken:
        fn = f"{base}-{hashlib.sha256(name.encode()).hexdigest()[:6]}.warden.lock"
    taken.add(fn)
    return fn


# --- masking -------------------------------------------------------------------

#: Flags whose *following* value (or ``=``/``:``-joined value) is a credential.
#: Doctor-local and deliberately wider than ``auth_audit._is_auth_key``: Smithery's
#: ``--key <uuid>``, mcp-remote's ``--header "Authorization: Bearer …"``. A
#: single-letter ``-k`` is not here: its value masks only on a vendor-pattern hit.
_AUTH_FLAGS = {
    "key", "api-key", "apikey", "token", "secret", "password", "passwd", "pat", "bearer",
    "credential", "credentials", "cookie", "auth", "authorization", "header", "h",
}
_WIN_REF = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")
_AUTH_QUERY = {"api_key", "apikey", "key", "token", "access_token", "secret", "sig", "signature", "auth"}
_PATH_ENTROPY_MIN_LEN = 20
_PATH_ENTROPY_THRESHOLD = 3.5


def _is_auth_flag(token: str) -> bool:
    """Both the raw and the ``_``→``-`` folded spelling are checked, so the
    substring rules in ``_is_auth_key`` (``api_key``) stay reachable."""
    raw = token.lstrip("-").lower()
    folded = raw.replace("_", "-")
    return folded in _AUTH_FLAGS or _is_auth_key(raw) or _is_auth_key(folded)


def _is_ref(value: str) -> bool:
    """``${VAR}`` / ``$VAR`` / ``{{ x }}`` / ``%VAR%`` — a reference carries nothing."""
    return _looks_like_secret_ref(value) or bool(_WIN_REF.fullmatch(value.strip()))


def _json_object_with_auth_key(arg: str) -> bool:
    if not arg.lstrip().startswith("{"):
        return False
    try:
        doc = json.loads(arg)
    except ValueError:
        return False
    return isinstance(doc, dict) and any(_is_auth_flag(str(k)) for k in doc)


def _mask_arg(prev: str, arg: str) -> bool:
    """Whether a launch argument must be masked in the printed ``pin`` command.

    A vendor-pattern hit always masks. The entropy heuristic alone does **not**
    — ``@modelcontextprotocol/server-github`` is high-entropy and is exactly the
    token the user must copy. The value after an auth-shaped flag, the value of
    an auth-shaped ``KEY=value`` / ``Key: value``, and a JSON object carrying an
    auth-shaped key are masked unless the value is a ``${VAR}``-style reference.
    """
    if any(f.rule_id != "WRD-SEC-ENTROPY" for f in scan_field(arg, "arg")):
        return True
    if _json_object_with_auth_key(arg):
        return True
    for sep in ("=", ":"):
        key, found, value = arg.partition(sep)
        if found and _is_auth_flag(key.strip()):
            return not _is_ref(value)
    if prev.startswith("-") and _is_auth_flag(prev):
        return not _is_ref(arg)
    return False


def _risky_segment(seg: str) -> bool:
    return len(seg) >= _PATH_ENTROPY_MIN_LEN and (
        shannon_entropy(seg) >= _PATH_ENTROPY_THRESHOLD
        or any(f.rule_id != "WRD-SEC-ENTROPY" for f in scan_field(seg, "url"))
    )


def _auth_pairs(qs: str) -> bool:
    return any(_is_auth_flag(k) or k.lower() in _AUTH_QUERY for k, _ in parse_qsl(qs, keep_blank_values=True))


def _redact_url(url: str) -> str:
    """Keep scheme + host; mask userinfo, auth-shaped query params, token-like path
    segments, and an auth-shaped or token-like fragment.

    When nothing needs masking the *original string* is returned byte-for-byte —
    never a re-encoded copy — so the printed ``--url`` still matches the config
    and ``lock_covers`` recognises the lock the user pins from it.
    """
    parts = urlsplit(url)
    if "@" in parts.netloc:
        return "<REDACTED: url embeds a credential>"
    changed = False
    segments: list[str] = []
    for seg in parts.path.split("/"):
        if _risky_segment(seg):
            segments.append("REDACTED")
            changed = True
        else:
            segments.append(seg)
    query: list[tuple[str, str]] = []
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        if _is_auth_flag(k) or k.lower() in _AUTH_QUERY:
            query.append((k, "REDACTED"))
            changed = True
        else:
            query.append((k, v))
    fragment = parts.fragment
    if fragment and (_risky_segment(fragment) or _auth_pairs(fragment)):
        fragment = "REDACTED"
        changed = True
    if not changed:
        return url
    return urlunsplit((parts.scheme, parts.netloc, "/".join(segments), urlencode(query), fragment))


def pin_command(name: str, server: dict[str, Any], lock: str | None = None) -> str:
    """The copy-pasteable ``pin`` for one server; credential-bearing parts are masked.

    ``env`` is deliberately not emitted: an env-dependent server's secrets belong
    in the user's shell environment, never inline on a command line.
    """
    lock = lock or f"{slug(name)}.warden.lock"
    tail = f"--approve --approver you@example.com --lock {lock}"
    url = server.get("url")
    if isinstance(url, str) and url:
        return f"mcp-warden pin --url {shlex.quote(_redact_url(safe_text(url, 2048)))} {tail}"
    argv = [shlex.quote(safe_text(server.get("command") or "<command>", 2048))]
    prev = ""
    for a in server.get("args") or []:
        a = str(a)
        argv.append("<REDACTED>" if _mask_arg(prev, a) else shlex.quote(safe_text(a, 2048)))
        prev = a
    return f"mcp-warden pin {' '.join(argv)} {tail}"
