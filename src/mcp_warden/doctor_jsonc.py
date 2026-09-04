"""JSONC → JSON for VS Code ``mcp.json`` — one linear, string-aware pass (DSE-1516/1529).

Split from ``doctor_discovery.py`` to keep that module under the LOC budget.
VS Code permits ``//`` and ``/* */`` comments and trailing commas; a client
loads such a file happily, so ``doctor`` must audit exactly what it loads.
"""

from __future__ import annotations

import re

__all__ = ["strip_jsonc"]

_STRING_END = re.compile(r'(?:[^"\\]|\\.)*"')


def strip_jsonc(text: str) -> str:
    """Remove ``//`` / ``/* */`` comments and trailing commas — outside strings only.

    One left-to-right, string-aware pass, linear in the input: a string literal
    is copied verbatim (so a ``"//"`` or ``"echo {a, }"`` inside a value is never
    touched), a comment becomes a single space, and a ``,`` is held back until
    the next token shows whether it is trailing. An unterminated string or
    ``/*`` leaves the remainder untouched, which is invalid JSON and fails
    closed — the earlier regex form back-tracked once per unterminated ``/*``
    and went quadratic on a hostile file (CSO review of #98, N9).
    """
    out: list[str] = []
    pending_comma = False  # a ',' seen, not yet emitted: dropped if '}' / ']' follows
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            m = _STRING_END.match(text, i + 1)
            if m is None:  # unterminated: leave the rest as-is (invalid JSON)
                if pending_comma:
                    out.append(",")
                out.append(text[i:])
                break
            end = m.end()
            if pending_comma:
                out.append(",")
                pending_comma = False
            out.append(text[i:end])
            i = end
            continue
        if ch == "/" and text.startswith("//", i):
            nl = text.find("\n", i)
            out.append(" ")
            i = n if nl == -1 else nl
            continue
        if ch == "/" and text.startswith("/*", i):
            close = text.find("*/", i + 2)
            if close == -1:  # unterminated block comment: leave the rest as-is
                if pending_comma:
                    out.append(",")
                out.append(text[i:])
                break
            out.append(" ")
            i = close + 2
            continue
        if ch == ",":
            if pending_comma:
                out.append(",")
            pending_comma = True
            i += 1
            continue
        if ch in " \t\r\n":
            out.append(ch)
            i += 1
            continue
        if pending_comma:
            if ch not in "}]":
                out.append(",")
            pending_comma = False
        out.append(ch)
        i += 1
    if pending_comma:
        out.append(",")
    return "".join(out)
