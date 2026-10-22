"""Reference, locator and placeholder heuristics for the WRD-AUTH-* audit.

Split out of :mod:`mcp_warden.auth_audit` (DSE-1540) with no behaviour change
beyond the separator-token fix in :func:`_tokenish_segment`. Everything here
answers one question about a config value: does it carry a credential, or
only point at / stand in for one?
"""

from __future__ import annotations

import re

from .checks_secret import shannon_entropy

#: An env/secret-manager reference anywhere in the value: ``${TOKEN}``,
#: ``${TOKEN:-default}`` / ``${TOKEN:=default}`` / ``${TOKEN:?msg}`` (shell expansion
#: forms, one level of nesting), ``$TOKEN``, ``{{ secret }}``, ``%TOKEN%`` (Windows).
_SECRET_REF = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:[:\-+?=](?:[^{}]|\$\{[^{}]*\})*)?\}"
    r"|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|\{\{[^}]+\}\}"
    r"|%[A-Za-z_][A-Za-z0-9_]*%"
)
#: ``${VAR:-D}`` / ``${VAR:+D}`` / ``${VAR:=D}`` (colon optional): D is *substituted
#: text* and is a literal unless it is empty, itself a reference (recursively —
#: ``${T:-${U:-hunter2!}}`` bottoms out on a literal), or itself a placeholder
#: (CSO F1/N1/N2). ``${VAR:?msg}`` names an error message, never a value.
_REF_WITH_DEFAULT = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-+=]((?:[^{}]|\$\{[^{}]*\})*)\}")
#: ``${VAR:?msg}``: the message is an error string, but a token-shaped run inside it
#: (``${API_KEY:?9f8e…}``) is a secret parked where the scanner looks away (NF-3).
_REF_WITH_MESSAGE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?\?((?:[^{}]|\$\{[^{}]*\})*)\}")

#: A path/URI segment that is itself token-shaped (CSO F5/N3/NF-1): alphanumeric
#: only and any of — 20+ characters; 16+ at >= 3.5 bits/char; 16+ mixed-case
#: (``Passw0rdPassw0rd`` is low-entropy but no directory is named that). A
#: lowercase hex key or a GHSAT-style token is carried, not pointed at. A segment
#: with a dot (``keys.json``) is a file name.
#:
#: A segment joined by ``-``/``_`` but no dot is judged with the separators
#: stripped (NF-2, DSE-1540): 16+ characters at >= 3.5 bits/char that also carry a
#: digit or mixed case is a token (``9f8e7d6c-5b4a-…`` UUID keys,
#: ``tok_9f8e…``). Words joined by separators — ``application_default_credentials``,
#: ``my-app`` — have no digit and one case, so they stay names.
_ALNUM_SEGMENT = re.compile(r"[A-Za-z0-9]+")
_SEPARATED_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")
_TOKENISH_MIN_LEN, _TOKENISH_LONG, _TOKENISH_ENTROPY = 16, 20, 3.5


def _separated_token(seg: str) -> bool:
    """A ``-``/``_``-joined segment that is a token once its separators are removed."""
    if not _SEPARATED_SEGMENT.fullmatch(seg):
        return False
    core = seg.replace("-", "").replace("_", "")
    if len(core) < _TOKENISH_MIN_LEN or shannon_entropy(core) < _TOKENISH_ENTROPY:
        return False
    mixed_case = core.lower() != core and core.upper() != core
    return mixed_case or any(ch.isdigit() for ch in core)


def _tokenish_segment(seg: str) -> bool:
    if not _ALNUM_SEGMENT.fullmatch(seg):
        return _separated_token(seg)
    if len(seg) < _TOKENISH_MIN_LEN:
        return False
    if len(seg) >= _TOKENISH_LONG:
        return True
    mixed_case = seg.lower() != seg and seg.upper() != seg
    return mixed_case or shannon_entropy(seg) >= _TOKENISH_ENTROPY


def _text_carries_a_token(text: str) -> bool:
    """Any alphanumeric run inside free text (a URI fragment, a ``:?`` message) that
    is token-shaped (CSO NF-3): ``#9f8e…`` / ``${K:?9f8e…}`` carry the secret."""
    return any(_tokenish_segment(run) for run in _ALNUM_RUN.findall(text))


#: Secret-manager reference URIs — the value names where the secret lives rather
#: than carrying it. Requires a ``/``-separated path of >= 2 segments after the
#: scheme, none of them token-shaped.
_SECRET_URI = re.compile(
    r"^(?:op|vault|awssm|gcpsm|azkv|secretref|keyring|pass)://(\S+)$", re.IGNORECASE
)
#: A filesystem path pointing at a credential file. Every branch (``~/``, ``./``,
#: ``../``, ``/``, ``C:\``) needs >= 2 path-safe segments, none token-shaped, so a
#: base64 blob that happens to start with ``/`` stays a literal.
_PATH_PREFIX = re.compile(r"^(?:~/|\./|\.\./|/|[A-Za-z]:[\\/])")


def _segments_are_a_locator(rest: str) -> bool:
    segs = [seg for seg in re.split(r"[\\/]+", rest) if seg]
    if len(segs) < 2:
        return False
    return all(_PATH_SEGMENT.fullmatch(seg) and not _tokenish_segment(seg) for seg in segs)


def _is_secret_locator(v: str) -> bool:
    """A secret-manager URI or credential-file path: names where a secret lives."""
    m = _SECRET_URI.match(v)
    if m:
        path, _, fragment = m.group(1).partition("#")
        if fragment and (not _PATH_SEGMENT.fullmatch(fragment) or _text_carries_a_token(fragment)):
            return False  # `#key` names a field; `#9f8e…` carries the secret
        return _segments_are_a_locator(path)
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
#: The ONLY short bare words that are a scheme/type slot rather than a credential
#: (CSO N4 — an allowlist; ``admin``, ``qwerty``, ``letmein`` are working secrets).
_SCHEME_TYPE_WORDS = frozenset({
    "basic", "bearer", "token", "apikey", "api-key", "digest", "negotiate", "oauth", "none",
})
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")
_X_RUN = re.compile(r"^x{3,}$")
#: ``<token>`` / ``<your-api-key>`` — an angle-bracketed slot.
_ANGLE_SLOT = re.compile(r"<[^<>]{1,64}>")
#: Auth scheme words that may sit beside a reference or a slot and still count as
#: "no literal here". A closed set (CSO F3): any other alphabetic run — including
#: a short alphabetic secret such as ``correcthorse`` — is a literal.
_SCHEME_WORDS = frozenset({"bearer", "token", "basic", "apikey", "negotiate", "digest"})


def _only_scheme_words(text: str) -> bool:
    return all(tok.lower() in _SCHEME_WORDS for tok in text.split())


def _looks_like_placeholder(value: str) -> bool:
    """True when the value is an obvious fill-me-in, not a real credential.

    Bounded on purpose (CSO F2/N5): unless every token is a placeholder or filler
    word, a value of 16+ characters that contains a digit is never downgraded.
    """
    v = value.strip().lower()
    if not v:
        return False
    tokens = [t for t in _TOKEN_SPLIT.split(v) if t]
    strong = [t for t in tokens if t in _PLACEHOLDER_TOKENS or _X_RUN.match(t)]
    joined = "-" + "-".join(tokens) + "-"
    phrase_tokens: set[str] = set()
    for phrase in _PLACEHOLDER_PHRASES:
        if f"-{phrase}-" in joined:
            phrase_tokens.update(phrase.split("-"))
    filler_ok = bool(tokens) and all(
        t in _PLACEHOLDER_TOKENS or t in _FILLER_TOKENS or t in phrase_tokens or _X_RUN.match(t)
        for t in tokens
    )
    if filler_ok and (strong or phrase_tokens or (tokens[0] == "my" and len(tokens) > 1)):
        return True
    if len(v) >= 16 and any(ch.isdigit() for ch in v):
        return False  # hard floor: a long value with a digit and a real token
    if v in _PLACEHOLDER_EXACT or v == "...":
        return True
    if v.endswith("...") and (len(v) <= 12 or filler_ok):
        return True  # `sk-...`, `your-key...` — never `<key>...`
    if _ANGLE_SLOT.search(v) and _only_scheme_words(_ANGLE_SLOT.sub(" ", v)):
        return True
    return v.replace("_", "-") in _SCHEME_TYPE_WORDS


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
    a reference (recursively), or itself a placeholder.
    """
    v = value.strip()
    if _is_secret_locator(v):
        return True
    if not _SECRET_REF.search(v):
        return False
    for default in _REF_WITH_DEFAULT.findall(v):
        d = default.strip()
        if d and not _looks_like_secret_ref(d) and not _looks_like_placeholder(d):
            return False
    if any(_text_carries_a_token(msg) for msg in _REF_WITH_MESSAGE.findall(v)):
        return False
    remainder = _SECRET_REF.sub(" ", v)
    return _only_scheme_words(remainder)
