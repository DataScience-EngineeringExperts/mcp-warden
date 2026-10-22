"""Reference, locator and placeholder heuristics for the WRD-AUTH-* audit.

Split out of :mod:`mcp_warden.auth_audit` (DSE-1540). The only behaviour change
is the separator-token rule in :func:`_tokenish_segment` and its use on URI
fragments and ``:?`` messages. Everything here
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
#: A segment carrying ``-``/``_`` is judged piece by piece across ``.``/``~``
#: (NF-2, DSE-1540); plain alphanumeric pieces of a dotted name stay a stem and an
#: extension. A ``-``/``_``-joined piece is a token when either: one of its parts
#: is a token-shaped alphanumeric run that contains a digit (``tok_9f8e…``,
#: ``token-9f8e…``); or, after dropping digit-only parts and word parts (4+
#: letters, not all hex), what remains switches between letters and digits 3+
#: times and is 20+ characters (16+ if mixed case) — ``9f8e7d6c-5b4a-…`` UUID
#: keys, ``Passw0rd_Passw0rd_X``. Descriptive names — ``gcp-sa-key-prod-2024``,
#: ``id_ed25519_github-work``, GCP key files ``<project>-123456-a1b2c3d4e5f6.json``
#: — stay names.
_ALNUM_SEGMENT = re.compile(r"[A-Za-z0-9]+")
_SEPARATED_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
_FREE_TEXT_RUN = re.compile(r"[A-Za-z0-9_-]+")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._~-]+")
_WORD_PART = re.compile(r"[A-Za-z]{4,}")
_HEX_LETTERS = re.compile(r"[A-Fa-f]+")
_CLASS_SWITCH = re.compile(r"(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])")
_TOKENISH_MIN_LEN, _TOKENISH_LONG, _TOKENISH_ENTROPY, _TOKENISH_SWITCHES = 16, 20, 3.5, 3


def _alnum_token(seg: str) -> bool:
    if len(seg) < _TOKENISH_MIN_LEN:
        return False
    if len(seg) >= _TOKENISH_LONG:
        return True
    mixed_case = seg.lower() != seg and seg.upper() != seg
    return mixed_case or shannon_entropy(seg) >= _TOKENISH_ENTROPY


def _separated_token(seg: str) -> bool:
    """A ``-``/``_``-joined piece that carries a token (see the rule above)."""
    parts = [p for p in re.split(r"[-_]+", seg) if p]
    if any(_alnum_token(p) and any(ch.isdigit() for ch in p) for p in parts):
        return True
    core = "".join(
        p for p in parts
        if not p.isdigit() and not (_WORD_PART.fullmatch(p) and not _HEX_LETTERS.fullmatch(p))
    )
    mixed_case = core.lower() != core and core.upper() != core
    min_len = _TOKENISH_MIN_LEN if mixed_case else _TOKENISH_LONG
    return len(core) >= min_len and len(_CLASS_SWITCH.findall(core)) >= _TOKENISH_SWITCHES


def _tokenish_segment(seg: str) -> bool:
    pieces = re.split(r"[.~]+", seg)
    if len(pieces) == 1 and _ALNUM_SEGMENT.fullmatch(seg):
        return _alnum_token(seg)
    # In a dotted name the alphanumeric pieces are a stem and an extension (a
    # hash-named cache file, ``keys.json``); only separator-joined pieces are judged.
    return any(
        not _ALNUM_SEGMENT.fullmatch(p) and _SEPARATED_SEGMENT.fullmatch(p) and _separated_token(p)
        for p in pieces if p
    )


def _text_carries_a_token(text: str) -> bool:
    """Any run inside free text (a URI fragment, a ``:?`` message) that is
    token-shaped (CSO NF-3): ``#9f8e…`` / ``${K:?9f8e-7d6c…}`` carry the secret."""
    return any(_tokenish_segment(run) for run in _FREE_TEXT_RUN.findall(text))


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
