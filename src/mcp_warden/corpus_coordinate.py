"""Package coordinates for the community lock corpus (DSE-1515, phase 1).

A *coordinate* names exactly one published artifact — ``npm:@scope/name@1.2.3``
or ``pypi:name@1.2.3`` — and is the key under which attesters file their signed
locks. It is derived from the server launch argv the same way ``checks_supply``
reads it, but is deliberately stricter: a floating spec (``pkg``, ``pkg@latest``,
``pkg@^1``) cannot be attested, so it resolves to ``None`` and the caller fails
closed (``WRD-CONSENSUS-UNRESOLVED``) instead of guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from .checks_supply import _is_flag, _is_local_path

#: Explicit ``--coordinate`` grammar: ``<ecosystem>:<name>@<version>``.
_EXPLICIT = re.compile(r"(?P<eco>npm|pypi):(?P<name>[^:]+)@(?P<ver>[^@/]+)\Z")
#: A concrete version: leading digit, then version chars (never a tag/range).
_PINNED_VERSION = re.compile(r"\d[A-Za-z0-9._+\-]*\Z")
#: Package-name characters we will ever turn into an on-disk path segment.
_NAME_CHARS = re.compile(r"[A-Za-z0-9@._\-/]+\Z")


@dataclass(frozen=True)
class Coordinate:
    """One published package version; the corpus key."""

    ecosystem: str  # "npm" | "pypi"
    name: str  # npm: case-sensitive, may be scoped; pypi: PEP 503 normalized
    version: str

    def __str__(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"

    @property
    def path_segment(self) -> str:
        """On-disk name: a scoped npm name ``@org/name`` becomes ``@org__name``."""
        return self.name.replace("/", "__")

    def relative_dir(self) -> PurePosixPath:
        """``locks/<ecosystem>/<segment>/<version>`` inside a corpus checkout."""
        return PurePosixPath("locks") / self.ecosystem / self.path_segment / self.version


def _clean(text: str) -> bool:
    """No whitespace or control characters anywhere: a trailing newline must not
    resolve to a coordinate whose directory merely does not exist (CSO M1)."""
    return bool(text) and not any(ch.isspace() or ord(ch) < 32 or ord(ch) == 0x7F for ch in text)


def _validate(eco: str, name: str, version: str) -> Coordinate | None:
    """Reject anything that could escape the corpus tree or float."""
    if not _clean(name) or not _clean(version):
        return None
    if not _NAME_CHARS.fullmatch(name) or ".." in name.split("/") or name.startswith("/"):
        return None
    if name.count("/") > 1 or (name.count("/") == 1 and not name.startswith("@")):
        return None
    if not _PINNED_VERSION.fullmatch(version):
        return None
    if eco == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    return Coordinate(eco, name, version)


def parse_explicit(text: str) -> Coordinate | None:
    """Parse a user-supplied ``--coordinate`` string; ``None`` if malformed."""
    m = _EXPLICIT.fullmatch(text)
    if not m:
        return None
    return _validate(m.group("eco"), m.group("name"), m.group("ver"))


def _split_npm_spec(spec: str) -> Coordinate | None:
    """``@scope/name@1.2.3`` / ``name@1.2.3`` -> Coordinate; unpinned -> None."""
    body = spec[1:] if spec.startswith("@") else spec
    if "@" not in body:
        return None
    name, _, version = body.rpartition("@")
    if spec.startswith("@"):
        name = "@" + name
    return _validate("npm", name, version)


def _split_py_spec(spec: str) -> Coordinate | None:
    """``name==1.2.3`` (optionally with extras) -> Coordinate; else None."""
    if "==" not in spec:
        return None
    name, _, version = spec.partition("==")
    name = re.sub(r"\[.*\]$", "", name)  # strip extras
    return _validate("pypi", name, version)


def _positional(argv: list[str], *, value_flags: set[str]) -> tuple[str | None, dict[str, str]]:
    """First positional token after the runner plus values of ``value_flags``."""
    picked: dict[str, str] = {}
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            rest = [t for t in argv[i + 1 :] if not _is_local_path(t)]
            return (rest[0] if rest else None), picked
        if tok in value_flags and i + 1 < len(argv):
            picked[tok] = argv[i + 1]
            i += 2
            continue
        if _is_flag(tok) or _is_local_path(tok):
            i += 1
            continue
        return tok, picked
    return None, picked


def resolve_coordinate(command: str, args: list[str], explicit: str | None = None) -> Coordinate | None:
    """Derive the corpus coordinate for a launch, or ``None`` when it cannot be pinned.

    ``explicit`` (the ``--coordinate`` flag) wins outright. Otherwise the runner
    is read from ``command``'s basename: ``npx`` (``-p``/``--package`` value or
    the first positional spec), ``uvx`` (``--from`` value or first positional),
    ``pipx run`` (``--spec`` value or first positional). Anything else — a bare
    ``node ./server.js``, an unpinned ``npx pkg``, ``--url`` with no coordinate —
    returns ``None`` so the caller fails closed.
    """
    if explicit is not None:
        return parse_explicit(explicit)
    runner = PurePosixPath(command).name if command else ""
    if runner == "npx":
        pos, picked = _positional(args, value_flags={"-p", "--package"})
        spec = picked.get("-p") or picked.get("--package") or pos
        return _split_npm_spec(spec) if spec else None
    if runner == "uvx":
        pos, picked = _positional(args, value_flags={"--from", "--python", "-p", "-w", "--with"})
        spec = picked.get("--from") or pos
        return _split_py_spec(spec) if spec else None
    if runner == "pipx" and args and args[0] == "run":
        pos, picked = _positional(args[1:], value_flags={"--spec", "--python"})
        spec = picked.get("--spec") or pos
        return _split_py_spec(spec) if spec else None
    return None
