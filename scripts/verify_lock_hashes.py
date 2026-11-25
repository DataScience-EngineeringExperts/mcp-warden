"""Validate each digest in uv's universal lockfiles against its exact PyPI release."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen

PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)(?:\s*;\s*\S.*)?")
SHA256 = re.compile(r"[0-9a-fA-F]{64}")
HASH_PREFIX = "--hash=sha256:"


def lock_entries(path: Path) -> Iterator[tuple[int, str, str, list[str]]]:
    """Read uv pip compile --generate-hashes entries, including inactive markers."""
    fragments: list[str] = []
    for number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = re.split(r"(^|\s+)#", raw_line, maxsplit=1)[0].strip()
        if not line:
            continue
        if not fragments:
            start = number
        fragments.append(line.removesuffix("\\").rstrip())
        if line.endswith("\\"):
            continue

        requirement, *options = re.split(r"\s+(?=--)", " ".join(fragments))
        pin = PIN.fullmatch(requirement)
        if pin is None:
            raise ValueError(f"{path}:{start}: expected an exact version pin")

        hashes = []
        for option in options:
            digest = option.removeprefix(HASH_PREFIX)
            if not option.startswith(HASH_PREFIX) or not SHA256.fullmatch(digest):
                raise ValueError(f"{path}:{start}: expected a SHA-256 hash option")
            hashes.append(digest.lower())
        if not hashes:
            raise ValueError(f"{path}:{start}: pin has no SHA-256 hashes")

        name, version = pin.groups()
        yield start, re.sub(r"[-_.]+", "-", name).lower(), version, hashes
        fragments.clear()

    if fragments:
        raise ValueError(f"{path}:{start}: unterminated lock entry")


def release_hashes(name: str, version: str) -> set[str]:
    url = f"https://pypi.org/pypi/{name}/{quote(version, safe='')}/json"
    try:
        with urlopen(url, timeout=15) as response:
            if response.geturl() != url:
                raise ValueError("PyPI release metadata redirected")
            try:
                metadata = json.load(response)
            except ValueError:
                raise ValueError("invalid PyPI release metadata") from None
    except OSError as exc:
        raise ValueError(f"could not fetch PyPI release metadata ({exc})") from None

    try:
        files = metadata["urls"]
        if not isinstance(files, list) or not files:
            raise ValueError
        digests = [file["digests"]["sha256"] for file in files]
        if not all(SHA256.fullmatch(digest) for digest in digests):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ValueError("invalid PyPI release metadata") from None

    return {digest.lower() for digest in digests}


def verify_locks(paths: list[Path]) -> None:
    cache: dict[tuple[str, str], set[str]] = {}
    for path in paths:
        pin_count = hash_count = 0
        for number, name, version, hashes in lock_entries(path):
            pin = (name, version)
            label = f"{path}:{number}: {name}=={version}"
            if pin not in cache:
                try:
                    cache[pin] = release_hashes(name, version)
                except ValueError as exc:
                    raise ValueError(f"{label}: {exc}") from None

            unknown = sorted(set(hashes) - cache[pin])
            if unknown:
                raise ValueError(f"{label}: SHA-256 not published by PyPI: {', '.join(unknown)}")

            pin_count += 1
            hash_count += len(hashes)

        if not pin_count:
            raise ValueError(f"{path}: lockfile contains no pins")
        print(f"{path}: verified {hash_count} SHA-256 hashes across {pin_count} pins")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfiles", type=Path, nargs="+")
    args = parser.parse_args(argv)

    try:
        verify_locks(args.lockfiles)
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
