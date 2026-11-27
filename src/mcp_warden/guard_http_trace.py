"""Incremental inspect-compatible trace sink for long-lived HTTP sessions."""

from __future__ import annotations

import json
import os
from pathlib import Path


class HTTPTrace:
    def __init__(self, path: Path | None):
        self.path = path
        self.stream = None
        self.pending: dict | None = None

    def __enter__(self):
        if self.path is not None:
            # Restrict the new file to the operator and refuse existing paths.
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self.stream = os.fdopen(fd, "w", encoding="utf-8")
        return self

    def __exit__(self, *args):
        if self.stream is not None:
            try:
                self.flush()
            finally:
                self.stream.close()

    def flush(self) -> None:
        if self.pending is not None:
            self.stream.write(json.dumps(self.pending, ensure_ascii=True) + "\n")
            self.pending = None

    def frame(self, direction: str, obj: dict) -> None:
        self.flush()
        self.pending = {"direction": direction, "frame": obj}

    def withheld(self, obj: dict) -> None:
        self.pending["forwarded"] = False
