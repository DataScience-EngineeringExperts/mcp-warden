"""Root-cumulative semantic budgets and deterministic inspection transforms."""
from __future__ import annotations

import unicodedata

from normalization_ipc import NormalizationError, canonical

PROFILE = "mcp-warden.normalizer.v1"
CEILINGS = dict(input_bytes=16*1024*1024, expanded_bytes=64*1024*1024,
                output_bytes=16*1024*1024, depth=8, nodes=4096, members=256,
                spans=100_000, map_bytes=8*1024*1024, combining_run=64, work=100_000_000)
SUPPORTED = frozenset({"text/plain", "application/json", "application/xml", "text/xml",
                       "text/html", "text/markdown", "text/csv", "message/rfc822",
                       "application/zip", "application/pdf"})


def fail(code="NRM-MALFORMED"):
    raise NormalizationError(code)


def decode(data, charset="utf-8"):
    if charset.lower().replace("_", "-") not in {"utf-8", "utf8", "us-ascii", "ascii", "iso-8859-1"}:
        fail("NRM-UNSUPPORTED")
    try:
        text = data.decode(charset, errors="strict")
        text.encode("utf-8", errors="strict")
        return text
    except (UnicodeError, LookupError):
        fail()


class Context:
    """A single budget ledger is shared by every nested parse and decoding view."""

    def __init__(self, raw, budget):
        if (type(budget) is not dict or budget.keys() != CEILINGS.keys()
                or any(type(v) is not int or not 0 < v <= CEILINGS[k] for k, v in budget.items())):
            fail("NRM-PROFILE")
        self.budget, self.raw, self.segments = budget, raw, []
        self.usage = dict.fromkeys(budget, 0)
        self.charge("input_bytes", len(raw))
        self.charge("map_bytes", 2)

    def charge(self, key, amount):
        self.usage[key] += amount
        if self.usage[key] > self.budget[key]:
            fail("NRM-OVER-CAP")

    def node(self, depth):
        if depth > self.budget["depth"]:
            fail("NRM-OVER-CAP")
        self.usage["depth"] = max(self.usage["depth"], depth)
        self.charge("nodes", 1)
        self.charge("work", 1)

    def emit(self, raw_text, locator, exact=False):
        if not raw_text:
            return
        if len(locator.encode("utf-8")) > 1024:
            fail("NRM-OVER-CAP")
        run = 0
        for char in raw_text:
            run = run + 1 if unicodedata.combining(char) else 0
            self.usage["combining_run"] = max(self.usage["combining_run"], run)
            if run > self.budget["combining_run"]:
                fail("NRM-OVER-CAP")
        text = unicodedata.normalize("NFKC", raw_text)
        text = "".join(c for c in text if unicodedata.category(c) not in {"Cf", "Cc"}
                       or c in "\n\r\t")
        run = 0
        for char in text:
            run = run + 1 if unicodedata.combining(char) else 0
            self.usage["combining_run"] = max(self.usage["combining_run"], run)
            if run > self.budget["combining_run"]:
                fail("NRM-OVER-CAP")
        if not text:
            fail("NRM-EMPTY")
        self.charge("work", len(raw_text.encode("utf-8")) + len(text.encode("utf-8")))
        self.charge("output_bytes", len(text.encode("utf-8")))
        segment = dict(text=text, raw_text=raw_text, locator=locator,
                       precision="exact" if exact and text == raw_text else "container",
                       source_start=0, source_end=len(self.raw))
        self.charge("spans", 1)
        self.charge("map_bytes", len(canonical(segment)) + bool(self.segments))
        self.segments.append(segment)

    def parse(self, data, media, locator="root", depth=0, charset="utf-8"):
        from formats_containers import parse_email, parse_zip
        from formats_pdf import parse_pdf
        from formats_structured import parse_structured
        self.node(depth)
        self.charge("work", len(data))
        if not data:
            fail("NRM-EMPTY")
        if media not in SUPPORTED:
            fail("NRM-UNSUPPORTED")
        if media == "application/zip":
            parse_zip(self, data, locator, depth)
        elif media == "message/rfc822":
            parse_email(self, data, locator, depth)
        elif media == "application/pdf":
            parse_pdf(self, data, locator, depth)
        else:
            if data.startswith((b"%PDF-", b"PK\x03\x04", b"PK\x05\x06", b"\x00", b"\xff\xfe", b"\xfe\xff")):
                fail("NRM-AMBIGUOUS")
            text = decode(data, charset)
            self.emit(text, locator, exact=depth == 0 and media == "text/plain"
                      and data == text.encode("utf-8"))
            parse_structured(self, text, media, locator, depth)
