"""Strict structured formats retain source syntax and decoded inspection views."""
import base64
import csv
import io
import json
import re
from html import unescape
from html.parser import HTMLParser
from xml.etree import ElementTree

from formats import SUPPORTED, fail


def _json(ctx, text, locator, depth):
    # Check lexical nesting before the C decoder can build a deeply nested tree.
    level, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            level += 1
            if depth + level > ctx.budget["depth"]:
                fail("NRM-OVER-CAP")
        elif char in "]}":
            level -= 1

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail()
            result[key] = value
        return result

    obj = json.loads(text, object_pairs_hook=pairs,
                     parse_constant=lambda _: fail())
    string_values = []

    def visit(value, nesting):
        ctx.node(nesting)
        if isinstance(value, dict):
            if "mimeType" in value and any(k in value for k in ("blob", "data", "text")):
                media = value["mimeType"]
                carriers = [k for k in ("blob", "data", "text") if k in value]
                if type(media) is not str or media not in SUPPORTED or len(carriers) != 1:
                    fail("NRM-UNSUPPORTED")
                carrier = carriers[0]
                encoded = value[carrier]
                if type(encoded) is not str:
                    fail()
                if carrier == "text":
                    if media in {"application/pdf", "application/zip", "message/rfc822"}:
                        fail("NRM-AMBIGUOUS")
                    payload = encoded.encode("utf-8")
                else:
                    payload = base64.b64decode(encoded, validate=True)
                    if base64.b64encode(payload).decode("ascii") != encoded:
                        fail()
                ctx.charge("members", 1)
                ctx.charge("expanded_bytes", len(payload))
                ctx.parse(payload, media, locator + "/json-embedded", nesting + 1)
            for key, item in value.items():
                ctx.node(nesting + 1)
                ctx.emit(key, locator + "/json-key")
                visit(item, nesting + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, nesting + 1)
        elif isinstance(value, str):
            string_values.append(value)
            ctx.emit(value, locator + "/json-string")
    visit(obj, depth)
    # Keep keys/metadata in their original evidence views without inserting
    # them between adjacent decoded string values in this additional view.
    ctx.emit("".join(string_values), locator + "/json-combined-values")


def _xml(ctx, text, locator, depth):
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        fail("NRM-UNSUPPORTED")
    class Target:
        def __init__(self):
            self.nesting = depth
            self.pending = []
            self.combined = []

        def flush(self):
            ctx.emit("".join(self.pending), locator + "/xml-text")
            self.pending = []

        def start(self, tag, attrs):
            self.flush()
            self.nesting += 1
            ctx.node(self.nesting)
            ctx.emit(tag, locator + "/xml-tag")
            for key, value in attrs.items():
                ctx.node(self.nesting + 1)
                ctx.emit(key, locator + "/xml-attribute-name")
                ctx.emit(value, locator + "/xml-attribute")

        def end(self, tag):
            self.flush()
            self.nesting -= 1

        def data(self, value):
            self.pending.append(value)
            self.combined.append(value)

        def close(self):
            self.flush()
            ctx.emit("".join(self.combined), locator + "/xml-combined-text")
            return None

    parser = ElementTree.XMLParser(target=Target())
    for offset in range(0, len(text), 4096):
        parser.feed(text[offset:offset + 4096])
    parser.close()


class InspectionHTML(HTMLParser):
    def __init__(self, ctx, locator, depth):
        super().__init__(convert_charrefs=True)
        self.ctx, self.locator, self.depth = ctx, locator, depth
        self.stack = []
        self.combined = []

    def handle_starttag(self, tag, attrs):
        self.ctx.node(self.depth + len(self.stack) + 1)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input",
                       "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(tag)
        self.ctx.emit(tag, self.locator + "/html-tag")
        for key, value in attrs:
            self.ctx.node(self.depth + 1)
            self.ctx.emit(key, self.locator + "/html-attribute-name")
            self.ctx.emit(value or "", self.locator + "/html-attribute")

    def handle_startendtag(self, tag, attrs):
        before = len(self.stack)
        self.handle_starttag(tag, attrs)
        del self.stack[before:]

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            fail("NRM-AMBIGUOUS")

    def close(self):
        super().close()
        if self.stack:
            fail("NRM-AMBIGUOUS")
        self.ctx.emit("".join(self.combined), self.locator + "/html-combined-text")

    def handle_data(self, data):
        self.combined.append(data)
        self.ctx.node(self.depth + 1)
        self.ctx.emit(data, self.locator + "/html-data")

    def handle_comment(self, data):
        self.ctx.node(self.depth + 1)
        self.ctx.emit(data, self.locator + "/html-comment")


def parse_structured(ctx, text, media, locator, depth):
    if media == "application/json":
        _json(ctx, text, locator, depth)
    elif media in {"application/xml", "text/xml"}:
        _xml(ctx, text, locator, depth)
    elif media == "text/html":
        # A whole decoded syntax view also preserves escaped markup/metadata
        # that forgiving HTML tokenization could otherwise leave uninterpreted.
        ctx.emit(unescape(text), locator + "/html-decoded-source")
        parser = InspectionHTML(ctx, locator, depth)
        parser.feed(text)
        parser.close()
    elif media == "text/csv":
        # Per-worker setting: the process handles one root request only.
        csv.field_size_limit(ctx.budget["input_bytes"])
        for row in csv.reader(io.StringIO(text, newline=""), strict=True):
            ctx.node(depth + 1)
            for field in row:
                ctx.node(depth + 1)
                ctx.emit(field, locator + "/csv-field")
