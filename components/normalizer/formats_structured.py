"""Strict structured formats retain source syntax and decoded inspection views."""
import csv
import io
import json
import re
from html.parser import HTMLParser
from xml.etree import ElementTree

from formats import fail


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

    def visit(value, nesting):
        ctx.node(nesting)
        if isinstance(value, dict):
            for key, item in value.items():
                ctx.node(nesting + 1)
                ctx.emit(key, locator + "/json-key")
                visit(item, nesting + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, nesting + 1)
        elif isinstance(value, str):
            ctx.emit(value, locator + "/json-string")
    visit(obj, depth)


def _xml(ctx, text, locator, depth):
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        fail("NRM-UNSUPPORTED")
    # Expat builds only one bounded subtree at a time through a pull parser.
    parser = ElementTree.XMLPullParser(events=("start", "end"))
    nesting = depth
    for offset in range(0, len(text), 4096):
        parser.feed(text[offset:offset + 4096])
        for event, element in parser.read_events():
            if event == "start":
                nesting += 1
                ctx.node(nesting)
                ctx.emit(element.tag, locator + "/xml-tag")
                for key, value in element.attrib.items():
                    ctx.node(nesting + 1)
                    ctx.emit(key, locator + "/xml-attribute-name")
                    ctx.emit(value, locator + "/xml-attribute")
            else:
                ctx.emit(element.text or "", locator + "/xml-text")
                ctx.emit(element.tail or "", locator + "/xml-tail")
                nesting -= 1
                element.clear()
    parser.close()


class InspectionHTML(HTMLParser):
    def __init__(self, ctx, locator, depth):
        super().__init__(convert_charrefs=True)
        self.ctx, self.locator, self.depth = ctx, locator, depth

    def handle_starttag(self, tag, attrs):
        self.ctx.node(self.depth + 1)
        self.ctx.emit(tag, self.locator + "/html-tag")
        for key, value in attrs:
            self.ctx.node(self.depth + 1)
            self.ctx.emit(key, self.locator + "/html-attribute-name")
            self.ctx.emit(value or "", self.locator + "/html-attribute")

    handle_startendtag = handle_starttag

    def handle_data(self, data):
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
