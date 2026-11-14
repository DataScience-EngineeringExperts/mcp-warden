"""Bounded CommonMark token evidence; no rendering, fetching or plugins."""
from importlib.metadata import version

from formats import fail
from formats_structured import InspectionHTML

PINS = {"markdown-it-py": "4.3.0", "mdurl": "0.1.2"}
CONTAINERS = {"blockquote", "bullet_list", "ordered_list", "list_item", "paragraph",
              "heading", "em", "strong", "link"}
LEAVES = {"text", "code_inline", "code_block", "fence", "softbreak", "hardbreak",
          "html_inline", "html_block", "image", "inline", "hr"}


def parse_markdown(ctx, text, locator, depth):
    """Inspect semantic tokens and metadata while preserving the source view."""
    from markdown_it import MarkdownIt
    from markdown_it.common.utils import unescapeAll
    if any(version(name) != expected for name, expected in PINS.items()):
        fail("NRM-RUNTIME")
    # The parser's internal cap may discard a deeply nested tail. Set it above
    # our rejecting token-depth limit: an ancestor must exceed our cap first.
    parser = MarkdownIt("commonmark", {"maxNesting": ctx.budget["depth"] + 2})
    environment = {}
    tokens = parser.parse(text, environment)
    combined = []
    html = InspectionHTML(ctx, locator + "/markdown-html", depth)

    def visit(items, base):
        for token in items:
            ctx.node(base + token.level)
            kind = token.type
            if kind not in LEAVES and not any(
                    kind == container + suffix for container in CONTAINERS
                    for suffix in ("_open", "_close")):
                fail("NRM-UNSUPPORTED")
            for key, value in token.attrs.items():
                if type(key) is not str or type(value) is not str:
                    fail("NRM-UNSUPPORTED")
                ctx.node(base + token.level)
                ctx.emit(key, locator + "/markdown-attribute-name")
                ctx.emit(value, locator + "/markdown-attribute")
            if token.info:
                ctx.emit(token.info, locator + "/markdown-info-raw")
                ctx.emit(unescapeAll(token.info), locator + "/markdown-info-decoded")
            if kind in {"html_inline", "html_block"}:
                ctx.emit(token.content, locator + "/markdown-html-source")
                before = len(html.combined)
                html.feed(token.content)
                combined.extend(html.combined[before:])
            elif kind in {"softbreak", "hardbreak"}:
                combined.append("\n")
                ctx.emit("\n", locator + "/markdown-break")
            elif token.children is not None:
                visit(token.children, base + token.level)
            elif kind in {"text", "code_inline", "code_block", "fence"}:
                # CommonMark decodes text escapes/entities but intentionally
                # preserves literal escape syntax in code tokens.
                ctx.emit(token.content, locator + "/markdown-token:" + kind)
                combined.append(token.content)
            elif token.content:
                fail("NRM-UNSUPPORTED")
    visit(tokens, depth)
    before = len(html.combined)
    html.close()
    combined.extend(html.combined[before:])
    ctx.emit("".join(combined), locator + "/markdown-combined-text")

    if set(environment) - {"references", "duplicate_refs"}:
        fail("NRM-UNSUPPORTED")
    definitions = list(environment.get("references", {}).items())
    definitions.extend((entry["label"], entry) for entry in environment.get("duplicate_refs", []))
    for label, definition in definitions:
        ctx.node(depth + 1)
        ctx.emit(label, locator + "/markdown-reference-label")
        for key, value in definition.items():
            if key == "map":
                continue
            if type(value) is not str:
                fail("NRM-UNSUPPORTED")
            ctx.emit(value, locator + "/markdown-reference:" + key)
