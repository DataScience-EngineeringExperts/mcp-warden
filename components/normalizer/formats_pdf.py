"""Conservative text PDF profile; uncertain extraction is a refusal."""
import io
import zlib

from formats import fail

ACTIVE = frozenset({"/A", "/AA", "/JS", "/JavaScript", "/OpenAction", "/EmbeddedFiles",
                    "/EmbeddedFile", "/AcroForm", "/XFA", "/RichMedia", "/Launch",
                    "/GoToR", "/SubmitForm", "/ImportData", "/Sound", "/Movie",
                    "/Collection", "/OCProperties", "/AF", "/Metadata", "/FontFile",
                    "/FontFile2", "/FontFile3", "/CharProcs"})


def parse_pdf(ctx, data, locator, depth):
    import pypdf
    from pypdf.generic import (
        ArrayObject,
        ByteStringObject,
        ContentStream,
        DecodedStreamObject,
        DictionaryObject,
        EncodedStreamObject,
        IndirectObject,
        StreamObject,
        TextStringObject,
    )
    if pypdf.__version__ != "7.1.0":
        fail("NRM-RUNTIME")
    if not data.startswith(b"%PDF-") or not data.rstrip().endswith(b"%%EOF"):
        fail()
    reader = pypdf.PdfReader(io.BytesIO(data), strict=True)
    if reader.is_encrypted:
        fail("NRM-ENCRYPTED")
    if reader.xref_objStm:
        # Compressed object streams cannot be charged before pypdf inflates them.
        fail("NRM-UNSUPPORTED")
    visited = set()

    def inspect(obj, nesting):
        if isinstance(obj, IndirectObject):
            ident = (obj.idnum, obj.generation)
            if ident in visited:
                return
            visited.add(ident)
            obj = obj.get_object()
        ctx.node(nesting)
        if isinstance(obj, StreamObject):
            filters = obj.get("/Filter", [])
            filters = [filters] if isinstance(filters, str) else filters
            if list(filters) not in [[], ["/FlateDecode"]] or obj.get("/DecodeParms"):
                fail("NRM-UNSUPPORTED")
            encoded = obj._data
            if filters:
                decoder = zlib.decompressobj()
                cap = ctx.budget["expanded_bytes"] - ctx.usage["expanded_bytes"]
                decoded = decoder.decompress(encoded, cap + 1)
                if len(decoded) > cap or decoder.unconsumed_tail or not decoder.eof or decoder.unused_data:
                    fail("NRM-OVER-CAP")
            else:
                decoded = encoded
            ctx.charge("expanded_bytes", len(decoded))
            ctx.charge("work", len(encoded) + len(decoded))
            try:
                ctx.emit(decoded.decode("utf-8", "strict"), locator + "/pdf-stream-source")
            except UnicodeError:
                fail("NRM-UNSUPPORTED")
            # Reuse bounded decoded bytes; extraction must not inflate them again.
            if isinstance(obj, EncodedStreamObject):
                bounded = DecodedStreamObject()
                bounded.set_data(decoded)
                obj.decoded_self = bounded
            if obj.get("/Subtype") in {"/Image", "/Form"}:
                fail("NRM-UNSUPPORTED")
        if isinstance(obj, DictionaryObject):
            for key, value in obj.items():
                if key in ACTIVE:
                    fail("NRM-UNSUPPORTED")
                ctx.emit(str(key), locator + "/pdf-key")
                inspect(value, nesting + 1)
        elif isinstance(obj, ArrayObject):
            for value in obj:
                inspect(value, nesting + 1)
        elif isinstance(obj, TextStringObject):
            ctx.emit(str(obj), locator + "/pdf-string")
        elif isinstance(obj, ByteStringObject):
            fail("NRM-UNSUPPORTED")
    # Inspect all cross-reference objects, including unreachable string evidence.
    for generation, objects in sorted(reader.xref.items()):
        if generation == 65535:
            continue
        for number in sorted(objects):
            if number:
                inspect(IndirectObject(number, generation, reader), depth)
    inspect(reader.trailer, depth)
    if not reader.pages:
        fail("NRM-EMPTY")
    for index, page in enumerate(reader.pages):
        ctx.node(depth + 1)
        allowed = {b"q", b"Q", b"cm", b"BT", b"ET", b"Td", b"TD", b"Tm", b"T*",
                   b"Tf", b"Tj", b"TJ", b"'", b'"', b"Tc", b"Tw", b"Tz", b"TL",
                   b"Tr", b"Ts", b"rg", b"RG", b"g", b"G", b"k", b"K", b"w",
                   b"d", b"J", b"j", b"M", b"m", b"l", b"c", b"v", b"y", b"h",
                   b"re", b"S", b"s", b"f", b"F", b"f*", b"B", b"B*", b"b",
                   b"b*", b"n", b"W", b"W*", b"BMC", b"BDC", b"EMC", b"MP", b"DP"}
        stream = ContentStream(page.get("/Contents"), reader)
        for _operands, operator in stream.operations:
            ctx.charge("work", 1)
            if operator not in allowed:
                fail("NRM-UNSUPPORTED")
        missing_font = False

        def text_visitor(text, cm, tm, font, size):
            nonlocal missing_font
            if text.strip() and font is None:
                missing_font = True

        text = page.extract_text(visitor_text=text_visitor)
        if missing_font or "\ufffd" in text:
            fail("NRM-AMBIGUOUS")
        if not text or not text.strip():
            fail("NRM-EMPTY")
        ctx.emit(text, locator + f"/page:{index + 1}")
