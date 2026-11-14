"""Conservative text PDF profile; uncertain extraction is a refusal."""
import io
import zlib

from formats import fail

ACTIVE = frozenset({"/A", "/AA", "/JS", "/JavaScript", "/OpenAction", "/EmbeddedFiles",
                    "/EmbeddedFile", "/AcroForm", "/XFA", "/RichMedia", "/Launch",
                    "/GoToR", "/SubmitForm", "/ImportData", "/Sound", "/Movie",
                    "/Collection", "/OCProperties", "/AF", "/Metadata"})


def parse_pdf(ctx, data, locator, depth):
    import pypdf
    from pypdf.generic import (ArrayObject, ByteStringObject, DictionaryObject,
                               IndirectObject, StreamObject, TextStringObject)
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
            # Reuse bounded decoded bytes; extraction must not inflate them again.
            obj._data = decoded
            if "/Filter" in obj:
                del obj["/Filter"]
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
        text = page.extract_text()
        if not text or not text.strip():
            fail("NRM-EMPTY")
        ctx.emit(text, locator + f"/page:{index + 1}")
