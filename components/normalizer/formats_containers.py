"""No-filesystem ZIP and RFC822/MIME traversal with one aggregate ledger."""
import base64
import binascii
import io
import quopri
import re
import stat
import struct
import zipfile
from email import policy
from email.header import decode_header
from email.parser import BytesParser
from pathlib import PurePosixPath

from formats import SUPPORTED, decode, fail

SUFFIXES = {".txt": "text/plain", ".json": "application/json", ".xml": "application/xml",
            ".html": "text/html", ".htm": "text/html", ".md": "text/markdown",
            ".csv": "text/csv", ".eml": "message/rfc822", ".zip": "application/zip",
            ".pdf": "application/pdf"}


def select_media(data, filename):
    media = SUFFIXES.get(PurePosixPath(filename).suffix.lower())
    sniffed = ("application/pdf" if data.startswith(b"%PDF-") else
               "application/zip" if data.startswith((b"PK\x03\x04", b"PK\x05\x06")) else None)
    if sniffed and media and sniffed != media:
        fail("NRM-AMBIGUOUS")
    if not media and not sniffed:
        fail("NRM-UNSUPPORTED")
    return sniffed or media


def parse_zip(ctx, data, locator, depth):
    if not data.startswith(b"PK\x03\x04"):
        fail("NRM-EMPTY")
    with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
        entries = archive.infolist()
        if not entries:
            fail("NRM-EMPTY")
        seen = set()
        if data[-22-len(archive.comment):][:4] != b"PK\x05\x06":
            fail("NRM-UNSUPPORTED")
        cursor = 0
        ctx.emit(decode(archive.comment), locator + "/zip-comment")
        for entry in entries:
            if entry.header_offset != cursor or len(data) < cursor + 30:
                fail("NRM-AMBIGUOUS")
            local = struct.unpack("<4s5H3I2H", data[cursor:cursor + 30])
            signature, _, flags, compression, _, _, crc, size, expanded, name_len, extra_len = local
            if (signature != b"PK\x03\x04" or flags & 8 or extra_len or entry.extra
                    or crc != entry.CRC or size != entry.compress_size or expanded != entry.file_size
                    or compression != entry.compress_type):
                fail("NRM-UNSUPPORTED")
            cursor += 30 + name_len + size
            if cursor > archive.start_dir:
                fail()
            name = entry.filename
            parts = name.split("/")
            if (not name or name.startswith("/") or "\\" in name or ":" in name
                    or any(part in {"", ".", ".."} for part in parts)
                    or "\x00" in name or name in seen or entry.orig_filename != name
                    or entry.flag_bits & 1 or entry.is_dir()
                    or stat.S_ISLNK(entry.external_attr >> 16)
                    or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}):
                fail("NRM-UNSUPPORTED")
            seen.add(name)
            ctx.charge("members", 1)
            ctx.node(depth + 1)
            ctx.emit(name, locator + "/zip-member-name")
            ctx.emit(decode(entry.comment), locator + "/zip-member-comment")
            if entry.file_size <= 0 or entry.file_size > ctx.budget["expanded_bytes"] - ctx.usage["expanded_bytes"]:
                fail("NRM-OVER-CAP")
            chunks, count = [], 0
            with archive.open(entry, "r") as member:
                while chunk := member.read(min(65536, ctx.budget["expanded_bytes"] - ctx.usage["expanded_bytes"] + 1)):
                    ctx.charge("expanded_bytes", len(chunk))
                    ctx.charge("work", len(chunk))
                    count += len(chunk)
                    chunks.append(chunk)
            if count != entry.file_size:
                fail()
            payload = b"".join(chunks)
            ctx.parse(payload, select_media(payload, name), locator + "/zip:" + name, depth + 1)
        if cursor != archive.start_dir:
            fail("NRM-AMBIGUOUS")


def _header(value):
    result = []
    for part, charset in decode_header(value):
        result.append(decode(part, charset or "ascii") if isinstance(part, bytes) else part)
    return "".join(result)


def _payload(part):
    value = part.get_payload(decode=False)
    if type(value) is not str:
        fail()
    # surrogateescape recovers exact original octets from the stdlib email parser.
    data = value.encode("ascii", "surrogateescape")
    transfer = str(part.get("Content-Transfer-Encoding", "7bit")).lower().strip()
    if transfer == "base64":
        compact = re.sub(rb"[\r\n\t ]", b"", data)
        try:
            decoded = base64.b64decode(compact, validate=True)
        except (ValueError, binascii.Error):
            fail()
        if base64.b64encode(decoded) != compact:
            fail()
        return decoded
    if transfer == "quoted-printable":
        if re.search(rb"=(?![0-9a-fA-F]{2}|\r?\n)", data):
            fail()
        return quopri.decodestring(data)
    if transfer not in {"7bit", "8bit", "binary"}:
        fail("NRM-UNSUPPORTED")
    if transfer == "7bit" and any(byte > 127 for byte in data):
        fail()
    return data


def parse_email(ctx, data, locator, depth):
    message = BytesParser(policy=policy.default).parsebytes(data)
    if not list(message.raw_items()) or b"\n\n" not in data.replace(b"\r\n", b"\n"):
        fail()

    def visit(part, path, nesting):
        ctx.node(nesting)
        # The stdlib accepts duplicates and selects a first value without
        # reporting defects; that leaves transfer/type interpretation ambiguous.
        if any(len(part.get_all(header, [])) > 1 for header in (
                "Content-Type", "Content-Transfer-Encoding", "Content-Disposition", "MIME-Version")):
            fail("NRM-AMBIGUOUS")
        if part.defects:
            fail()
        for key, value in part.raw_items():
            ctx.node(nesting)
            ctx.emit(key + ": " + value, path + "/mime-header-raw")
            ctx.emit(_header(value), path + "/mime-header-decoded")
        for value in part.values():
            if getattr(value, "defects", ()):
                fail()
        media = part.get_content_type()
        if part.is_multipart():
            transfer = str(part.get("Content-Transfer-Encoding", "7bit")).lower().strip()
            if transfer not in {"7bit", "8bit", "binary"}:
                fail("NRM-UNSUPPORTED")
            if media == "message/rfc822" or part.get_content_maintype() == "multipart":
                ctx.emit(part.preamble or "", path + "/mime-preamble")
                ctx.emit(part.epilogue or "", path + "/mime-epilogue")
                children = part.get_payload()
                if not children:
                    fail("NRM-EMPTY")
                for index, child in enumerate(children):
                    ctx.charge("members", 1)
                    visit(child, path + f"/mime:{index}", nesting + 1)
                return
            fail("NRM-UNSUPPORTED")
        if media not in SUPPORTED:
            fail("NRM-UNSUPPORTED")
        payload = _payload(part)
        ctx.charge("expanded_bytes", len(payload))
        ctx.charge("work", len(payload))
        filename = part.get_filename()
        if filename:
            ctx.emit(filename, path + "/mime-filename")
            selected = select_media(payload, filename)
            if selected != media:
                fail("NRM-AMBIGUOUS")
        ctx.parse(payload, media, path + "/body", nesting + 1,
                  charset=part.get_content_charset() or "utf-8")
    visit(message, locator, depth)
