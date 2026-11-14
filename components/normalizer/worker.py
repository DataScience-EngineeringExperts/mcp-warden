"""One-request isolated parser entrypoint; stdout is framed protocol only."""
from __future__ import annotations

import base64
import hashlib
import logging
import sys
import unicodedata
from pathlib import Path

# Python -I excludes the script directory; only this immutable image directory
# is added. No caller path, environment entry or package discovery is consulted.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from formats import CEILINGS, PROFILE, Context, fail  # noqa: E402
from normalization_ipc import NormalizationError, encode_message, read_message  # noqa: E402


def process(request):
    """Return an atomic bounded extraction or an input-free refusal."""
    try:
        if (type(request) is not dict or set(request) != {
                "schema_version", "profile_id", "content_b64", "media_type", "budget"}
                or type(request["schema_version"]) is not int or request["schema_version"] != 1
                or request["profile_id"] != PROFILE or type(request["media_type"]) is not str
                or type(request["content_b64"]) is not str):
            fail("NRM-PROTOCOL")
        if sys.version_info[:2] != (3, 12) or unicodedata.unidata_version != "15.0.0":
            fail("NRM-RUNTIME")
        if len(request["content_b64"]) > ((CEILINGS["input_bytes"] + 2) // 3) * 4:
            fail("NRM-OVER-CAP")
        raw = base64.b64decode(request["content_b64"], validate=True)
        if base64.b64encode(raw).decode("ascii") != request["content_b64"]:
            fail("NRM-PROTOCOL")
        ctx = Context(raw, request["budget"])
        ctx.parse(raw, request["media_type"])
        if not ctx.segments:
            fail("NRM-EMPTY")
        return dict(schema_version=1, status="structurally-complete", profile_id=PROFILE,
                    input_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
                    runtime={"python": "3.12", "unicode": "15.0.0", "parser": "pypdf==7.1.0"},
                    segments=ctx.segments, usage=ctx.usage)
    except NormalizationError as exc:
        return {"schema_version": 1, "status": "refused", "code": exc.code}
    except Exception:
        return {"schema_version": 1, "status": "refused", "code": "NRM-MALFORMED"}


def main():
    logging.disable(logging.CRITICAL)
    try:
        result = process(read_message(sys.stdin.buffer))
    except NormalizationError as exc:
        result = {"schema_version": 1, "status": "refused", "code": exc.code}
    except Exception:
        result = {"schema_version": 1, "status": "refused", "code": "NRM-PROTOCOL"}
    try:
        sys.stdout.buffer.write(encode_message(result))
        sys.stdout.buffer.flush()
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
