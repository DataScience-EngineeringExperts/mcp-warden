"""Bounded strict trace loading for universal inspection only."""

import io
import struct
from pathlib import Path

from .normalization_ipc import MAX_FRAME, MAX_MESSAGE, NormalizationError, decode_message


def load_universal_records(path) -> list[dict]:
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_MESSAGE + 1)
        if len(data) > MAX_MESSAGE:
            raise NormalizationError("NRM-OVER-CAP")
        stream, records = io.BytesIO(data), []
        for _ in range(4096):
            line = stream.readline(16 * 1024 * 1024 + 1)
            if not line:
                return records
            if len(line) > 16 * 1024 * 1024:
                raise NormalizationError("NRM-OVER-CAP")
            if not line.strip():
                continue
            framed = b"".join(struct.pack(">I", len(chunk)) + chunk
                              for i in range(0, len(line), MAX_FRAME)
                              if (chunk := line[i:i + MAX_FRAME])) + b"\0\0\0\0"
            record = decode_message(framed)
            if (record.keys() != {"direction", "frame"} or type(record["frame"]) is not dict
                    or record["direction"] not in ("s2c", "c2s")):
                raise NormalizationError("NRM-PROTOCOL")
            records.append(record)
        if stream.read(1):
            raise NormalizationError("NRM-OVER-CAP")
        return records
    except NormalizationError:
        raise
    except Exception:
        raise NormalizationError("NRM-PROTOCOL") from None
