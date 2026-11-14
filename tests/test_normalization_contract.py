"""Framing/profile negative vectors before any parser execution."""

import io
import struct

import pytest

from mcp_warden.normalization_ipc import (
    MAX_FRAME,
    NormalizationError,
    decode_message,
    encode_message,
    read_message,
)
from mcp_warden.normalization_models import NormalizationBudgetV1, NormalizationProfileV1


def test_profile_has_finite_positive_non_boolean_limits():
    for value in (True, 0, -1, 9, 1.0, "8"):
        with pytest.raises(NormalizationError):
            NormalizationBudgetV1(depth=value)
    with pytest.raises(NormalizationError):
        NormalizationProfileV1("latest")


def test_frame_roundtrip_multiframe_and_unicode():
    value = {"data": "é" * MAX_FRAME}
    assert decode_message(encode_message(value)) == value


@pytest.mark.parametrize("data", [b"", b"\0", b"\0\0\0\0", encode_message({}) + b"x",
                                 struct.pack(">I", MAX_FRAME + 1)])
def test_framing_rejects_truncation_trailing_and_oversize(data):
    with pytest.raises(NormalizationError):
        read_message(io.BytesIO(data))


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'{"x":"\xff"}',
                                b'{"x":' + b'['*40 + b'0' + b']'*40 + b'}'])
def test_wire_rejects_non_object_duplicates_constants_utf8_and_depth(raw):
    with pytest.raises(NormalizationError):
        decode_message(struct.pack(">I", len(raw)) + raw + b"\0\0\0\0")
