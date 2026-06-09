"""Property-based fuzzing of the stdio JSON-RPC framer (issue #17, binding #1).

The framer is the live runtime attack surface: a parse_error Frame is the VISIBLE
fail-open signal (the guard forwards it), so the security invariant is that a frame
is NEVER silently both-empty and a real JSON object is NEVER misclassified as a
parse_error (a silent drop). Properties here are construction-based with explicit
liveness ("a real object IS recovered", "a known-malformed length IS rejected")
and soundness ("never raises", "never negative", "modes agree").
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, assume, example, given, settings
from hypothesis import strategies as st

from mcp_warden.framing import (
    MODE_CONTENT_LENGTH,
    MODE_NEWLINE,
    Frame,
    FrameReader,
    _parse_content_length,
    _parse_frame,
    serialize_frame,
)

# --- strategies ---------------------------------------------------------------

# JSON-RPC-ish object values: scalars + shallow containers, JSON-serializable.
_json_scalars = st.none() | st.booleans() | st.integers() | st.text()
_json_values = st.recursive(
    _json_scalars,
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=8,
)
# A top-level JSON OBJECT (dict) — the only body shape the framer accepts as json.
json_objects = st.dictionaries(st.text(max_size=12), _json_values, max_size=6)


def _obj_bytes(obj: dict) -> bytes:
    """Serialize a JSON object to compact wire body bytes (as the framer emits)."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class _ChunkFeeder:
    """An async ``receive()`` yielding preset byte chunks, then EOF (``b""``).

    Each call pops one chunk; once exhausted every further call returns ``b""``
    (clean EOF), exactly like an anyio stream after the peer closes. Bounded by
    construction, so ``read_frame`` cannot hang on it.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    async def receive(self) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


def _xor_invariant(frame: Frame) -> bool:
    """Exactly one of {json set} / {parse_error non-empty} holds."""
    has_json = frame.json is not None
    has_error = frame.parse_error != ""
    return has_json != has_error  # XOR


# --- _parse_frame: XOR + never-raises (binding #1) ----------------------------


@given(raw=st.binary(max_size=256), body=st.binary(max_size=256))
def test_parse_frame_xor_never_raises(raw: bytes, body: bytes) -> None:
    """For ANY bytes, _parse_frame returns a Frame with the XOR invariant.

    A null/array/non-object/garbage body legitimately yields parse_error — that
    is the CORRECT fail-open signal, not a failure. The property is only that the
    Frame is never both-empty and never raises.
    """
    frame = _parse_frame(raw, body)
    assert isinstance(frame, Frame)
    assert _xor_invariant(frame)
    if frame.json is not None:
        assert isinstance(frame.json, dict)


@given(body=st.binary(max_size=256))
def test_parse_frame_non_object_is_parse_error(body: bytes) -> None:
    """A body that decodes to valid JSON but is NOT an object => parse_error."""
    try:
        decoded = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        assume(False)
        return
    assume(not isinstance(decoded, dict))
    frame = _parse_frame(b"", body)
    assert frame.json is None and frame.parse_error != ""


# --- LIVENESS / anti-bypass: a real JSON object is NEVER misclassified ---------


@given(obj=json_objects)
@example(obj={})
@example(obj={"jsonrpc": "2.0", "id": 1, "method": "tools/call"})
def test_real_object_body_is_recovered(obj: dict) -> None:
    """If body IS valid JSON-object bytes, json MUST be set (no false drop)."""
    frame = _parse_frame(b"", _obj_bytes(obj))
    assert frame.parse_error == ""
    assert frame.json == obj


# --- _parse_content_length: int|None, never raises, never negative ------------
#
# Finding A (issue #17 log): the live code accepted `-5` (NEGATIVE length that
# mis-slices the body), `1_000`, `+5`, unicode digits, etc. Fixed to require
# ASCII `^[0-9]+$`. The frozen @examples below pin that regression permanently.


# A generous bound for the unit tests of _parse_content_length: large enough that
# legitimate small lengths pass, small enough that 2**63 is rejected (B2).
_CL_MAX = 1 << 20


@given(header=st.binary(max_size=128))
def test_parse_content_length_int_or_none_never_negative(header: bytes) -> None:
    """For ANY header bytes: returns int|None, never raises, never negative."""
    out = _parse_content_length(header, _CL_MAX)
    assert out is None or (isinstance(out, int) and 0 <= out <= _CL_MAX)


def _oracle_cl(header: bytes, bound: int) -> int | None:
    """Independent reference for the hardened _parse_content_length contract.

    Mirrors the spec (B1 single-valid-only, B2 bound, B9 leading-zero) WITHOUT
    reusing the implementation, so the property is a real cross-check:
    accept iff there is EXACTLY ONE Content-Length header AND its stripped value
    is an ASCII-digit run AND (value == "0" or no leading zero) AND int <= bound.
    """
    prefix = b"content-length:"
    vals = [
        line[len(prefix) :].strip()
        for line in header.split(b"\r\n")
        if line[: len(prefix)].lower() == prefix
    ]
    if len(vals) != 1:
        return None
    v = vals[0]
    if not v.isdigit():
        return None
    if len(v) > 1 and v[:1] == b"0":  # leading zero (B9)
        return None
    n = int(v)
    return n if n <= bound else None


@example(b"Content-Length: -5")  # Finding A: negative must be rejected
@example(b"Content-Length: +5")  # signed must be rejected
@example(b"Content-Length: 1_000")  # underscores must be rejected
@example(b"Content-Length: 0")  # zero is valid
@example(b"Content-Length: 42")  # plain digits valid
@example(b"Content-Length: 007")  # B9: leading zeros rejected
@example(b"Content-Length: 5\r\nContent-Length: 5")  # B1: duplicate (even equal) rejected
@example(b"Content-Length: x\r\nContent-Length: 5")  # B1: malformed-first + valid-second rejected
@example(b"Content-Length: 5\r\nContent-Length: 9")  # B1: two different values rejected
@example(b"Content-Length: " + str(2**63).encode())  # B2: absurd length rejected, no hang
@example(b"Content-Length: 16")  # single valid within bound: accepted
@given(
    header=st.one_of(
        st.binary(max_size=128),
        # Construct realistic-looking headers with adversarial length tokens.
        st.builds(
            lambda tok: b"Content-Length: " + tok,
            st.sampled_from(
                [b"-1", b"-999", b"+7", b" 5 ", b"1_2", b"0x10", b"abc", b"", b"5\t", b"  3", b"007"]
            ),
        ),
        st.builds(lambda n: b"Content-Length: " + str(n).encode(), st.integers(min_value=0, max_value=10**9)),
        # B1: build multi-Content-Length headers (duplicate / malformed+valid).
        st.builds(
            lambda a, b: b"Content-Length: " + a + b"\r\nContent-Length: " + b,
            st.sampled_from([b"5", b"9", b"x", b"-1", b"007"]),
            st.sampled_from([b"5", b"9", b"x", b"-1", b"007"]),
        ),
    )
)
def test_parse_content_length_rejects_nonconformant(header: bytes) -> None:
    """Single-valid-only + bounded: the impl agrees with an independent oracle.

    Liveness for the soundness fix: a known-bad ``-5`` is REJECTED (None), a
    duplicate Content-Length (B1) is REJECTED, an absurd ``2**63`` (B2) is
    REJECTED, and a lone in-bound digit run is accepted as exactly that integer.
    """
    out = _parse_content_length(header, _CL_MAX)
    assert out is None or (isinstance(out, int) and 0 <= out <= _CL_MAX)
    assert out == _oracle_cl(header, _CL_MAX)


def test_parse_content_length_absurd_value_returns_promptly() -> None:
    """B2 regression: a 2**63 declared length is rejected (None), never a hang.

    Asserts the parse returns promptly (no attempt to bound/allocate the value)
    and yields None so the framer surfaces a visible parse_error fail-open rather
    than blocking on a body that can never arrive.
    """
    import time

    header = b"Content-Length: " + str(2**63).encode()
    start = time.monotonic()
    out = _parse_content_length(header, _CL_MAX)
    assert out is None
    assert time.monotonic() - start < 1.0


# --- read_frame: never raises, never hangs, XOR on non-EOF (binding #1) --------


async def _read_all(reader: FrameReader) -> list[Frame]:
    frames: list[Frame] = []
    # Hard cap on iterations: the feeder is finite + EOF-terminating, so a
    # correct reader drains in O(bytes). The cap turns any HANG into a fast fail.
    for _ in range(10_000):
        f = await reader.read_frame()
        if f is None:
            break
        frames.append(f)
    else:  # pragma: no cover - only hit if read_frame fails to terminate
        raise AssertionError("read_frame did not reach EOF within the iteration cap")
    return frames


@settings(suppress_health_check=[HealthCheck.too_slow])
@given(chunks=st.lists(st.binary(max_size=64), max_size=16))
async def test_read_frame_never_raises_or_hangs(chunks: list[bytes]) -> None:
    """Over arbitrary chunked bytes: returns Frame|None, never raises, terminates.

    Every non-EOF Frame satisfies the XOR invariant.
    """
    reader = FrameReader(_ChunkFeeder(chunks).receive, max_frame_bytes=1 << 16)
    frames = await _read_all(reader)
    for f in frames:
        assert isinstance(f, Frame)
        assert _xor_invariant(f)


# --- mode-equivalence: CL serialization and newline serialization agree --------


@given(obj=json_objects)
@example(obj={"id": 7, "method": "tools/list"})
async def test_mode_equivalence_cl_vs_newline(obj: dict) -> None:
    """A well-formed object round-trips IDENTICALLY through both framing modes.

    The Frame parsed from its Content-Length serialization and from its newline
    serialization recover the same ``json`` (no mode-confusion divergence).
    """
    cl_wire = serialize_frame(obj, MODE_CONTENT_LENGTH)
    nl_wire = serialize_frame(obj, MODE_NEWLINE)

    cl_reader = FrameReader(_ChunkFeeder([cl_wire]).receive, max_frame_bytes=1 << 20)
    nl_reader = FrameReader(_ChunkFeeder([nl_wire]).receive, max_frame_bytes=1 << 20)

    cl_frames = await _read_all(cl_reader)
    nl_frames = await _read_all(nl_reader)

    assert cl_reader.mode == MODE_CONTENT_LENGTH
    assert nl_reader.mode == MODE_NEWLINE
    assert len(cl_frames) == 1 and len(nl_frames) == 1
    assert cl_frames[0].json == obj
    assert nl_frames[0].json == obj
    assert cl_frames[0].json == nl_frames[0].json


# --- truncation: a body short of its declared Content-Length => parse_error ----


@given(obj=json_objects, missing=st.integers(min_value=1, max_value=64))
@example(obj={"id": 1}, missing=1)
async def test_truncated_body_yields_parse_error_not_json(obj: dict, missing: int) -> None:
    """A Content-Length frame whose body is shorter than declared => parse_error.

    NEVER a semantically-different ``json`` Frame. This is the security-relevant
    direction: a truncated body must surface as the visible fail-open signal, not
    a silently re-interpreted object.
    """
    body = _obj_bytes(obj)
    assume(len(body) >= 1)
    cut = min(missing, len(body))
    truncated_body = body[: len(body) - cut]
    # Declare the FULL length but only feed the truncated body, then EOF.
    wire = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + truncated_body
    reader = FrameReader(_ChunkFeeder([wire]).receive, max_frame_bytes=1 << 20)
    frames = await _read_all(reader)
    # Exactly one frame, and it must be a parse_error (truncated body at EOF),
    # never a recovered json object.
    assert len(frames) == 1
    assert frames[0].json is None
    assert frames[0].parse_error != ""


# --- COMPOSITION (binding #7): re-serialized Content-Length is never a lie ------
#
# The guard's s2c redact path (wire_block.redacted_result) strips ANSI / redacts
# secrets IN PLACE in a result, then re-serializes the modified frame. A redaction
# CHANGES the body length, so the emitted Content-Length header MUST reflect the
# post-transform body — a stale/lying length would desync the client framer.
# serialize_frame computes the header from the actual bytes, so this property
# pins that the whole pipeline (transform -> serialize -> re-parse) is
# length-consistent and round-trips, after a body-mutating transform.


@st.composite
def result_frame_with_ansi(draw):
    """Build a JSON-RPC tools/call response whose text blocks may carry ANSI."""
    n_blocks = draw(st.integers(min_value=0, max_value=3))
    blocks = []
    for _ in range(n_blocks):
        # Allowed text plus possibly-spliced disallowed control codepoints.
        # B4 (issue #17 audit): exercise the FULL disallowed set, not just the 4
        # C0/DEL points — add the C1 control range (0x80-0x9F) and the Unicode
        # line/paragraph separators U+2028/U+2029 so the Content-Length /
        # pipeline composition property sees every codepoint the ANSI rule strips.
        base = draw(st.text(max_size=20))
        bad = draw(
            st.lists(
                st.sampled_from(
                    [0x1B, 0x07, 0x00, 0x7F]  # ESC / BEL / NUL / DEL
                    + list(range(0x80, 0xA0))  # C1 controls
                    + [0x2028, 0x2029]  # line / paragraph separator
                ),
                max_size=3,
            )
        )
        chars = list(base)
        for cp in bad:
            chars.insert(draw(st.integers(min_value=0, max_value=len(chars))), chr(cp))
        blocks.append({"type": "text", "text": "".join(chars)})
    rpc_id = draw(st.integers(min_value=0, max_value=10_000))
    return {"jsonrpc": "2.0", "id": rpc_id, "result": {"content": blocks}}


@given(frame_obj=result_frame_with_ansi())
@example(
    frame_obj={
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": "hi\x1b[31mred\x1b[0m"}]},
    }
)
async def test_redact_pipeline_content_length_is_consistent(frame_obj: dict) -> None:
    """ANSI-strip a result frame, re-serialize, and the Content-Length is honest.

    Runs the ACTUAL guard s2c redact transform (wire_block.redacted_result with
    the ANSI finding), then re-serializes via serialize_frame and re-parses with
    FrameReader. Asserts: (1) the declared Content-Length equals the real body
    byte length AFTER the transform, and (2) the re-parsed object equals the
    transformed object (no desync). A redaction that shortened the body but kept
    a stale length would fail (1); a serialize bug would fail (2).
    """
    from mcp_warden.result_inspection import InspectionPolicy, ResultFinding
    from mcp_warden.wire_block import redacted_result

    original_result = frame_obj["result"]
    policy = InspectionPolicy(expected_output_charset="text")
    ansi_finding = ResultFinding(
        rule_id="WRD-RES-ANSI", severity="high", tier="block", message="ansi", block_index=0
    )
    # Apply the real transform (strips disallowed codepoints from text blocks).
    transformed = redacted_result(
        frame_obj["id"], original_result, [ansi_finding], policy, redact_secret_echo=False
    )

    wire = serialize_frame(transformed, MODE_CONTENT_LENGTH)

    # (1) The declared Content-Length equals the ACTUAL serialized body length.
    sep = wire.find(b"\r\n\r\n")
    assert sep != -1
    declared = _parse_content_length(wire[:sep], 1 << 20)
    actual_body = wire[sep + 4 :]
    assert declared is not None
    assert declared == len(actual_body), "emitted Content-Length must match the post-transform body"

    # (2) Re-parsing the re-serialized frame recovers the transformed object.
    reader = FrameReader(_ChunkFeeder([wire]).receive, max_frame_bytes=1 << 20)
    frames = await _read_all(reader)
    assert len(frames) == 1
    assert frames[0].json == transformed
    # And after the strip, no disallowed codepoint survives in any text block.
    from mcp_warden import res_rules

    for block in frames[0].json["result"].get("content", []):
        if block.get("type") == "text":
            assert res_rules.find_ansi_codepoints(block["text"], "text") == []
