"""Closed serialization primitives shared only by the DSE-717 foundation."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import rfc8785
from pydantic import BaseModel, ConfigDict, model_validator

from mcp_warden.evidence_state import DIGEST_RE, MAX_COUNTER

MAX_CANONICAL_BYTES = 256 * 1024
ZERO_DIGEST = "sha256:" + "0" * 64


class ReceiptError(Exception):
    """Code-only error. Provider details are deliberately never retained."""

    def __init__(self, code: str):
        self.code = code if type(code) is str and code in ERROR_CODES else "RCT-INTERNAL-ERROR"
        super().__init__(self.code)

    def __repr__(self):
        return self.code


ERROR_CODES = frozenset(
    """RCT-INTERNAL-ERROR RCT-MALFORMED RCT-NONCANONICAL RCT-OVER-CAP
RCT-LIMIT-UNSUPPORTED RCT-EVENT-BINDING RCT-SIGNER-UNAUTHORIZED RCT-SIGNATURE-INVALID
RCT-AUTHORIZATION-UNAVAILABLE RCT-STALE RCT-INTEGRITY RCT-PROVIDER-UNAVAILABLE
RCT-TAIL-MISMATCH RCT-APPEND-FAILED RCT-STATE-COMMIT RCT-STORE-ALIAS RCT-RECOVERY-ONLY
RCT-LATCH-FAILED RCT-RECOVERY-AUTHORIZATION RULE-BUNDLE-MALFORMED RULE-OVERRIDE-INVALID
RULE-POLICY-MISMATCH RCT-REPLAY-MISMATCH RCT-UNSUPPORTED-PROTECTION""".split()
)


def receipt_digest(payload: bytes, domain: str) -> str:
    if (
        type(payload) is not bytes
        or type(domain) is not str
        or domain
        not in {
            "receipt",
            "signed-receipt",
            "authorization",
            "signature-frame",
            "rule",
            "override",
            "recovery",
            "governed-decision",
            "context",
            "evidence-result",
            "state",
            "fallback",
            "log-entry",
            "time",
            "invalid",
            "trust-root",
            "revocation",
            "latch",
            "replay",
        }
    ):
        raise ReceiptError("RCT-MALFORMED")
    return (
        "sha256:"
        + hashlib.sha256(b"mcp-warden/dse717/v1/" + domain.encode() + b"\x00" + payload).hexdigest()
    )


class ReceiptModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    def __init__(self, **data: Any):
        bad = False
        try:
            super().__init__(**data)
        except Exception:
            bad = True
        if bad:
            raise ReceiptError("RCT-MALFORMED") from None

    def __setattr__(self, name, value):
        raise ReceiptError("RCT-MALFORMED") from None

    def __delattr__(self, name):
        raise ReceiptError("RCT-MALFORMED") from None

    @model_validator(mode="after")
    def _closed_scalars(self):
        for name in type(self).model_fields:
            value = getattr(self, name)
            if value is None:
                continue
            if name.endswith("_digest") and (
                type(value) is not str or DIGEST_RE.fullmatch(value) is None
            ):
                raise ValueError("invalid digest")
            if (
                name.endswith("_generation")
                or name.endswith("_sequence")
                or name
                in {
                    "generation",
                    "sequence",
                    "trusted_time",
                    "valid_from",
                    "valid_until",
                    "expires_at",
                    "not_before",
                }
            ):
                if type(value) is not int or not 0 <= value <= MAX_COUNTER:
                    raise ValueError("invalid counter")
        return self


def exact(value: object, cls: type[BaseModel]) -> None:
    bad = type(value) is not cls
    if not bad:
        try:
            cls.model_validate(value)
        except Exception:
            bad = True
    if bad:
        raise ReceiptError("RCT-MALFORMED") from None


def canonical(value: object) -> bytes:
    bad = False
    result = None
    try:
        data = value.model_dump(mode="json") if isinstance(value, ReceiptModel) else value
        result = rfc8785.dumps(data)
    except Exception:
        bad = True
    if bad or type(result) is not bytes:
        raise ReceiptError("RCT-MALFORMED") from None
    if len(result) > MAX_CANONICAL_BYTES:
        raise ReceiptError("RCT-OVER-CAP")
    return result


def parse_canonical(payload: bytes) -> dict:
    if type(payload) is not bytes or len(payload) > MAX_CANONICAL_BYTES:
        raise ReceiptError("RCT-OVER-CAP")
    bad = False
    data = None

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        data = json.loads(payload, object_pairs_hook=unique)
        if type(data) is not dict or canonical(data) != payload:
            bad = True
    except Exception:
        bad = True
    if bad:
        raise ReceiptError("RCT-NONCANONICAL") from None
    return data
