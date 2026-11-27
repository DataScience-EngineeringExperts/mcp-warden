"""Closed, detached, verifiable projection of local evidence activity."""

from __future__ import annotations

import hashlib
import json
import re

from .evidence_vault_files import EvidenceVaultError

_SIGNING_DOMAIN = b"warden.local-evidence.summary.v1\0"
COUNT_BANDS = ("0", "1-9", "10-99", "100+")
_FIELDS = ("capture_count_band", "review_count_band", "deletion_count_band")
MAX_SUMMARY_BYTES = 1024


def parse_summary(data: bytes) -> dict:
    def unique(pairs):
        fields = {}
        for key, value in pairs:
            if key in fields:
                raise EvidenceVaultError("EVD-SUMMARY")
            fields[key] = value
        return fields

    if len(data) > MAX_SUMMARY_BYTES:
        raise EvidenceVaultError("EVD-SUMMARY")
    return json.loads(data, object_pairs_hook=unique)


def _signing_input(summary: dict) -> bytes:
    return _SIGNING_DOMAIN + json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("ascii")


def signed_summary(key, *, captures: int, reviews: int, deletions: int) -> dict:
    summary = {"schema_version": 1}
    for field, count in zip(_FIELDS, (captures, reviews, deletions), strict=True):
        summary[field] = COUNT_BANDS[sum(count >= edge for edge in (1, 10, 100))]
    return {"summary": summary, "signature": key.sign(_signing_input(summary)).hex()}


def checked_summary(artifact: dict) -> tuple[dict, bytes]:
    if type(artifact) is not dict or set(artifact) != {"summary", "signature"}:
        raise EvidenceVaultError("EVD-SUMMARY")
    summary, encoded_signature = artifact["summary"], artifact["signature"]
    if (
        type(summary) is not dict or set(summary) != {"schema_version", *_FIELDS}
        or type(summary["schema_version"]) is not int or summary["schema_version"] != 1
        or any(summary[field] not in COUNT_BANDS for field in _FIELDS)
        or type(encoded_signature) is not str or len(encoded_signature) != 128
    ):
        raise EvidenceVaultError("EVD-SUMMARY")
    signature = bytes.fromhex(encoded_signature)
    if len(signature) != 64 or signature.hex() != encoded_signature:
        raise EvidenceVaultError("EVD-SUMMARY")
    return summary, signature


def verify_summary(artifact: dict, key_hex: str) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    summary, signature = checked_summary(artifact)
    if len(key_hex) != 64:
        raise EvidenceVaultError("EVD-SUMMARY")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
        key.verify(signature, _signing_input(summary))
    except (InvalidSignature, ValueError):
        raise EvidenceVaultError("EVD-SUMMARY") from None


_INCIDENT_DOMAIN = b"warden.local-evidence.incident-summary.v1\0"
_REPORT_ID_DOMAIN = b"warden.local-evidence.incident-report-id.v1\0"


def signed_incident_summary(key, object_id: str) -> dict:
    # Public pseudonym derived from a domain-separated signature over the vault's
    # high-entropy local object ID. It reveals neither that ID nor a raw digest.
    report_id = hashlib.sha256(key.sign(_REPORT_ID_DOMAIN + object_id.encode("ascii"))).hexdigest()
    summary = {"schema_version": 1, "disposition": "reported-withheld", "report_id": report_id}
    return {"summary": summary, "signature": key.sign(_incident_signing_input(summary)).hex()}


def _incident_signing_input(summary: dict) -> bytes:
    return _INCIDENT_DOMAIN + json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("ascii")


def checked_incident_summary(artifact: dict) -> tuple[dict, bytes]:
    if type(artifact) is not dict or set(artifact) != {"summary", "signature"}:
        raise EvidenceVaultError("EVD-SUMMARY")
    summary, signature = artifact["summary"], artifact["signature"]
    if (
        type(summary) is not dict or set(summary) != {"schema_version", "disposition", "report_id"}
        or type(summary["schema_version"]) is not int or summary["schema_version"] != 1
        or summary["disposition"] != "reported-withheld"
        or type(summary["report_id"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", summary["report_id"])
        or type(signature) is not str or not re.fullmatch(r"[0-9a-f]{128}", signature)
    ):
        raise EvidenceVaultError("EVD-SUMMARY")
    return summary, bytes.fromhex(signature)


def verify_incident_summary(artifact: dict, key_hex: str) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    summary, signature = checked_incident_summary(artifact)
    if not re.fullmatch(r"[0-9a-f]{64}", key_hex):
        raise EvidenceVaultError("EVD-SUMMARY")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
        key.verify(signature, _incident_signing_input(summary))
    except (InvalidSignature, ValueError):
        raise EvidenceVaultError("EVD-SUMMARY") from None
