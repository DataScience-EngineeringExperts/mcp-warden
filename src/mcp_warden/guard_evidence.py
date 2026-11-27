"""Minimized capture at the Linux stdio handoff."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .evidence_vault_files import CATEGORIES, EvidenceVaultError


class LocalEvidenceCapture:
    def __init__(self, socket: Path, *, service_uid: int, tenant: str) -> None:
        import anyio

        from .evidence_key_service import LocalServiceClient

        if not hasattr(anyio, "wait_readable"):
            raise EvidenceVaultError("EVD-PLATFORM")
        self.client = LocalServiceClient(socket, service_uid=service_uid)
        self.tenant = tenant

    def preflight(self) -> None:
        for category in CATEGORIES:
            if self.client.request({"action": "ready", "tenant": self.tenant, "category": category}) != {"ready": True}:
                raise EvidenceVaultError("EVD-STORAGE")

    def capture(self, category: str, value: object) -> None:
        from .evidence_key_service import encode_payload

        data = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii")
        outcome = self.client.request({
            "action": "capture", "tenant": self.tenant, "category": category, "content": encode_payload(data),
        })
        if set(outcome) != {"object_id"} or type(outcome["object_id"]) is not str or not re.fullmatch(
            r"[0-9a-f]{32}", outcome["object_id"]
        ):
            raise EvidenceVaultError("EVD-STORAGE")


def evidence_abort(rpc_id=None):
    from .guard_loop import StrictInspectionAbort

    return StrictInspectionAbort(site="local-evidence", tool="?", exc_type="EvidenceUnavailable", rpc_id=rpc_id)


def capture_request(state, frame) -> None:
    obj = _envelope(frame)
    method, rpc_id = obj.get("method"), obj.get("id")
    if method is not None and rpc_id is not None and (
        not _valid_id(rpc_id) or rpc_id in state.inflight or len(state.inflight) >= state.config.max_inflight
    ):
        raise evidence_abort()
    if method == "tools/call":
        params = obj.get("params", {})
        if not _valid_id(rpc_id) or type(params) is not dict or type(params.get("arguments", {})) is not dict:
            raise evidence_abort()
        _capture(state, "tool-arguments", params.get("arguments", {}), rpc_id)


def capture_result(state, frame) -> None:
    obj = _envelope(frame)
    if "method" in obj:
        return
    rpc_id = obj.get("id")
    if not _valid_id(rpc_id) or rpc_id not in state.inflight:
        raise evidence_abort()
    if "error" in obj:
        state.method_for(rpc_id)
        state.tool_for(rpc_id)
    elif state.inflight[rpc_id] == "tools/call":
        _capture(state, "tool-result", obj["result"], rpc_id)


def _envelope(frame) -> dict:
    obj = frame.json
    if obj is None or obj.get("jsonrpc") != "2.0":
        raise evidence_abort()
    if "id" in obj and not _valid_id(obj["id"]):
        raise evidence_abort()
    if "method" in obj:
        if type(obj["method"]) is not str or not obj["method"] or "error" in obj or "result" in obj:
            raise evidence_abort()
    elif ("error" in obj) == ("result" in obj) or not _valid_id(obj.get("id")):
        raise evidence_abort()
    return obj


def _valid_id(value: object) -> bool:
    if type(value) is int:
        return abs(value) <= 2**53 - 1
    if type(value) is not str or not 1 <= len(value) <= 128:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True

def _capture(state, category, value, rpc_id) -> None:
    from .evidence_key_service import EvidenceKeyServiceError

    try:
        state.local_evidence.capture(category, value)
    except (OSError, ValueError, EvidenceKeyServiceError, RecursionError):
        raise evidence_abort(rpc_id) from None
