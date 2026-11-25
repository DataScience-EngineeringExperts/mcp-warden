"""Translate observed transport frames into session-local correlation evidence."""

from __future__ import annotations

import hashlib
import logging
import secrets
from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field

from .content_models import IngressKindV1
from .correlation import CorrelationEngine
from .correlation_signals import boundary_attempts
from .injection_catalog import match_injection_catalog
from .res_catalog import extract_blocks
from .result_inspection import TIER_MONITOR, ResultFinding

logger = logging.getLogger("mcp_warden.correlation")

_MAX_BINDINGS = 1024
_MAX_ID_LENGTH = 256
_RESPONSE_INGRESS = {
    "tools/call": IngressKindV1.TOOL_RESULT,
    "prompts/get": IngressKindV1.MCP_PROMPT,
    "resources/read": IngressKindV1.MCP_RESOURCE,
}


def _request_ingress(method: str, params: object) -> IngressKindV1 | None:
    ingress = _RESPONSE_INGRESS.get(method)
    if ingress is None or type(params) is not dict:
        return None
    descriptor = params.get("uri" if ingress is IngressKindV1.MCP_RESOURCE else "name")
    if type(descriptor) is not str or not descriptor.strip():
        return None
    if ingress in (IngressKindV1.TOOL_RESULT, IngressKindV1.MCP_PROMPT):
        args = params.get("arguments", {})
        if type(args) is not dict:
            return None
        if ingress is IngressKindV1.MCP_PROMPT and any(type(value) is not str for value in args.values()):
            return None
    return ingress


@dataclass
class ResponseEvidence:
    """Collect finite IDs from all views of one observed response."""

    ingress: IngressKindV1 | None
    signal_ids: set[str] = field(default_factory=set)
    taints: set[str] = field(default_factory=set)

    def add_raw(self, result: dict) -> None:
        if self.ingress is IngressKindV1.TOOL_RESULT:
            try:
                self.signal_ids.update(boundary_attempts(result))
                blocks, _ = extract_blocks(result)
                self.signal_ids.update(
                    match.rule_id for _, text in blocks for match in match_injection_catalog(text)
                )
            except Exception:
                logger.warning("correlation signal recognition unavailable")


class CorrelationSession:
    """One live transport or one explicitly directed offline replay.

    IDs serve only to bind one outstanding request to a response. An opaque,
    session-keyed lookup digest keeps peer values out of correlation state.
    Neither JSON-RPC IDs nor data nested in an MCP frame define a session,
    an observation's order, or its ingress kind.
    """

    def __init__(self) -> None:
        self._engine = CorrelationEngine()
        self._key = secrets.token_bytes(32)
        self._bindings: OrderedDict[bytes, IngressKindV1 | None] = OrderedDict()

    def _binding(self, rpc_id: object) -> bytes | None:
        if type(rpc_id) is str and len(rpc_id) <= _MAX_ID_LENGTH:
            value = b"s" + rpc_id.encode("utf-8", "surrogatepass")
        elif type(rpc_id) is int and rpc_id.bit_length() <= 64:
            value = b"i" + str(rpc_id).encode("ascii")
        else:
            return None
        return hashlib.blake2b(value, key=self._key, digest_size=16).digest()

    def _finish_binding(self, binding: bytes | None) -> IngressKindV1 | None:
        if binding is None or binding not in self._bindings:
            return None
        ingress = self._bindings[binding]
        self._bindings[binding] = None  # reject ID reuse while this entry is retained
        return ingress

    def client(self, frame: dict, *, forwarded: bool = True) -> tuple[ResultFinding, ...]:
        """Observe a well-formed client attempt and bind only forwarded calls."""
        method = frame.get("method")
        if frame.get("jsonrpc") != "2.0" or type(method) is not str or "result" in frame or "error" in frame:
            return self._observe("c2s")
        params = frame.get("params")
        if method.startswith("notifications/"):
            if (method == "notifications/cancelled" and "id" not in frame and type(params) is dict
                    and ("reason" not in params or type(params["reason"]) is str)):
                self._finish_binding(self._binding(params.get("requestId")))
            return self._observe("c2s")
        binding = self._binding(frame.get("id"))
        if binding is None:
            return self._observe("c2s")
        if binding in self._bindings:
            self._finish_binding(binding)
            return self._observe("c2s")

        ingress = _request_ingress(method, params)
        self._bindings[binding] = ingress if forwarded else None
        if len(self._bindings) > _MAX_BINDINGS:
            self._bindings.popitem(last=False)
        return self._observe("c2s", tool_selection=ingress is IngressKindV1.TOOL_RESULT)

    def response(self, frame: dict) -> ResponseEvidence:
        """Consume a request match at most once, including terminal errors."""
        if (frame.get("jsonrpc") != "2.0" or "method" in frame
                or ("error" in frame) == ("result" in frame)):
            return ResponseEvidence(None)
        ingress = self._finish_binding(self._binding(frame.get("id")))
        return ResponseEvidence(ingress if type(frame.get("result")) is dict else None)

    def server(self, evidence: ResponseEvidence) -> tuple[ResultFinding, ...]:
        if evidence.ingress is None:
            return self._observe("s2c")
        return self._observe(
            "s2c", evidence.ingress, signal_ids=evidence.signal_ids, taints=evidence.taints
        )

    def undirected(self) -> None:
        """Count an offline record with unknown direction without taking evidence."""
        self._engine.observe()

    def _observe(
        self,
        direction: str,
        ingress: IngressKindV1 | None = None,
        *,
        signal_ids: Iterable[str] = (),
        taints: Iterable[str] = (),
        tool_selection: bool = False,
    ) -> tuple[ResultFinding, ...]:
        try:
            matches = self._engine.observe(
                ingress,
                injection_rule_ids=signal_ids,
                taints=taints,
                tool_selection=tool_selection,
            )
        except Exception:
            logger.warning("correlation observation unavailable")
            return ()
        return tuple(
            ResultFinding(
                rule_id=match.rule_id,
                severity="medium",
                tier=TIER_MONITOR,
                message="Observed a sequence consistent with an attempted capability boundary crossing.",
                action="reported",
                direction=direction,
                correlation=match,
            )
            for match in matches
        )
