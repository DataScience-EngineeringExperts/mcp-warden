"""Shared raw/normalized inspection; refused normalization is never a clean pass."""

from __future__ import annotations

from .content_models import IngressKindV1, MediaTypeV1
from .normalization_ingress import normalize_supplied
from .normalization_ipc import NormalizationError, canonical
from .normalization_models import NormalizationProfileV1


def refusal(code: str = "NRM-MALFORMED"):
    from .result_inspection import ResultFinding
    return ResultFinding(rule_id="WRD-RES-NORMALIZATION", severity="high", tier="block",
                         message="normalization refused: " + code)


def _unique(findings):
    seen, result = set(), []
    for finding in findings:
        key = (finding.rule_id, finding.message, finding.snippet, finding.matched_phrases)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def inspect_supplied(content: bytes, media_type: MediaTypeV1, source_kind: IngressKindV1,
                     profile: NormalizationProfileV1, policy, *, exfil_denylist, inject_phrases):
    """Inspect both views before the caller's delivery decision; no authority is returned."""
    from .normalization import TEXT_MEDIA, _profile
    from .result_inspection import inspect_result
    raw_findings = []
    try:
        _profile(profile)
        if type(content) is not bytes or len(content) > profile.budget.input_bytes:
            raise NormalizationError("NRM-OVER-CAP")
        if type(media_type) is MediaTypeV1 and media_type.value in TEXT_MEDIA:
            raw_findings = inspect_result(
                {"content": [{"type": "text", "text": content.decode("utf-8", "strict")}]},
                "supplied", policy, exfil_denylist=exfil_denylist, inject_phrases=inject_phrases)
        result = normalize_supplied(content, media_type, source_kind, profile)
        return _unique(raw_findings + inspect_normalized(result, policy, exfil_denylist=exfil_denylist,
                                                         inject_phrases=inject_phrases))
    except NormalizationError as exc:
        return raw_findings + [refusal(exc.code)]
    except Exception:
        return raw_findings + [refusal()]


def inspect_normalized(result, policy, *, exfil_denylist, inject_phrases):
    """Inspect validated normalized evidence without rerunning the parser worker."""
    from .normalization_validation import validate_result
    from .result_inspection import inspect_result
    try:
        validate_result(result)
        views = [view for segment in result.segments for view in (segment.raw_text, segment.text)]
        # An additional boundary-free view catches phrases split across markup
        # tokens/nodes; explicit source maps still record the real segment boundaries.
        views += ["".join(s.text for s in result.segments),
                  "\n".join(s.text for s in result.segments)]
        findings, seen = [], set()
        for text in views:
            for finding in inspect_result({"content": [{"type": "text", "text": text}]},
                                          "supplied", policy, exfil_denylist=exfil_denylist,
                                          inject_phrases=inject_phrases):
                key = (finding.rule_id, finding.message, finding.snippet, finding.matched_phrases)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
        return findings
    except NormalizationError as exc:
        return [refusal(exc.code)]
    except Exception:
        return [refusal()]


def _block(block: object) -> None:
    if type(block) is not dict:
        raise NormalizationError("NRM-UNSUPPORTED")
    if block.get("type") == "text" and type(block.get("text")) is str:
        return
    if block.get("type") == "resource" and type(block.get("resource")) is dict:
        _resource(block["resource"])
        return
    raise NormalizationError("NRM-UNSUPPORTED")


def _resource(resource: dict) -> None:
    if type(resource.get("text")) is str:
        return
    if type(resource.get("blob")) is str and type(resource.get("mimeType")) is str:
        return
    raise NormalizationError("NRM-UNSUPPORTED")


def inspect_mcp_frame(obj: dict, method: str, profile: NormalizationProfileV1,
                      policy, *, exfil_denylist, inject_phrases, raw_content: bytes | None = None):
    """Validate supplied MCP containers then inspect all fields, including metadata.

    URI-only resources, unknown blocks and binary image/audio content refuse;
    declared supported embedded blobs are decoded by the isolated shared engine.
    """
    try:
        if type(obj) is not dict:
            raise NormalizationError()
        if raw_content is not None:
            from .normalization import _profile
            from .normalization_trace import decode_object
            _profile(profile)
            if type(raw_content) is not bytes or len(raw_content) > profile.budget.input_bytes:
                raise NormalizationError("NRM-OVER-CAP")
            # Never erase duplicate keys/escapes by capturing a reserialized
            # parsed object while delivering the original server body.
            parsed = decode_object(raw_content)
            if canonical(parsed) != canonical(obj):
                raise NormalizationError("NRM-MANIFEST")
        result = obj.get("result")
        kind = IngressKindV1.TOOL_RESULT
        if type(result) is dict:
            if method == "tools/call" or "content" in result or "structuredContent" in result:
                blocks = result.get("content", [])
                if type(blocks) is not list or (not blocks and not result.get("structuredContent")):
                    raise NormalizationError("NRM-PARTIAL")
                for block in blocks:
                    _block(block)
            if method == "prompts/get" or "messages" in result:
                kind = IngressKindV1.MCP_PROMPT
                messages = result.get("messages")
                if type(messages) is not list or not messages:
                    raise NormalizationError("NRM-PARTIAL")
                for message in messages:
                    if type(message) is not dict:
                        raise NormalizationError()
                    _block(message.get("content"))
            if method == "resources/read" or "contents" in result:
                kind = IngressKindV1.MCP_RESOURCE
                contents = result.get("contents")
                if type(contents) is not list or not contents:
                    raise NormalizationError("NRM-PARTIAL")
                for resource in contents:
                    if type(resource) is not dict:
                        raise NormalizationError()
                    _resource(resource)
        elif "result" in obj:
            raise NormalizationError()
        payload = raw_content if raw_content is not None else canonical(obj)
        return inspect_supplied(payload, MediaTypeV1.APPLICATION_JSON, kind, profile,
                                policy, exfil_denylist=exfil_denylist, inject_phrases=inject_phrases)
    except NormalizationError as exc:
        return [refusal(exc.code)]
    except Exception:
        return [refusal()]
