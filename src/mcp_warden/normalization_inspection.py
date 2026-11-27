"""Shared raw/normalized inspection; refused normalization is never a clean pass."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import replace
from typing import TYPE_CHECKING

from .content_models import IngressKindV1, MediaTypeV1
from .correlation_signals import boundary_attempts_in_text
from .injection_catalog import match_injection_catalog
from .normalization_ingress import normalize_supplied
from .normalization_ipc import NormalizationError, canonical
from .normalization_models import NormalizationProfileV1
from .taint_lineage import ContentLineageV1

if TYPE_CHECKING:
    from .result_inspection import ResultFinding


def _observe(observer: Callable[[tuple[str, ...]], None] | None, value: tuple[str, ...]) -> None:
    if observer is not None:
        try:
            observer(value)
        except Exception:
            # Correlation telemetry has no role in normalization or delivery.
            pass


def _observe_matches(
    observer: Callable[[tuple[str, ...]], None] | None,
    views: Iterable[str],
    extract_ids: Callable[[str], Iterable[str]],
) -> None:
    if observer is not None:
        try:
            matches = {match for view in views for match in extract_ids(view)}
        except Exception:
            return
        _observe(observer, tuple(sorted(matches)))


def _catalog_ids(view: str) -> Iterable[str]:
    return (match.rule_id for match in match_injection_catalog(view))


def _scoped_views(result, payload: dict) -> tuple[str, ...]:
    from .normalization import _json_texts

    # Frame-wide locators cannot bind decoded attachments or combined views
    # to a JSON path. Admit views with an exact raw string match in the result.
    raw_texts = _json_texts(payload)
    normalized = (segment.text for segment in result.segments if segment.raw_text in raw_texts)
    return tuple(dict.fromkeys((*sorted(raw_texts), *normalized)))


def refusal(code: str = "NRM-MALFORMED"):
    from .result_inspection import ResultFinding
    return ResultFinding(rule_id="WRD-RES-NORMALIZATION", severity="high", tier="block",
                         message="normalization refused: " + code)


def _unique(findings: Iterable[ResultFinding]) -> list[ResultFinding]:
    """Keep one finding per equivalent view, combining its catalog evidence."""
    unique = {}
    for finding in findings:
        key = (finding.rule_id, finding.message, finding.snippet, finding.matched_phrases)
        first = unique.setdefault(key, finding)
        if not finding.injection_matches or first.injection_matches == finding.injection_matches:
            continue
        matches = {(m.rule_id, m.catalog_version): m for m in first.injection_matches}
        for match in finding.injection_matches:
            match_key = (match.rule_id, match.catalog_version)
            previous = matches.setdefault(match_key, match)
            if previous.evidence_ids != match.evidence_ids:
                evidence_ids = tuple(sorted(set(previous.evidence_ids).union(match.evidence_ids)))
                matches[match_key] = replace(previous, evidence_ids=evidence_ids)
        unique[key] = replace(first, injection_matches=tuple(matches[k] for k in sorted(matches)))
    return list(unique.values())


def inspect_supplied(content: bytes, media_type: MediaTypeV1, source_kind: IngressKindV1,
                     profile: NormalizationProfileV1, policy, *, exfil_denylist, inject_phrases,
                     lineage: ContentLineageV1 | None = None,
                     on_taints: Callable[[tuple[str, ...]], None] | None = None,
                     on_boundary_attempts: Callable[[tuple[str, ...]], None] | None = None,
                     on_catalog_matches: Callable[[tuple[str, ...]], None] | None = None,
                     _correlation_result: dict | None = None):
    """Inspect both views before the caller's delivery decision; no authority is returned."""
    from .normalization import TEXT_MEDIA, _profile
    from .result_inspection import inspect_result
    raw_findings = []
    try:
        _profile(profile)
        if type(content) is not bytes or len(content) > profile.budget.input_bytes:
            raise NormalizationError("NRM-OVER-CAP")
        if type(media_type) is MediaTypeV1 and media_type.value in TEXT_MEDIA:
            raw_view = content.decode("utf-8", "strict")
            raw_findings = inspect_result(
                {"content": [{"type": "text", "text": raw_view}]},
                "supplied", policy, exfil_denylist=exfil_denylist, inject_phrases=inject_phrases)
        lineage_options = {} if lineage is None else {"lineage": lineage}
        result = normalize_supplied(content, media_type, source_kind, profile, **lineage_options)

        normalized_findings = inspect_normalized(
            result, policy, exfil_denylist=exfil_denylist, inject_phrases=inject_phrases,
            on_taints=on_taints, on_boundary_attempts=on_boundary_attempts,
            on_catalog_matches=on_catalog_matches, _correlation_result=_correlation_result,
        )
        return _unique(raw_findings + normalized_findings)
    except NormalizationError as exc:
        return raw_findings + [refusal(exc.code)]
    except Exception:
        return raw_findings + [refusal()]


def inspect_normalized(
    result, policy, *, exfil_denylist, inject_phrases,
    on_taints: Callable[[tuple[str, ...]], None] | None = None,
    on_boundary_attempts: Callable[[tuple[str, ...]], None] | None = None,
    on_catalog_matches: Callable[[tuple[str, ...]], None] | None = None,
    _correlation_result: dict | None = None,
):
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
        unique_views = tuple(dict.fromkeys(views))
        findings = _unique(
            finding
            for text in unique_views
            for finding in inspect_result(
                {"content": [{"type": "text", "text": text}]},
                "supplied", policy, exfil_denylist=exfil_denylist, inject_phrases=inject_phrases,
            )
        )
        _observe(on_taints, result.envelope.taints)
        if on_boundary_attempts is not None or on_catalog_matches is not None:
            try:
                scoped = unique_views if _correlation_result is None else _scoped_views(
                    result, _correlation_result,
                )
            except Exception:
                return findings
            _observe_matches(on_boundary_attempts, scoped, boundary_attempts_in_text)
            _observe_matches(on_catalog_matches, scoped, _catalog_ids)
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
                      policy, *, exfil_denylist, inject_phrases, raw_content: bytes | None = None,
                      ingress: IngressKindV1 | None = None,
                      lineage: ContentLineageV1 | None = None,
                      on_taints: Callable[[tuple[str, ...]], None] | None = None,
                      on_boundary_attempts: Callable[[tuple[str, ...]], None] | None = None,
                      on_catalog_matches: Callable[[tuple[str, ...]], None] | None = None):
    """Validate supplied MCP containers then inspect all fields, including metadata.

    URI-only resources, unknown blocks and binary image/audio content refuse;
    declared supported embedded blobs are decoded by the isolated shared engine.
    Lineage is explicit process-side evidence supplied by the caller.
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
        elif lineage is not None:
            raise NormalizationError("NRM-LINEAGE")
        payload = raw_content if raw_content is not None else canonical(obj)
        return inspect_supplied(
            payload, MediaTypeV1.APPLICATION_JSON, kind if ingress is None else ingress, profile,
            policy, exfil_denylist=exfil_denylist, inject_phrases=inject_phrases,
            lineage=lineage,
            on_taints=on_taints if type(result) is dict else None,
            on_boundary_attempts=on_boundary_attempts if type(result) is dict else None,
            on_catalog_matches=on_catalog_matches if type(result) is dict else None,
            _correlation_result=result if type(result) is dict else None,
        )
    except NormalizationError as exc:
        return [refusal(exc.code)]
    except Exception:
        return [refusal()]
