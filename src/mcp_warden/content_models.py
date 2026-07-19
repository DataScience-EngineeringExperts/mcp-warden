"""Strict immutable models for deterministic untrusted content envelopes.

This module intentionally has no dependency on the legacy lockfile models or
canonicalization helpers.  It defines evidence only; no field grants authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictInt,
    ValidationError,
    field_validator,
    model_validator,
)

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TRANSFORM_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
TRANSFORM_VERSION_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9])?$")

MAX_CONTENT_BYTES = 16 * 1024 * 1024
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_SOURCE_IDENTITY_BYTES = 8 * 1024
MAX_SOURCE_CLAIMS_BYTES = 32 * 1024
MAX_TRANSFORM_IDENTITY_BYTES = 8 * 1024
MAX_TRANSFORM_PARAMETERS_BYTES = 32 * 1024
MAX_BUNDLE_COMPONENT_BYTES = 64 * 1024
MAX_JSON_DEPTH = 16
MAX_JSON_NODES = 4_096
MAX_JSON_OBJECT_KEYS = 128
MAX_JSON_STRING_BYTES = 8 * 1024
MAX_PARENTS = 64
MAX_TAINTS = 32
MAX_DEPENDENCIES = 256


class DigestDomain(StrEnum):
    """Closed, typed namespace for every V1 digest."""

    CONTENT = "mcp-warden/content-envelope/v1/content"
    SOURCE_IDENTITY = "mcp-warden/content-envelope/v1/source-identity"
    SOURCE_CLAIMS = "mcp-warden/content-envelope/v1/source-claims"
    DERIVED_SOURCE_IDENTITY = "mcp-warden/content-envelope/v1/derived-source-identity"
    DERIVED_SOURCE_CLAIMS = "mcp-warden/content-envelope/v1/derived-source-claims"
    TRANSFORM_IMPLEMENTATION = "mcp-warden/content-envelope/v1/transform-implementation"
    TRANSFORM_PARAMETERS = "mcp-warden/content-envelope/v1/transform-parameters"
    BUNDLE_ARTIFACT = "mcp-warden/content-envelope/v1/bundle-artifact"
    BUNDLE_SIGNATURE = "mcp-warden/content-envelope/v1/bundle-signature"
    BUNDLE_VERSION = "mcp-warden/content-envelope/v1/bundle-version"
    BUNDLE_PUBLISHER = "mcp-warden/content-envelope/v1/bundle-publisher"
    BUNDLE_DEPENDENCY = "mcp-warden/content-envelope/v1/bundle-dependency"
    BUNDLE_POLICY_BINDING = "mcp-warden/content-envelope/v1/bundle-policy-binding"
    ENVELOPE = "mcp-warden/content-envelope/v1/envelope"


class IngressKindV1(StrEnum):
    TOOL_RESULT = "tool_result"
    WEB = "web"
    DOCUMENT = "document"
    EMAIL = "email"
    DATABASE_TEXT = "database_text"
    MCP_PROMPT = "mcp_prompt"
    MCP_RESOURCE = "mcp_resource"
    BUNDLE_METADATA = "bundle_metadata"
    AGENT_MESSAGE = "agent_message"


class MediaTypeV1(StrEnum):
    APPLICATION_JSON = "application/json"
    APPLICATION_OCTET_STREAM = "application/octet-stream"
    APPLICATION_PDF = "application/pdf"
    APPLICATION_XML = "application/xml"
    APPLICATION_ZIP = "application/zip"
    MESSAGE_RFC822 = "message/rfc822"
    TEXT_CSV = "text/csv"
    TEXT_HTML = "text/html"
    TEXT_MARKDOWN = "text/markdown"
    TEXT_PLAIN = "text/plain"
    TEXT_XML = "text/xml"


class TaintV1(StrEnum):
    UNTRUSTED = "core:untrusted"
    MALFORMED = "core:malformed"
    UNINSPECTABLE = "core:uninspectable"
    SENSITIVE = "core:sensitive"
    EXECUTABLE = "core:executable"
    AUTHORITY_INJECTION = "core:authority-injection"
    SECRET = "core:secret"
    PRIVATE_NETWORK = "core:private-network"
    CRITICAL = "core:critical"


class TransformKindV1(StrEnum):
    INGRESS_CAPTURE = "ingress_capture"
    DETERMINISTIC = "deterministic"


TAINT_REGISTRY_V1 = frozenset(item.value for item in TaintV1)
MEDIA_TYPE_REGISTRY_V1 = frozenset(item.value for item in MediaTypeV1)
INGRESS_KIND_REGISTRY_V1 = frozenset(item.value for item in IngressKindV1)
TRANSFORM_REGISTRY_V1 = MappingProxyType(
    {
        TransformKindV1.INGRESS_CAPTURE: ("mcp-warden.capture", "1"),
        TransformKindV1.DETERMINISTIC: ("mcp-warden.transform.deterministic", "1"),
    }
)
TRANSFORM_IDENTITIES_V1 = frozenset(TRANSFORM_REGISTRY_V1.values())
TRANSFORM_KIND_BY_IDENTITY_V1 = MappingProxyType(
    {identity: kind for kind, identity in TRANSFORM_REGISTRY_V1.items()}
)
if len(TRANSFORM_KIND_BY_IDENTITY_V1) != len(TRANSFORM_REGISTRY_V1):
    raise RuntimeError("duplicate V1 transform identity")
TRANSFORM_ID_REGISTRY_V1 = frozenset(item[0] for item in TRANSFORM_IDENTITIES_V1)
TRANSFORM_VERSION_REGISTRY_V1 = frozenset(item[1] for item in TRANSFORM_IDENTITIES_V1)


class ContentEnvelopeError(Exception):
    """Stable code-only envelope failure with no input-bearing message."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def __str__(self) -> str:
        return self.code

    def __repr__(self) -> str:
        return self.code


class _FrozenModel(BaseModel):
    _validation_code: ClassVar[str] = "ENV-MALFORMED"
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    def __init__(self, **data: Any) -> None:
        invalid = False
        try:
            super().__init__(**data)
        except ValidationError:
            invalid = True
        if invalid:
            raise ContentEnvelopeError(self._validation_code) from None

    def __setattr__(self, name: str, value: Any) -> None:
        invalid = False
        try:
            super().__setattr__(name, value)
        except ValidationError:
            invalid = True
        if invalid:
            raise ContentEnvelopeError(self._validation_code) from None

    def __delattr__(self, name: str) -> None:
        invalid = False
        try:
            super().__delattr__(name)
        except ValidationError:
            invalid = True
        if invalid:
            raise ContentEnvelopeError(self._validation_code) from None

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        invalid = False
        try:
            result = super().model_validate(obj, **kwargs)
        except ValidationError:
            invalid = True
            result = None
        if invalid:
            raise ContentEnvelopeError(cls._validation_code) from None
        return result

    @classmethod
    def model_validate_json(cls, json_data: str | bytes | bytearray, **kwargs: Any) -> Any:
        invalid = False
        try:
            result = super().model_validate_json(json_data, **kwargs)
        except ValidationError:
            invalid = True
            result = None
        if invalid:
            raise ContentEnvelopeError(cls._validation_code) from None
        return result

    @classmethod
    def model_validate_strings(cls, obj: Any, **kwargs: Any) -> Any:
        invalid = False
        try:
            result = super().model_validate_strings(obj, **kwargs)
        except ValidationError:
            invalid = True
            result = None
        if invalid:
            raise ContentEnvelopeError(cls._validation_code) from None
        return result


def _digest(value: str) -> str:
    if DIGEST_RE.fullmatch(value) is None:
        raise ValueError("invalid digest")
    return value


class ContentEvidenceV1(_FrozenModel):
    digest: str
    length: StrictInt
    media_type: str

    _valid_digest = field_validator("digest")(_digest)

    @field_validator("length")
    @classmethod
    def _valid_length(cls, value: int) -> int:
        if value < 0 or value > MAX_CONTENT_BYTES:
            raise ValueError("invalid length")
        return value

    @field_validator("media_type")
    @classmethod
    def _valid_media_type(cls, value: str) -> str:
        if value not in MEDIA_TYPE_REGISTRY_V1:
            raise ValueError("invalid media type")
        return value


class SourceEvidenceV1(_FrozenModel):
    kind: str
    identity_digest: str
    claims_digest: str

    _valid_identity = field_validator("identity_digest")(_digest)
    _valid_claims = field_validator("claims_digest")(_digest)

    @field_validator("kind")
    @classmethod
    def _valid_kind(cls, value: str) -> str:
        if value not in INGRESS_KIND_REGISTRY_V1 and value != "derived":
            raise ValueError("invalid source kind")
        return value


class ParentRefV1(_FrozenModel):
    _validation_code: ClassVar[str] = "ENV-LINEAGE-INVALID"
    envelope_digest: str
    content_digest: str

    _valid_envelope = field_validator("envelope_digest")(_digest)
    _valid_content = field_validator("content_digest")(_digest)


class TransformEvidenceV1(_FrozenModel):
    id: str
    version: str
    implementation_digest: str
    parameters_digest: str

    _valid_implementation = field_validator("implementation_digest")(_digest)
    _valid_parameters = field_validator("parameters_digest")(_digest)

    @field_validator("id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        if value not in TRANSFORM_ID_REGISTRY_V1 or TRANSFORM_ID_RE.fullmatch(value) is None:
            raise ValueError("invalid transform id")
        return value

    @field_validator("version")
    @classmethod
    def _valid_version(cls, value: str) -> str:
        if (
            value not in TRANSFORM_VERSION_REGISTRY_V1
            or TRANSFORM_VERSION_RE.fullmatch(value) is None
        ):
            raise ValueError("invalid transform version")
        return value

    @model_validator(mode="after")
    def _valid_identity_pair(self) -> TransformEvidenceV1:
        if (self.id, self.version) not in TRANSFORM_IDENTITIES_V1:
            raise ValueError("invalid transform identity")
        return self


class BundleEvidenceV1(_FrozenModel):
    _validation_code: ClassVar[str] = "ENV-BUNDLE-INVALID"
    artifact_digest: str
    signature_evidence_digest: str | None
    version_claims_digest: str
    publisher_claims_digest: str
    dependency_digests: tuple[str, ...]
    policy_binding_claims_digest: str

    _valid_artifact = field_validator("artifact_digest")(_digest)
    _valid_version = field_validator("version_claims_digest")(_digest)
    _valid_publisher = field_validator("publisher_claims_digest")(_digest)
    _valid_policy = field_validator("policy_binding_claims_digest")(_digest)

    @field_validator("signature_evidence_digest")
    @classmethod
    def _valid_signature(cls, value: str | None) -> str | None:
        return None if value is None else _digest(value)

    @field_validator("dependency_digests")
    @classmethod
    def _valid_dependencies(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_DEPENDENCIES or value != tuple(sorted(set(value))):
            raise ValueError("invalid dependency digests")
        for digest in value:
            _digest(digest)
        return value


class ContentEnvelopeV1(_FrozenModel):
    schema_version: Literal[1]
    trust_state: Literal["untrusted"]
    content: ContentEvidenceV1
    source: SourceEvidenceV1
    parents: tuple[ParentRefV1, ...]
    transform: TransformEvidenceV1
    taints: tuple[str, ...]
    bundle: BundleEvidenceV1 | None
    envelope_digest: str

    _valid_envelope = field_validator("envelope_digest")(_digest)

    @field_validator("parents")
    @classmethod
    def _valid_parents(cls, value: tuple[ParentRefV1, ...]) -> tuple[ParentRefV1, ...]:
        if len(value) > MAX_PARENTS:
            raise ValueError("too many parents")
        if value != tuple(sorted(value, key=lambda item: (item.envelope_digest, item.content_digest))):
            raise ValueError("parents not sorted")
        if len({item.envelope_digest for item in value}) != len(value):
            raise ValueError("duplicate parents")
        return value

    @field_validator("taints")
    @classmethod
    def _valid_taints(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) > MAX_TAINTS or value != tuple(sorted(set(value))):
            raise ValueError("invalid taints")
        if "core:untrusted" not in value or any(item not in TAINT_REGISTRY_V1 for item in value):
            raise ValueError("invalid taints")
        return value

    @model_validator(mode="after")
    def _valid_shape(self) -> ContentEnvelopeV1:
        if self.source.kind == "derived":
            if not self.parents:
                raise ValueError("derived envelope requires parents")
            if (
                TRANSFORM_KIND_BY_IDENTITY_V1.get((self.transform.id, self.transform.version))
                is not TransformKindV1.DETERMINISTIC
            ):
                raise ContentEnvelopeError("ENV-LINEAGE-INVALID") from None
        elif self.parents:
            raise ValueError("ingress envelope cannot have parents")
        elif (
            TRANSFORM_KIND_BY_IDENTITY_V1.get((self.transform.id, self.transform.version))
            is not TransformKindV1.INGRESS_CAPTURE
        ):
            raise ContentEnvelopeError("ENV-MALFORMED") from None
        if self.source.kind == IngressKindV1.BUNDLE_METADATA.value and self.bundle is None:
            raise ValueError("bundle metadata source requires bundle evidence")
        return self


@dataclass(frozen=True, slots=True)
class BundleEvidenceInput:
    """Raw evidence accepted by constructors and discarded after hashing."""

    artifact: bytes
    signature_evidence: bytes | None
    version_claims: bytes
    publisher_claims: bytes
    dependencies: tuple[bytes, ...]
    policy_binding_claims: bytes

    def __post_init__(self) -> None:
        components = (
            self.artifact,
            self.version_claims,
            self.publisher_claims,
            self.policy_binding_claims,
        )
        if any(type(value) is not bytes for value in components):
            raise ContentEnvelopeError("ENV-BUNDLE-INVALID") from None
        if self.signature_evidence is not None and type(self.signature_evidence) is not bytes:
            raise ContentEnvelopeError("ENV-BUNDLE-INVALID") from None
        if type(self.dependencies) is not tuple:
            raise ContentEnvelopeError("ENV-BUNDLE-INVALID") from None
        if len(self.dependencies) > MAX_DEPENDENCIES:
            raise ContentEnvelopeError("ENV-OVER-CAP") from None
        if any(type(value) is not bytes for value in self.dependencies):
            raise ContentEnvelopeError("ENV-BUNDLE-INVALID") from None
        bounded = components + self.dependencies
        if self.signature_evidence is not None:
            bounded += (self.signature_evidence,)
        if any(len(value) > MAX_BUNDLE_COMPONENT_BYTES for value in bounded):
            raise ContentEnvelopeError("ENV-OVER-CAP") from None
