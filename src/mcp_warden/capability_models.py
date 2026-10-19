"""Strict data-only models for advisory capability preparation, never authority."""

from typing import Literal

import rfc8785
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from mcp_warden.content_models import ContentEnvelopeV1
from mcp_warden.decision_models import (
    DIGEST_RE,
    IDENTIFIER_RE,
    CapabilityV1,
    DecisionRequestV1,
    IdentityBindingV1,
)

# Each candidate reuses full PDP validation; keep work bounded below MAX_GRANTS.
MAX_CANDIDATES = 64
SCOPE_SCHEMA = "exact-bound-operation-v1"


class CapabilityError(Exception):
    """Closed, secret-safe error; rejected input/provider text is never retained."""

    def __init__(self, code="CAP-INPUT-MALFORMED"):
        codes = {"CAP-INPUT-MALFORMED", "CAP-AUTHORITY-UNAVAILABLE", "CAP-WIRE-REJECTED"}
        self.code = code if type(code) is str and code in codes else "CAP-INPUT-MALFORMED"
        super().__init__(self.code)


class CapabilityModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", frozen=True, strict=True, hide_input_in_errors=True,
        revalidate_instances="always",
    )

    def __init__(self, **data):
        invalid = False
        try:
            super().__init__(**data)
        except Exception:
            invalid = True
        if invalid:
            raise CapabilityError() from None

    def __setattr__(self, name, value):
        raise CapabilityError() from None

    def __delattr__(self, name):
        raise CapabilityError() from None

    @classmethod
    def model_validate(cls, obj, **kwargs):
        invalid = False
        result = None
        try:
            result = super().model_validate(obj, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise CapabilityError() from None
        return result

    @classmethod
    def model_validate_json(cls, value, **kwargs):
        invalid = False
        result = None
        try:
            result = super().model_validate_json(value, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise CapabilityError() from None
        return result

    @classmethod
    def model_validate_strings(cls, value, **kwargs):
        invalid = False
        result = None
        try:
            result = super().model_validate_strings(value, **kwargs)
        except Exception:
            invalid = True
        if invalid:
            raise CapabilityError() from None
        return result

    @field_validator("*", mode="before")
    @classmethod
    def _schema(cls, value, info):
        if info.field_name == "schema_version" and type(value) is not int:
            raise ValueError
        return value


def validate_exact(value, cls):
    """Revalidate exact public types, including incomplete or copied instances."""
    invalid = False
    try:
        if type(value) is not cls:
            raise ValueError
        cls.model_validate(value)
    except Exception:
        invalid = True
    if invalid:
        raise CapabilityError() from None


def valid_digest(value):
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise ValueError
    return value


class CapabilityIntentV1(CapabilityModel):
    """Untrusted desired context; only independent activated PDP grants authorize it.

    Context digests must come from the host's authenticated subject/session path.
    This model does not authenticate callers or grant access to matching identities.
    Call-limited requests are unsupported rather than silently weakened.
    """

    schema_version: Literal[1] = 1
    scope_schema: Literal["exact-bound-operation-v1"] = SCOPE_SCHEMA
    identity: IdentityBindingV1
    envelope: ContentEnvelopeV1
    capability: str
    data_scope_digest: str
    purpose_digest: str
    destination_digest: str
    arguments_digest: str
    call_limit: None = None

    _digests = field_validator(
        "data_scope_digest", "purpose_digest", "destination_digest", "arguments_digest",
    )(valid_digest)

    @field_validator("capability")
    @classmethod
    def _capability(cls, value):
        if value not in {item.value for item in CapabilityV1}:
            raise ValueError
        return value

    @model_validator(mode="after")
    def _nested(self):
        validate_exact(self.identity, IdentityBindingV1)
        validate_exact(self.envelope, ContentEnvelopeV1)
        return self


class PreparedCapabilityV1(CapabilityModel):
    """Advisory bound request data; must be independently rechecked by the PEP."""

    schema_version: Literal[1] = 1
    scope_schema: Literal["exact-bound-operation-v1"] = SCOPE_SCHEMA
    request: DecisionRequestV1
    policy_digest: str
    runtime_digest: str

    _digests = field_validator("policy_digest", "runtime_digest")(valid_digest)

    @model_validator(mode="after")
    def _nested(self):
        validate_exact(self.request, DecisionRequestV1)
        return self


class ToolProjectionV1(CapabilityModel):
    """Minimal synthetic list descriptor, without upstream prose or schemas."""

    name: str
    capability: str

    @field_validator("name")
    @classmethod
    def _name(cls, value):
        if IDENTIFIER_RE.fullmatch(value) is None:
            raise ValueError
        return value

    @field_validator("capability")
    @classmethod
    def _capability(cls, value):
        if value not in {item.value for item in CapabilityV1}:
            raise ValueError
        return value


def serialize_prepared_capability(value):
    """Canonical advisory bytes with digest-only context, never raw arguments."""
    validate_exact(value, PreparedCapabilityV1)
    invalid = False
    payload = None
    try:
        payload = rfc8785.dumps(value.model_dump(mode="json"))
        if len(payload) > 256 * 1024:
            raise ValueError
    except Exception:
        invalid = True
    if invalid:
        raise CapabilityError() from None
    return payload
