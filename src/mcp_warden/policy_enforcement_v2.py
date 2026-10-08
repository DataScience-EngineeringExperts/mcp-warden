"""DSE-717 mediation: governed decision, signed durable evidence, then effect."""

from mcp_warden.content_envelope import to_public_bytes
from mcp_warden.content_models import ContentEnvelopeV1
from mcp_warden.decision_governor import DecisionGovernorV1
from mcp_warden.decision_models import (
    DecisionDigestDomain,
    digest_decision_bytes,
)
from mcp_warden.enforcement_result_v2 import (
    make_enforcement_result_v2,
    serialize_enforcement_result_v2,
)
from mcp_warden.evidence_coordinator import DecisionEvidenceCoordinatorV1
from mcp_warden.evidence_helpers import require_protected_tails
from mcp_warden.evidence_models import (
    create_evidence_context,
    create_evidence_result,
    validate_evidence_result,
)
from mcp_warden.evidence_state import StateError, operationally_healthy, validate_floor
from mcp_warden.governed_decision import convert_failed_allow, create_governed_decision
from mcp_warden.policy_decision import (
    ActivatedRuntimeV1,
    _has_activation_marker,
    canonical_runtime_bytes,
)
from mcp_warden.policy_enforcement import (
    EnforcementTraceV1,
    PolicyEnforcementPointV1,
)
from mcp_warden.receipt_kernel import ReceiptError, canonical, receipt_digest

INVALID_DIGEST = receipt_digest(b"invalid-input", "invalid")


class PolicyEnforcementPointV2:
    __slots__ = ("_pdp", "_adapter", "_bundles", "_governor", "_coordinator")

    def __init__(self, pdp, adapter, *, governor, coordinator, executable_bundles=()):
        # Reuse the sealed V1 initialization contract, never its evidence shortcut.
        v1 = PolicyEnforcementPointV1(pdp, adapter, executable_bundles=executable_bundles)
        if (
            type(governor) is not DecisionGovernorV1
            or type(coordinator) is not DecisionEvidenceCoordinatorV1
            or governor.policy.policy_digest != pdp.policy_digest
            or governor.authorization.digest != coordinator.authorization.digest
        ):
            raise ReceiptError("RCT-MALFORMED")
        for name, value in (
            ("_pdp", pdp),
            ("_adapter", adapter),
            ("_bundles", v1._bundles),
            ("_governor", governor),
            ("_coordinator", coordinator),
        ):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise ReceiptError("RCT-MALFORMED")

    @property
    def manifest_digest(self):
        return self._adapter.manifest_digest

    @property
    def registration_operations(self):
        return self._adapter.registration_operations

    def execute(self, request, *, runtime, effect, override=None):
        return self._execute(
            request, runtime=runtime, effect=effect, override=override, events=[], channels=None
        )

    def _execute_instrumented(self, request, *, runtime, effect, override=None):
        events = []
        channels = []
        result = self._execute(
            request,
            runtime=runtime,
            effect=effect,
            override=override,
            events=events,
            channels=channels,
        )
        events.append("result:" + result.code)
        return result, EnforcementTraceV1(
            events=tuple(events),
            output_channels=(serialize_enforcement_result_v2(result), canonical(events), *channels),
        )

    def _preflight(self, request, effect):
        from mcp_warden.policy_enforcement_v2_helpers import preflight

        return preflight(self._adapter, self._bundles, request, effect)

    def _execute(self, request, *, runtime, effect, override, events, channels):
        code, request_valid, effect_valid = self._preflight(request, effect)
        time_valid = False
        now, until, runtime_digest = 0, 1, INVALID_DIGEST
        try:
            time_valid = _has_activation_marker(runtime, ActivatedRuntimeV1)
            if time_valid:
                payload = canonical_runtime_bytes(runtime.runtime)
                time_valid = (
                    digest_decision_bytes(payload, domain=DecisionDigestDomain.RUNTIME)
                    == runtime.runtime_digest
                )
            if time_valid:
                now, until, runtime_digest = (
                    runtime.runtime.trusted_time,
                    runtime.runtime.trusted_time_valid_until,
                    runtime.runtime_digest,
                )
                time_valid = now < until
        except Exception:
            time_valid = False
        base = self._pdp.evaluate(request, runtime=runtime)
        d = None
        if code is None and time_valid:
            authority_ready = False
            try:
                state, latch = self._coordinator._read()
                if not operationally_healthy(state, latch):
                    raise ReceiptError("RCT-RECOVERY-ONLY")
                validate_floor(state, kind="adapter", generation=0, digest=self.manifest_digest)
                if request.operation.bundle_manifest_digest is not None:
                    validate_floor(
                        state,
                        kind="executable-bundle",
                        generation=0,
                        digest=request.operation.bundle_manifest_digest,
                    )
                time_digest = receipt_digest(
                    canonical(
                        {
                            "runtime_digest": runtime_digest,
                            "trusted_time": now,
                            "valid_until": until,
                        }
                    ),
                    "time",
                )
                authority_ready = True
                try:
                    d = self._governor.govern(
                        base,
                        request=request,
                        snapshot=state,
                        now=now,
                        trusted_time_digest=time_digest,
                        override=override,
                    )
                except ReceiptError as error:
                    if type(error) is not ReceiptError:
                        raise ReceiptError("RCT-INTERNAL-ERROR") from None
                    if error.code != "RULE-OVERRIDE-INVALID":
                        raise
                    # Reject the supplied override while retaining all strengthening
                    # rules and critical quarantine reasons from the valid decision.
                    unoverridden = self._governor.govern(
                        base,
                        request=request,
                        snapshot=state,
                        now=now,
                        trusted_time_digest=time_digest,
                    )
                    values = unoverridden.model_dump(exclude={"decision_digest"})
                    if unoverridden.effective_verdict != "quarantine":
                        values.update(effective_verdict="deny", public_reason=error.code)
                    d = create_governed_decision(**values)
            except Exception as error:
                # Only actual state/recovery failures use the recovery-only reason.
                # ReceiptError closes its codes; arbitrary provider text is discarded.
                if (
                    not authority_ready
                    or type(error) is StateError
                    or (type(error) is ReceiptError and error.code == "RCT-RECOVERY-ONLY")
                ):
                    code = "PEP-RECOVERY-ONLY"
                elif type(error) is ReceiptError:
                    code = ReceiptError(error.code).code
                else:
                    code = "RCT-INTERNAL-ERROR"
        if d is None:
            p = self._governor.policy
            d = create_governed_decision(
                request_digest=request.request_digest if request_valid else INVALID_DIGEST,
                effect_digest=effect.arguments_digest if effect_valid else INVALID_DIGEST,
                base_decision_digest=base.decision_digest,
                base_verdict=base.verdict,
                effective_verdict="quarantine" if base.verdict == "quarantine" else "deny",
                public_reason=base.reason if base.verdict == "quarantine" else code or base.reason,
                recovery_code="recovery-only" if code == "PEP-RECOVERY-ONLY" else base.recovery,
                policy_digest=p.policy_digest,
                policy_generation=p.policy.policy_generation,
                runtime_digest=runtime_digest,
                rule_digest=self._governor.rules.digest,
                rule_generation=self._governor.rules.bundle.generation,
                revocation_digest=p.revocation_digest,
                revocation_generation=p.policy.revocation_generation,
                adapter_digest=self.manifest_digest,
                bundle_digest=request.operation.bundle_manifest_digest if request_valid else None,
                envelope_digest=request.envelope.envelope_digest
                if request_valid
                else INVALID_DIGEST,
            )
        events.append("decision")

        def context_for(decision):
            from mcp_warden.receipt_models import ReceiptEventContextV1

            event = None
            if decision.override_digest is not None:
                action = override.authorization
                event = ReceiptEventContextV1(
                    kind="override",
                    actor_digest=action.actor_digest,
                    scope_digest=action.scope_digest,
                    authority_digest=override.digest,
                    expires_at=action.expires_at,
                )
            return create_evidence_context(
                decision=decision,
                effect_digest=effect.arguments_digest if effect_valid else INVALID_DIGEST,
                trusted_time=now if time_valid else 0,
                trusted_time_valid_until=until if time_valid else 1,
                trusted_time_status="verified" if time_valid else "unavailable",
                signer_authorization_digest=self._coordinator.authorization.digest,
                event=event,
            )

        context = context_for(d)
        evidence, permit = self._record(context, events, channels)
        if d.effective_verdict == "allow" and not permit:
            d = convert_failed_allow(d)
            events.append("decision")
            context = context_for(d)
            evidence, _ = self._record(context, events, channels)
        if d.effective_verdict != "allow" or not permit:
            return make_enforcement_result_v2(d, evidence, False, "blocked", d.public_reason)
        # Re-read independent state/latch immediately before selecting the sink.
        try:
            state, latch = self._coordinator._read()
            if (
                not operationally_healthy(state, latch)
                or state.primary_sequence != evidence.sequence
                or state.recovery_generation != evidence.recovery_generation
            ):
                raise ReceiptError("RCT-RECOVERY-ONLY")
            require_protected_tails(self._coordinator.primary, self._coordinator.fallback, state)
            handler = self._adapter._handler(request.operation.operation_id)
        except Exception:
            d = convert_failed_allow(d)
            events.append("decision")
            context = context_for(d)
            evidence, _ = self._record(context, events, channels)
            return make_enforcement_result_v2(d, evidence, False, "blocked", d.public_reason)
        try:
            events.append("sink")
            output = handler(effect.arguments)
        except Exception:
            return make_enforcement_result_v2(d, evidence, True, "indeterminate", "PEP-SINK-FAILED")
        events.append("output")
        valid_output = True
        try:
            if output is not None:
                if type(output) is not ContentEnvelopeV1:
                    raise ValueError
                to_public_bytes(output)
        except Exception:
            valid_output = False
        if not valid_output:
            return make_enforcement_result_v2(
                d, evidence, True, "indeterminate", "PEP-OUTPUT-INVALID"
            )
        return make_enforcement_result_v2(d, evidence, True, "completed", "PEP-EXECUTED", output)

    def _record(self, context, events, channels):
        result = None
        permit = False
        try:
            events.append("evidence")
            if channels is None:
                result = self._coordinator.record_decision(context)
            else:
                result, artifacts = self._coordinator.record_decision_instrumented(context)
                channels.extend(artifacts)
            permit = validate_evidence_result(
                result, context, primary_identity=self._coordinator.primary.store_identity_digest
            )
        except Exception:
            result = create_evidence_result(
                context,
                mode="unavailable",
                failure_code="RCT-INTEGRITY",
                recovery_mode="recovery-latched",
            )
        return result, permit
