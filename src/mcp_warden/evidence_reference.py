"""Reference process-local providers. Platform rollback protection is Unsupported.

These providers implement compare-and-advance/latch semantics for deterministic
kernel testing. They do not survive a process restart or a whole-state snapshot.
"""

from threading import Lock

from mcp_warden.evidence_state import (
    ProtectedStateSnapshotV1,
    RecoveryLatchSnapshotV1,
    StateError,
    _validate_exact_snapshot,
    validate_snapshot,
)
from mcp_warden.receipt_kernel import ReceiptError, canonical, receipt_digest


def state_with_digest(state: ProtectedStateSnapshotV1, **updates):
    candidate = ProtectedStateSnapshotV1(**(state.model_dump() | updates))
    # model_dump nests floors as dicts; strict state construction accepts validated
    # exact floor instances at the actual provider boundary.
    body = candidate.model_dump(mode="json", exclude={"state_digest"})
    return candidate.model_copy(update={"state_digest": receipt_digest(canonical(body), "state")})


def validate_protected_state(state):
    _validate_exact_snapshot(state)
    body = state.model_dump(mode="json", exclude={"state_digest"})
    if receipt_digest(canonical(body), "state") != state.state_digest:
        raise StateError("RCT-GENERATION-DIGEST")


def advance_state(state, **updates):
    return state_with_digest(state, state_generation=state.state_generation + 1, **updates)


class InMemoryProtectedStateV1:
    protection_capability = "process-local-reference"

    def __init__(self, state):
        _validate_exact_snapshot(state)
        self._state = state_with_digest(state)
        self._lock = Lock()
        self.fail = False

    def read(self):
        with self._lock:
            if self.fail:
                raise ReceiptError("RCT-PROVIDER-UNAVAILABLE")
            validate_protected_state(self._state)
            return self._state

    def compare_and_advance(self, expected, candidate):
        validate_protected_state(expected)
        validate_protected_state(candidate)
        with self._lock:
            if self.fail:
                raise ReceiptError("RCT-PROVIDER-UNAVAILABLE")
            if (
                self._state != expected
                or candidate.state_generation != expected.state_generation + 1
            ):
                raise ReceiptError("RCT-STATE-COMMIT")
            validate_snapshot(candidate, expected)
            self._state = candidate
            return candidate


class InMemoryRecoveryLatchV1:
    protection_capability = "process-local-reference"

    def __init__(self, snapshot=None):
        self._snapshot = snapshot or RecoveryLatchSnapshotV1(generation=0, latched=False)
        self._lock = Lock()
        self.fail = False

    def read(self):
        with self._lock:
            if self.fail:
                raise ReceiptError("RCT-LATCH-FAILED")
            if type(self._snapshot) is not RecoveryLatchSnapshotV1:
                raise ReceiptError("RCT-LATCH-FAILED")
            bad = False
            try:
                RecoveryLatchSnapshotV1.model_validate(self._snapshot)
            except Exception:
                bad = True
            if bad:
                raise ReceiptError("RCT-LATCH-FAILED") from None
            return self._snapshot

    def set(self, *, generation, event_digest):
        with self._lock:
            if self.fail or generation < self._snapshot.generation:
                raise ReceiptError("RCT-LATCH-FAILED")
            if self._snapshot.latched:
                if (
                    generation == self._snapshot.generation
                    and event_digest == self._snapshot.event_digest
                ):
                    return self._snapshot
                raise ReceiptError("RCT-LATCH-FAILED")
            self._snapshot = RecoveryLatchSnapshotV1(
                generation=generation, latched=True, event_digest=event_digest
            )
            return self._snapshot

    def authenticated_clear(
        self, *, generation, prior_event_digest, exit_receipt_digest, authorization
    ):
        from mcp_warden.evidence_recovery import validate_latch_clear

        validate_latch_clear(
            authorization,
            generation=generation,
            prior_event_digest=prior_event_digest,
            exit_receipt_digest=exit_receipt_digest,
        )
        with self._lock:
            old = self._snapshot
            if self.fail:
                raise ReceiptError("RCT-LATCH-FAILED")
            if not old.latched:
                if (
                    old.cleared_generation == generation
                    and old.cleared_event_digest == prior_event_digest
                    and old.exit_receipt_digest == exit_receipt_digest
                ):
                    return old
                raise ReceiptError("RCT-RECOVERY-AUTHORIZATION")
            if generation != old.generation + 1 or prior_event_digest != old.event_digest:
                raise ReceiptError("RCT-RECOVERY-AUTHORIZATION")
            self._snapshot = RecoveryLatchSnapshotV1(
                generation=generation,
                latched=False,
                cleared_generation=generation,
                cleared_event_digest=prior_event_digest,
                exit_receipt_digest=exit_receipt_digest,
            )
            return self._snapshot
