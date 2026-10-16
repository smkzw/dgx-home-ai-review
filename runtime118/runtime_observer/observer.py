# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure injected runtime-memory observer; it owns no node lifecycle resources."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import math
import re
import time
from typing import Callable, Mapping
_NAME = re.compile('[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\\Z')
_HEX_64 = re.compile('[0-9a-f]{64}\\Z')

def _finite_number(value: object) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False

@dataclass(frozen=True, slots=True)
class Identity:
    """Full immutable identity; labels/records must match every field."""
    node: str
    profile: str
    owner: str
    generation: int
    container_id: str
    image: str

    def __post_init__(self) -> None:
        for name in ('node', 'profile', 'owner'):
            value = getattr(self, name)
            if type(value) is not str or not _NAME.fullmatch(value):
                raise ValueError(f'invalid {name}')
        if type(self.generation) is not int or self.generation <= 0:
            raise ValueError('generation must be a positive non-bool integer')
        if type(self.container_id) is not str or not _HEX_64.fullmatch(self.container_id):
            raise ValueError('container_id must be a full lowercase 64-hex ID')
        if type(self.image) is not str or not self.image.startswith('sha256:') or (not _HEX_64.fullmatch(self.image[7:])):
            raise ValueError('image must be sha256:<64 lowercase hex>')

@dataclass(frozen=True, slots=True)
class RuntimePolicy:
    """Required, enabled memory gates; values are GiB and seconds."""
    warning_gib: float
    sustained_floor_gib: float
    emergency_gib: float
    sustained_count: int
    max_age_s: float

    def __post_init__(self) -> None:
        for name in ('warning_gib', 'sustained_floor_gib', 'emergency_gib', 'max_age_s'):
            value = getattr(self, name)
            if not _finite_number(value) or value <= 0:
                raise ValueError(f'{name} must be finite and positive')
        if not self.emergency_gib < self.sustained_floor_gib < self.warning_gib:
            raise ValueError('require emergency_gib < sustained_floor_gib < warning_gib')
        if type(self.sustained_count) is not int or self.sustained_count <= 0:
            raise ValueError('sustained_count must be a positive non-bool integer')

@dataclass(frozen=True, slots=True)
class OwnershipProof:
    """Parent evidence for exact labels, container PIDs, and PID-to-GPU-container mapping."""
    record_identity: object
    labels_identity: object
    ownership_known: object
    probe_known: object
    container_pid: object
    record_pids: object
    gpu_pid_map: object

@dataclass(frozen=True, slots=True)
class Observation:
    """One node-local sample; values are validated at the observer trust boundary."""
    identity: object
    observed_at: object
    sequence: object
    available_gib: object
    proof: object
    running: object
    paused: object
    restarted: object

@dataclass(frozen=True, slots=True)
class FreshProof:
    """Immutable fresh sample passed to the parent-owned fenced stop callback."""
    identity: Identity
    observed_at: float
    sequence: int
    available_gib: float
    ownership: OwnershipProof

@dataclass(frozen=True, slots=True)
class StopAck:
    """Identity-bound stopped acknowledgement, never GPU-clearance evidence."""
    identity: object
    stopped: object

class ObserverState(str, Enum):
    ACTIVE = 'ACTIVE'
    EXITED_HOLD_RETAINED = 'EXITED_HOLD_RETAINED'
    STOPPED_ACKNOWLEDGED_HOLD_RETAINED = 'STOPPED_ACKNOWLEDGED_HOLD_RETAINED'
    QUARANTINED_HOLD_RETAINED = 'QUARANTINED_HOLD_RETAINED'
    CANCELLED_OBSERVER_ONLY = 'CANCELLED_OBSERVER_ONLY'

@dataclass(frozen=True, slots=True)
class TickResult:
    state: ObserverState
    terminal: bool
    reason: str | None
    warning: bool
    low_streak: int
    sequence: int | None
    available_gib: float | None

@dataclass(frozen=True, slots=True)
class ObserverEvent:
    """Allowlisted operational metadata; intentionally contains no exception text/body."""
    event_type: str
    state: ObserverState
    reason: str
    identity: Identity
    sequence: int | None
    available_gib: float | None
    observed_at: float | None

    def as_record(self) -> Mapping[str, object]:
        return {'event': self.event_type, 'state': self.state.value, 'reason': self.reason, 'node': self.identity.node, 'profile': self.identity.profile, 'owner': self.identity.owner, 'generation': self.identity.generation, 'container_id': self.identity.container_id, 'image': self.identity.image, 'sequence': self.sequence, 'available_gib': self.available_gib, 'observed_at': self.observed_at}

class Observer:
    """Single-controller observer. The parent owns cross-process fencing and Docker."""

    def __init__(self, identity: Identity, policy: RuntimePolicy, observe: Callable[[Identity], object], fenced_stop: Callable[[Identity, FreshProof], object], notify: Callable[[Mapping[str, object]], object], *, clock: Callable[[], object], wait: Callable[[float], object], event_writer: Callable[[Mapping[str, object]], object] | None=None) -> None:
        if type(identity) is not Identity or type(policy) is not RuntimePolicy:
            raise TypeError('identity and policy must be validated immutable values')
        for name, callback in (('observe', observe), ('fenced_stop', fenced_stop), ('notify', notify), ('clock', clock), ('wait', wait)):
            if not callable(callback):
                raise TypeError(f'{name} must be callable')
        if event_writer is not None and (not callable(event_writer)):
            raise TypeError('event_writer must be callable or None')
        self.identity = identity
        self.policy = policy
        self._observe = observe
        self._fenced_stop = fenced_stop
        self._notify = notify
        self._clock = clock
        self._wait = wait
        self._event_writer = event_writer
        self._state = ObserverState.ACTIVE
        self._warning = False
        self._low_streak = 0
        self._last_sequence: int | None = None
        self._last_observed_at: float | None = None
        self._last_result = TickResult(ObserverState.ACTIVE, False, None, False, 0, None, None)

    @property
    def state(self) -> ObserverState:
        return self._state

    def tick(self) -> TickResult:
        """Make at most one new decision; terminal states are inert."""
        if self._state is not ObserverState.ACTIVE:
            return self._last_result
        try:
            raw = self._observe(self.identity)
        except Exception:
            return self._terminate(ObserverState.QUARANTINED_HOLD_RETAINED, 'observe_failed')
        try:
            sample, now = self._validate(raw)
        except _InvalidObservation as error:
            return self._terminate(ObserverState.QUARANTINED_HOLD_RETAINED, error.reason)
        sequence = sample.sequence
        observed_at = float(sample.observed_at)
        memory = float(sample.available_gib)
        self._last_sequence = sequence
        self._last_observed_at = observed_at
        if sample.running is False:
            return self._terminate(ObserverState.EXITED_HOLD_RETAINED, 'container_exited_without_clearance', sequence=sequence, memory=memory, observed_at=observed_at)
        warning = memory < self.policy.warning_gib
        if warning != self._warning:
            self._warning = warning
            self._publish(ObserverEvent('warning', ObserverState.ACTIVE, 'warning_threshold_entered' if warning else 'warning_threshold_cleared', self.identity, sequence, memory, observed_at), terminal=False)
        self._low_streak = self._low_streak + 1 if memory < self.policy.sustained_floor_gib else 0
        if memory < self.policy.emergency_gib:
            return self._stop(sample, 'emergency_memory', sequence, memory, observed_at)
        if self._low_streak >= self.policy.sustained_count:
            return self._stop(sample, 'sustained_low_memory', sequence, memory, observed_at)
        self._last_result = TickResult(ObserverState.ACTIVE, False, None, warning, self._low_streak, sequence, memory)
        return self._last_result

    def run(self, *, interval_s: float, cancelled: Callable[[], object]) -> TickResult:
        """Run until exit/stop/quarantine/cancel; waits occur after each full observation."""
        if not _finite_number(interval_s) or interval_s <= 0:
            raise ValueError('interval_s must be finite and positive')
        if not callable(cancelled):
            raise TypeError('cancelled must be callable')
        while self._state is ObserverState.ACTIVE:
            if self._cancel_requested(cancelled):
                return self._terminate(ObserverState.CANCELLED_OBSERVER_ONLY, 'cancelled')
            result = self.tick()
            if result.terminal:
                return result
            try:
                self._wait(float(interval_s))
            except Exception:
                return self._terminate(ObserverState.QUARANTINED_HOLD_RETAINED, 'wait_failed')
            if self._cancel_requested(cancelled):
                return self._terminate(ObserverState.CANCELLED_OBSERVER_ONLY, 'cancelled')
        return self._last_result

    def _cancel_requested(self, cancelled: Callable[[], object]) -> bool:
        try:
            value = cancelled()
        except Exception:
            self._terminate(ObserverState.QUARANTINED_HOLD_RETAINED, 'cancellation_check_failed')
            return True
        if type(value) is not bool:
            self._terminate(ObserverState.QUARANTINED_HOLD_RETAINED, 'cancellation_check_unknown')
            return True
        return value

    def _validate(self, raw: object) -> tuple[Observation, float]:
        if type(raw) is not Observation:
            raise _InvalidObservation('invalid_observation')
        sample = raw
        if type(sample.identity) is not Identity or sample.identity != self.identity:
            raise _InvalidObservation('identity_mismatch')
        if type(sample.proof) is not OwnershipProof:
            raise _InvalidObservation('ownership_unproven')
        proof = sample.proof
        if type(proof.record_identity) is not Identity or proof.record_identity != self.identity or type(proof.labels_identity) is not Identity or (proof.labels_identity != self.identity):
            raise _InvalidObservation('identity_mismatch')
        if any((type(value) is not bool for value in (sample.running, sample.paused, sample.restarted))):
            raise _InvalidObservation('runtime_state_unknown')
        if proof.ownership_known is not True or proof.probe_known is not True:
            raise _InvalidObservation('ownership_unproven')
        if sample.running:
            if type(proof.container_pid) is not int or proof.container_pid <= 0 or (not self._valid_pid_tuple(proof.record_pids, nonempty=True)) or (proof.container_pid not in proof.record_pids) or (type(proof.gpu_pid_map) is not tuple) or (not proof.gpu_pid_map) or (len(proof.gpu_pid_map) > 4096):
                raise _InvalidObservation('ownership_unproven')
            mapped_pids = []
            for pair in proof.gpu_pid_map:
                if type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not int or (pair[0] <= 0) or (pair[0] not in proof.record_pids) or (type(pair[1]) is not str) or (pair[1] != self.identity.container_id):
                    raise _InvalidObservation('ownership_unproven')
                mapped_pids.append(pair[0])
            if len(set(mapped_pids)) != len(mapped_pids):
                raise _InvalidObservation('ownership_unproven')
        elif proof.container_pid is not None or proof.record_pids != () or proof.gpu_pid_map != ():
            raise _InvalidObservation('ownership_unproven')
        if sample.paused or sample.restarted:
            raise _InvalidObservation('runtime_state_changed')
        if not _finite_number(sample.available_gib) or sample.available_gib <= 0:
            raise _InvalidObservation('memory_unknown')
        if type(sample.sequence) is not int or sample.sequence <= 0:
            raise _InvalidObservation('sample_not_monotonic')
        if not _finite_number(sample.observed_at):
            raise _InvalidObservation('sample_not_fresh')
        try:
            now_value = self._clock()
        except Exception as exc:
            raise _InvalidObservation('clock_failed') from exc
        if not _finite_number(now_value):
            raise _InvalidObservation('clock_failed')
        now = float(now_value)
        observed_at = float(sample.observed_at)
        if observed_at > now or now - observed_at > self.policy.max_age_s:
            raise _InvalidObservation('sample_not_fresh')
        if self._last_sequence is not None and sample.sequence <= self._last_sequence or (self._last_observed_at is not None and observed_at <= self._last_observed_at):
            raise _InvalidObservation('sample_not_monotonic')
        return (sample, now)

    @staticmethod
    def _valid_pid_tuple(value: object, *, nonempty: bool) -> bool:
        return type(value) is tuple and (bool(value) or not nonempty) and (len(value) <= 4096) and all((type(pid) is int and pid > 0 for pid in value)) and (len(set(value)) == len(value))

    def _stop(self, sample: Observation, reason: str, sequence: int, memory: float, observed_at: float) -> TickResult:
        proof = FreshProof(self.identity, observed_at, sequence, memory, sample.proof)
        try:
            ack = self._fenced_stop(self.identity, proof)
        except Exception:
            return self._terminate(ObserverState.QUARANTINED_HOLD_RETAINED, 'fenced_stop_failed', sequence=sequence, memory=memory, observed_at=observed_at)
        if type(ack) is not StopAck:
            return self._terminate(ObserverState.QUARANTINED_HOLD_RETAINED, 'stop_refused', sequence=sequence, memory=memory, observed_at=observed_at)
        if type(ack.identity) is not Identity or ack.identity != self.identity:
            return self._terminate(ObserverState.QUARANTINED_HOLD_RETAINED, 'stop_ack_identity_mismatch', sequence=sequence, memory=memory, observed_at=observed_at)
        if ack.stopped is not True:
            return self._terminate(ObserverState.QUARANTINED_HOLD_RETAINED, 'stop_refused', sequence=sequence, memory=memory, observed_at=observed_at)
        return self._terminate(ObserverState.STOPPED_ACKNOWLEDGED_HOLD_RETAINED, 'fenced_stop_acknowledged_hold_retained', sequence=sequence, memory=memory, observed_at=observed_at)

    def _terminate(self, state: ObserverState, reason: str, *, sequence: int | None=None, memory: float | None=None, observed_at: float | None=None) -> TickResult:
        if self._state is not ObserverState.ACTIVE:
            return self._last_result
        self._state = state
        self._last_result = TickResult(state, True, reason, self._warning, self._low_streak, sequence, memory)
        self._publish(ObserverEvent('terminal', state, reason, self.identity, sequence, memory, observed_at), terminal=True)
        return self._last_result

    def _publish(self, event: ObserverEvent, *, terminal: bool) -> None:
        if self._event_writer is not None:
            try:
                self._event_writer(event.as_record())
            except Exception:
                pass
        if terminal:
            try:
                self._notify(event.as_record())
            except Exception:
                pass

class _InvalidObservation(Exception):

    def __init__(self, reason: str) -> None:
        self.reason = reason

def wall_clock() -> float:
    """Default adapter for epoch timestamps; callers inject it explicitly."""
    return time.time()

def sleep_wait(seconds: float) -> None:
    """Default wait adapter; actual cadence includes observation and callback time."""
    time.sleep(seconds)
