# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""[REDACTED large text/source constant; see extracted source files]"""
from __future__ import annotations
import contextlib
from llm_gateway.errors import GatewayError
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Callable
from llm_gateway.facade import validate_drain_reply, validate_ensure_ready_reply, validate_generation_reply, validate_health_reply
from llm_gateway.state import GatewayStore
MAX_DRAIN_ATTEMPTS = 3
_REASON_RETRY: dict[str, float] = {'profile_busy': 5.0, 'profile_not_ready': 15.0, 'profile_starting': 15.0, 'profile_reconciling': 30.0, 'conflict_wait': 30.0, 'conflict_reconciling': 30.0, 'waiting_parent_session': 30.0, 'incumbent_contested_new_sessions_blocked': 30.0, 'incumbent_contested_protection_exhausted': 30.0, 'backend_unreachable': 15.0, 'backend_health_pending': 2.0, 'backend_model_mismatch': 30.0, 'backend_health_malformed': 30.0, 'facade_unavailable': 30.0, 'facade_disabled': 30.0, 'facade_reply_malformed': 30.0, 'facade_ready_without_identity': 30.0, 'facade_model_mismatch': 30.0, 'profile_draining': 2.0, 'profile_lifecycle_pending': 2.0, 'facade_generation_unavailable': 30.0, 'facade_generation_mismatch': 30.0, 'facade_generation_malformed': 30.0}

@dataclass
class RequestInfo:
    request_id: str
    owner: str
    alias: str
    profile: str
    session_id: str | None
    parent_session_id: str | None
    stream: bool
    submitted_at: float
    deadline: float
    state: str = 'queued'
    granted: bool = False

class Scheduler:
    """Server-authoritative admission; single coherent view under one lock."""

    def __init__(self, *, store: GatewayStore, facade: Any, config: GatewayConfig, probe_backend: Callable[[Any], dict[str, Any]], clock: Callable[[], float]=time.time):
        self.store = store
        self.facade = facade
        self.config = config
        self.probe_backend = probe_backend
        self.clock = clock
        self.conflicts = config.conflict_map()
        self.policy = config.policy
        self._operator_maintenance = False
        self._operator_public_inflight = 0
        self._operator_creative_pulse_inflight = 0
        self._operator_tick_inflight = 0
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._infos: dict[str, RequestInfo] = {}
        self._queues: dict[str, deque[str]] = defaultdict(deque)
        self._active: dict[str, int] = defaultdict(int)
        self._ready: dict[str, bool] = {}
        self._resident: dict[str, bool] = {}
        self._resident_since: dict[str, float] = {}
        self._generation: dict[str, int | None] = {}
        self._model_id: dict[str, str | None] = {}
        self._ensure_reason: dict[str, str] = {}
        self._last_ensure: dict[str, float] = {}
        self._health: dict[str, dict[str, Any]] = {}
        self._contested_since: dict[str, float] = {}
        self._last_activity: dict[str, float] = {}
        self._last_drain_attempt: dict[str, float] = {}
        self._last_reconcile: dict[str, float] = {}
        self._uncertain: set[str] = set()
        self._uncertain_slots: dict[str, int] = defaultdict(int)
        self._settlement_failures: dict[str, tuple[str, str]] = {}
        self._draining: set[str] = set()
        self._ensuring: set[str] = set()
        self._dispatch_checks: set[str] = set()
        self._drain_attempts: dict[str, tuple[int | None, int]] = {}
        self._last_reason: dict[str, str] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._creative = None
        self.creative_pulse = None
        self.manager = None
        for profile in self.store.reconciling_profiles():
            self._uncertain.add(profile)

    def start(self) -> 'Scheduler':
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name='llm-gateway-scheduler', daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        with self._cv:
            self._cv.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _loop(self) -> None:
        interval = self.policy.maintenance_interval_seconds
        while not self._stop.wait(interval):
            try:
                self.run_maintenance()
                self._operator_safe_creative_pulse()
            except Exception as exc:
                with self._lock:
                    self._last_reason['__maintenance__'] = f'error:{type(exc).__name__}'
            with self._cv:
                self._cv.notify_all()

    @contextlib.contextmanager
    def operator_public_call(self):
        with self._lock:
            if self._operator_maintenance:
                raise GatewayError('operator maintenance', code='operator_maintenance', http_status=503)
            self._operator_public_inflight += 1
        try:
            yield
        finally:
            with self._lock:
                self._operator_public_inflight -= 1
                self._cv.notify_all()

    @contextlib.contextmanager
    def operator_admission(self):
        with self._lock:
            if self._operator_maintenance:
                raise GatewayError('operator maintenance', code='operator_maintenance', http_status=503)
            yield

    def begin_operator_maintenance(self):
        with self._lock:
            if self._operator_maintenance:
                raise RuntimeError('operator_maintenance_already_held')
            if self._operator_tick_inflight or self._creative is not None or self._operator_creative_pulse_inflight or self._operator_public_inflight or self._infos or any(self._queues.values()) or any(self._active.values()) or self._uncertain or self._ensuring or self._dispatch_checks or self._draining:
                raise RuntimeError('operator_maintenance_work_or_lifecycle_pending')
            self._operator_maintenance = True
            self._cv.notify_all()

    def continue_operator_maintenance(self):
        with self._lock:
            if not self._operator_maintenance:
                raise RuntimeError('operator_continuation_requires_sticky_fence')
            if self._operator_tick_inflight or self._creative is not None or self._operator_creative_pulse_inflight or self._operator_public_inflight or self._infos or any(self._queues.values()) or any(self._active.values()) or self._uncertain or self._ensuring or self._dispatch_checks or self._draining:
                raise RuntimeError('operator_continuation_work_or_lifecycle_pending')
            self._cv.notify_all()

    def restore_operator_block(self):
        with self._lock:
            self._operator_maintenance = True
            self._cv.notify_all()

    def finish_operator_maintenance(self):
        with self._lock:
            if not self._operator_maintenance:
                raise RuntimeError('operator_fence_missing')
            if self._operator_tick_inflight or self._creative is not None or self._operator_creative_pulse_inflight or self._operator_public_inflight or self._infos or any(self._active.values()) or self._ensuring or self._dispatch_checks:
                raise RuntimeError('operator_fence_drift')
            self._ready['glm-ab'] = False
            self._resident['glm-ab'] = False
            self._generation['glm-ab'] = None
            self._model_id['glm-ab'] = None
            self._health.pop('glm-ab', None)
            self._operator_maintenance = False
            self._cv.notify_all()

    def _operator_safe_creative_pulse(self):
        with self._lock:
            if self._operator_maintenance or self.creative_pulse is None:
                return
            self._operator_creative_pulse_inflight += 1
        try:
            self.creative_pulse()
        finally:
            with self._lock:
                self._operator_creative_pulse_inflight -= 1
                self._cv.notify_all()

    def register(self, info: RequestInfo) -> None:
        with self._lock:
            if self._operator_maintenance:
                raise RuntimeError('operator_maintenance')
            if info.request_id in self._infos:
                raise RuntimeError(f'request already registered: {info.request_id}')
            self._infos[info.request_id] = info
            self._queues[info.profile].append(info.request_id)
            self._last_activity[info.profile] = self.clock()
            self._cv.notify_all()

    def unregister(self, request_id: str) -> None:
        with self._lock:
            info = self._infos.get(request_id)
            if info is not None:
                queue = self._queues.get(info.profile)
                if queue is not None:
                    try:
                        queue.remove(request_id)
                    except ValueError:
                        pass
                self._infos.pop(request_id, None)
            self._cv.notify_all()

    def abandon(self, request_id: str) -> None:
        """Handler gave up before dispatch; the queue entry is removed so it can
        never be granted later (the store marks the request expired/cancelled)."""
        self.unregister(request_id)

    def wait_for_change(self, timeout: float) -> None:
        with self._cv:
            self._cv.wait(timeout)

    def try_grant(self, request_id: str) -> dict[str, Any]:
        """Decide whether this request may dispatch *right now*.

        Pure state inspection (plus read-only store lookups); no lifecycle side
        effects. Reserves the profile slot when granted so a second caller can
        never double-book it.
        """
        with self._lock:
            if self._operator_maintenance:
                return {'granted': False, 'reason_code': 'operator_maintenance', 'retry_after_seconds': 30.0}
            now = self.clock()
            info = self._infos.get(request_id)
            if info is None:
                return {'granted': False, 'reason_code': 'unknown_request', 'retry_after_seconds': 30.0}
            profile = info.profile
            if self._creative_blocks(profile):
                return self._blocked(profile, 'creative_node_reserved', 2.0)
            queue = self._queues.get(profile)
            if not queue or queue[0] != request_id:
                return self._blocked(profile, 'not_queue_head', 5.0)
            if profile in self._draining:
                return self._blocked(profile, 'profile_draining', 2.0)
            if profile in self._ensuring or profile in self._dispatch_checks:
                return self._blocked(profile, 'profile_lifecycle_pending', 2.0)
            if profile in self._uncertain:
                return self._blocked(profile, 'profile_reconciling', 30.0)
            session_reason = self._session_gate(info, now)
            if session_reason is not None:
                return self._blocked(profile, session_reason, 30.0)
            if self._active[profile] >= self.policy.max_initial_jobs_running_per_profile:
                return self._blocked(profile, 'profile_busy', 5.0)
            for other in self.conflicts.get(profile, frozenset()):
                if other in self._draining:
                    return self._blocked(profile, 'conflict_wait', 30.0)
                if other in self._uncertain and (self._active[other] > 0 or self._resident.get(other)):
                    return self._blocked(profile, 'conflict_reconciling', 30.0)
                if self._active[other] > 0:
                    return self._blocked(profile, 'conflict_wait', 30.0)
                if self._resident.get(other):
                    return self._blocked(profile, 'conflict_wait', 30.0)
            contested = self._contested_since.get(profile)
            if contested is not None:
                if now - contested >= self.policy.max_contested_lease_protection_seconds:
                    return self._blocked(profile, 'incumbent_contested_protection_exhausted', 30.0)
                if now - contested >= self.policy.conflict_grace_seconds and (not self._known_session(info, contested)):
                    return self._blocked(profile, 'incumbent_contested_new_sessions_blocked', 30.0)
            if not self._ready.get(profile):
                reason = self._ensure_reason.get(profile, 'profile_not_ready')
                return self._blocked(profile, reason, _REASON_RETRY.get(reason, 15.0))
            health = self._health.get(profile)
            if health is None or not health.get('ok'):
                reason = 'backend_health_pending' if health is None else str(health.get('reason_code') or 'backend_unreachable')
                return self._blocked(profile, reason, _REASON_RETRY.get(reason, 15.0))
            queue.popleft()
            self._active[profile] += 1
            info.granted = True
            info.state = 'granted'
            self._last_activity[profile] = now
            self._last_reason.pop(profile, None)
            session_id = info.session_id
            generation = self._generation.get(profile)
            model_id = self._model_id.get(profile)
        if session_id:
            try:
                self.store.touch_session(session_id)
            except Exception:
                pass
        return {'granted': True, 'reason_code': 'granted', 'retry_after_seconds': None, 'generation': generation, 'model_id': model_id}

    def validate_dispatch_generation(self, profile: str, *, expected_generation: int | None) -> dict[str, Any]:
        """Require a live facade generation match immediately before dispatch."""
        expected_model = self.config.backends[profile].expected_model_id
        with self._lock:
            if self._operator_maintenance:
                return {'ok': False, 'reason_code': 'operator_maintenance'}
            if profile in self._draining or profile in self._ensuring or profile in self._dispatch_checks:
                return {'ok': False, 'reason_code': 'profile_lifecycle_pending'}
            cached_generation = self._generation.get(profile)
            if type(expected_generation) is not int or expected_generation <= 0 or cached_generation != expected_generation or (self._model_id.get(profile) != expected_model):
                self._mark_uncertain_locked(profile, 'facade_generation_mismatch', not_ready=True)
                return {'ok': False, 'reason_code': 'facade_generation_mismatch'}
            self._dispatch_checks.add(profile)
        try:
            try:
                current = validate_generation_reply(self.facade.get_generation(profile=profile))
            except Exception:
                current = validate_generation_reply(None)
            matches = current['available'] and type(current['generation']) is int and (current['generation'] == expected_generation) and current['ready'] and (current['state'].upper() == 'READY')
            if matches:
                return {'ok': True, 'generation': expected_generation, 'reason_code': 'ok'}
            reason = 'facade_generation_malformed' if current['reason_code'] == 'facade_reply_malformed' or current['generation'] is None else 'facade_generation_unavailable' if not current['available'] else 'facade_generation_mismatch'
            with self._lock:
                if self._generation.get(profile) != expected_generation or not matches:
                    self._mark_uncertain_locked(profile, reason, not_ready=True)
            return {'ok': False, 'reason_code': reason}
        finally:
            with self._lock:
                self._dispatch_checks.discard(profile)
                self._cv.notify_all()

    def _mark_uncertain_locked(self, profile: str, reason: str, *, not_ready: bool=False) -> None:
        self._uncertain.add(profile)
        self._ensure_reason[profile] = reason
        self._last_reason[profile] = reason
        if not_ready:
            self._ready[profile] = False

    def _blocked(self, profile: str, reason: str, retry_after: float) -> dict[str, Any]:
        """Record the machine-readable wait reason for status and return a wait."""
        self._last_reason[profile] = reason
        return {'granted': False, 'reason_code': reason, 'retry_after_seconds': retry_after}

    def _session_gate(self, info: RequestInfo, now: float) -> str | None:
        if info.parent_session_id:
            parent = self.store.session_row(info.parent_session_id)
            if parent is None:
                return 'waiting_parent_session'
            if parent['state'] != 'yielded':
                return 'waiting_parent_session'
        return None

    def _known_session(self, info: RequestInfo, contested_since: float) -> bool:
        if not info.session_id:
            return False
        session = self.store.session_row(info.session_id)
        if session is None or session['state'] == 'yielded':
            return False
        return float(session['created_at']) <= contested_since

    def release(self, request_id: str, *, keep_slot: bool=False) -> None:
        """Finish a granted request. ``keep_slot=True`` retains the profile slot
        because the engine outcome is unconfirmed (uncertain work)."""
        with self._lock:
            info = self._infos.pop(request_id, None)
            if info is not None:
                profile = info.profile
                if keep_slot:
                    self._uncertain.add(profile)
                    self._uncertain_slots[profile] += 1
                else:
                    self._active[profile] = max(0, self._active[profile] - 1)
                self._last_activity[profile] = self.clock()
            self._cv.notify_all()

    def finish_request(self, request_id: str, *, state: str, reason_code: str | None, keep_slot: bool=False) -> None:
        """Commit metadata before releasing capacity, under the same admission lock.

        A failed/ambiguous commit or release is sticky for this process. Neither
        engine-idle nor a later finish can reinterpret it as success. The already
        durable dispatch marker preserves restart/idempotency recovery semantics.
        """
        with self._lock:
            info = self._infos.get(request_id)
            if info is None or request_id in self._settlement_failures:
                raise RuntimeError('request_settlement_not_active_or_latched')
            profile = info.profile
            active_before = self._active[profile]
            held_before = self._uncertain_slots[profile]
            stage = 'terminal_persistence'
            try:
                self.store.finish_request(request_id, state=state, reason_code=reason_code, uncertain=state == 'reconciling')
                stage = 'capacity_release'
                self.release(request_id, keep_slot=keep_slot)
            except BaseException:
                self._infos[request_id] = info
                self._active[profile] = max(1, active_before, self._active[profile])
                self._uncertain_slots[profile] = held_before
                self._settlement_failures[request_id] = (profile, stage)
                self._mark_uncertain_locked(profile, 'request_settlement_failed')
                self._cv.notify_all()
                raise

    def note_uncertain(self, profile: str) -> None:
        with self._lock:
            self._uncertain.add(profile)
            self._cv.notify_all()

    def resolve_uncertain(self, profile: str, *, resolved: int) -> None:
        with self._lock:
            if any((p == profile for p, _stage in self._settlement_failures.values())):
                raise RuntimeError('request_settlement_failure_sticky')
            held = self._uncertain_slots.pop(profile, 0)
            self._active[profile] = max(0, self._active[profile] - max(held, resolved))
            self._uncertain.discard(profile)
            self._last_activity[profile] = self.clock()
            self._cv.notify_all()

    def run_maintenance(self) -> dict[str, Any]:
        """One maintenance tick. All facade/lifecycle effects live here."""
        with self._lock:
            if self._operator_maintenance:
                return {'drains': [], 'reconciled': [], 'ensured': [], 'errors': [], 'operator_maintenance': True}
            self._operator_tick_inflight += 1
        try:
            now = self.clock()
            report: dict[str, Any] = {'drains': [], 'reconciled': [], 'ensured': [], 'errors': []}
            for profile, queue in list(self._queues.items()):
                if not queue:
                    continue
                head = self._infos.get(queue[0])
                if head is None:
                    continue
                for other in self.conflicts.get(profile, frozenset()):
                    if self._active[other] > 0 or self._resident.get(other):
                        self._contested_since.setdefault(other, now)
            for other in list(self._contested_since):
                if not self._has_conflicting_waiter(other):
                    self._contested_since.pop(other, None)
            for profile in list(self._contested_since):
                outcome = self._maybe_contested_drain(profile, now)
                if outcome:
                    report['drains'].append(outcome)
            for profile, queue in list(self._queues.items()):
                if not queue:
                    continue
                head = self._infos.get(queue[0])
                if head is None:
                    continue
                if profile in self._uncertain:
                    continue
                if self._conflict_blocked(profile):
                    continue
                gate = self._session_gate(head, now)
                if gate is not None:
                    continue
                if now - self._last_ensure.get(profile, 0.0) < self.policy.ensure_poll_seconds:
                    continue
                self._last_ensure[profile] = now
                self._ensure_ready(profile, head.request_id, now, report)
            for profile, queue in list(self._queues.items()):
                if not queue or not self._ready.get(profile):
                    continue
                fresh = self._health.get(profile)
                if fresh is not None and now - fresh.get('checked_at', 0.0) < self.policy.backend_health_ttl_seconds:
                    continue
                self._check_health(profile, now)
            for profile in list(self._resident):
                if not self._resident.get(profile):
                    continue
                if profile in self._contested_since:
                    continue
                if self._queues.get(profile):
                    continue
                if self._active[profile] > 0 or profile in self._uncertain:
                    continue
                idle = now - self._last_activity.get(profile, now)
                if idle >= self.policy.keep_warm_without_conflict_seconds:
                    outcome = self._drain(profile, now, reason='keep_warm_expired')
                    if outcome:
                        report['drains'].append(outcome)
            for profile in list(self._uncertain):
                with self._lock:
                    failed = any((p == profile for p, _stage in self._settlement_failures.values()))
                if failed:
                    report['errors'].append({'profile': profile, 'error': 'request_settlement_failed'})
                    continue
                if now - self._last_reconcile.get(profile, 0.0) < self.policy.reconcile_interval_seconds:
                    continue
                self._last_reconcile[profile] = now
                try:
                    health = validate_health_reply(self.facade.health(profile=profile))
                except Exception as exc:
                    report['errors'].append({'profile': profile, 'error': type(exc).__name__})
                    continue
                if health['available'] and health['known'] and (health['active_requests'] == 0):
                    resolved = self._close_reconciling_requests(profile)
                    self.resolve_uncertain(profile, resolved=resolved)
                    self.store.record_event('reconcile_resolved', profile=profile, reason_code='engine_idle', detail=f'requests={resolved}')
                    report['reconciled'].append({'profile': profile, 'requests': resolved})
                else:
                    self.store.record_event('reconcile_hold', profile=profile, reason_code=health['reason_code'] if health['available'] else 'facade_unavailable', detail='active_requests unknown or non-zero')
            with self._cv:
                self._cv.notify_all()
            return report
        finally:
            with self._lock:
                self._operator_tick_inflight -= 1
                self._cv.notify_all()

    def _maybe_contested_drain(self, profile: str, now: float) -> dict[str, Any] | None:
        with self._lock:
            contested = self._contested_since.get(profile)
            if contested is None or not self._resident.get(profile):
                return None
            if self._active[profile] > 0 or profile in self._uncertain:
                return None
            if now - self._resident_since.get(profile, now) < self.policy.min_residency_seconds:
                return None
            if now - self._last_drain_attempt.get(profile, 0.0) < self.policy.reconcile_interval_seconds:
                return None
            protection_over = now - contested >= self.policy.max_contested_lease_protection_seconds
            grace_over = now - contested >= self.policy.conflict_grace_seconds
        fresh_lease = self._has_fresh_lease(profile, now)
        if protection_over or (grace_over and (not fresh_lease)):
            return self._drain(profile, now, reason='contested_queue')
        return None

    def _has_fresh_lease(self, profile: str, now: float) -> bool:
        for session in self.store.sessions_for_profile(profile):
            if session['state'] != 'active':
                continue
            if float(session['last_activity']) + self.policy.lease_ttl_seconds > now:
                return True
        return False

    def _has_conflicting_waiter(self, profile: str) -> bool:
        for other in self.conflicts.get(profile, frozenset()):
            queue = self._queues.get(other)
            if queue:
                return True
        return False

    def _conflict_blocked(self, profile: str) -> bool:
        with self._lock:
            if self._creative_blocks(profile):
                return True
            for other in self.conflicts.get(profile, frozenset()):
                if other in self._draining or self._active[other] > 0 or self._resident.get(other):
                    return True
            return False

    def _ensure_ready(self, profile: str, request_id: str, now: float, report: dict[str, Any]) -> None:
        with self._lock:
            if self._operator_maintenance:
                return
            if self._creative_blocks(profile) or profile in self._draining or profile in self._dispatch_checks or (profile in self._ensuring):
                return
            self._ensuring.add(profile)
        try:
            try:
                reply = validate_ensure_ready_reply(self.facade.ensure_ready(profile=profile, request_id=request_id))
            except Exception as exc:
                reply = None
                error = type(exc).__name__
            else:
                error = None
            report['ensured'].append({'profile': profile, 'ready': bool(reply and reply['ready']), 'reason': reply['reason_code'] if reply else f'facade_error_{error}'})
            mismatch = False
            ready_event_generation = None
            with self._lock:
                if profile in self._draining:
                    return
                if reply is None:
                    self._ready[profile] = False
                    self._ensure_reason[profile] = f'facade_error_{error}'
                elif reply['available'] and reply['ready']:
                    expected = self.config.backends[profile].expected_model_id
                    if reply['model_id'] != expected:
                        self._ready[profile] = False
                        self._ensure_reason[profile] = 'facade_model_mismatch'
                        mismatch = True
                    else:
                        old_generation = self._generation.get(profile)
                        if not self._resident.get(profile):
                            self._resident[profile] = True
                            self._resident_since[profile] = now
                            ready_event_generation = reply['generation']
                        self._ready[profile] = True
                        self._generation[profile] = reply['generation']
                        self._model_id[profile] = reply['model_id']
                        self._ensure_reason[profile] = 'ready'
                        if old_generation != reply['generation']:
                            self._drain_attempts.pop(profile, None)
                else:
                    self._ready[profile] = False
                    self._ensure_reason[profile] = reply['reason_code']
            if reply is None:
                report['errors'].append({'profile': profile, 'error': error})
            if mismatch:
                self.store.record_event('facade_model_mismatch', profile=profile, reason_code='facade_model_mismatch', detail=f'expected={self.config.backends[profile].expected_model_id}')
            elif ready_event_generation is not None:
                self.store.record_event('facade_ready', profile=profile, generation=ready_event_generation)
        finally:
            with self._lock:
                self._ensuring.discard(profile)
                self._cv.notify_all()

    def _check_health(self, profile: str, now: float) -> None:
        backend = self.config.backends[profile]
        try:
            result = self.probe_backend(backend)
        except Exception as exc:
            result = {'ok': False, 'reason_code': f'backend_probe_error_{type(exc).__name__}', 'model_ids': []}
        if not isinstance(result, dict):
            result = {'ok': False, 'reason_code': 'backend_health_malformed', 'model_ids': []}
        model_ids = result.get('model_ids')
        if not isinstance(model_ids, list):
            model_ids = []
        expected = backend.expected_model_id
        valid_identity = isinstance(expected, str) and bool(expected.strip()) and (result.get('ok') is True) and (expected in model_ids)
        reason = str(result.get('reason_code') or ('ok' if valid_identity else 'backend_unreachable'))
        if not valid_identity and reason == 'ok':
            reason = 'backend_model_mismatch'
        with self._lock:
            if profile in self._draining:
                return
            self._health[profile] = {'ok': valid_identity, 'reason_code': reason, 'model_ids': model_ids, 'checked_at': now}
        if not valid_identity:
            self.store.record_event('backend_health_failed', profile=profile, reason_code=reason)

    def _drain(self, profile: str, now: float, *, reason: str) -> dict[str, Any] | None:
        with self._lock:
            if self._operator_maintenance or (self._creative_blocks(profile) and reason != 'creative_yield') or profile in self._draining or (profile in self._ensuring) or (profile in self._dispatch_checks) or (self._active[profile] != 0) or (profile in self._uncertain) or (not self._resident.get(profile)):
                return None
            if reason == 'keep_warm_expired' and (self._queues.get(profile) or profile in self._contested_since):
                return None
            if reason == 'contested_queue' and (profile not in self._contested_since or not self._has_conflicting_waiter(profile)):
                return None
            cached_generation = self._generation.get(profile)
            previous_attempt = self._drain_attempts.get(profile)
            attempts = previous_attempt[1] if previous_attempt and previous_attempt[0] == cached_generation else 0
            if attempts >= MAX_DRAIN_ATTEMPTS:
                self._last_reason[profile] = 'drain_attempt_limit'
                return None
            self._drain_attempts[profile] = (cached_generation, attempts + 1)
            self._last_drain_attempt[profile] = now
            active_before = self._active[profile]
            self._draining.add(profile)
        try:
            self.store.record_event('drain_requested', profile=profile, generation=cached_generation, reason_code=reason)
            try:
                generation_reply = validate_generation_reply(self.facade.get_generation(profile=profile))
            except Exception:
                generation_reply = validate_generation_reply(None)
            live_generation = generation_reply['generation']
            if not generation_reply['available'] or type(live_generation) is not int or live_generation <= 0 or (not generation_reply['ready']) or (generation_reply['state'].upper() != 'READY'):
                return self._drain_refused(profile, reason, 'facade_generation_unavailable', not_ready=True)
            try:
                health = validate_health_reply(self.facade.health(profile=profile))
            except Exception:
                health = validate_health_reply(None)
            expected_model = self.config.backends[profile].expected_model_id
            if not health['available'] or not health['known'] or health['active_requests'] != 0 or (health['generation'] != live_generation) or (not health['ready']) or (health['model_id'] != expected_model):
                return self._drain_refused(profile, reason, 'facade_health_identity_unconfirmed', not_ready=True)
            try:
                backend_health = self.probe_backend(self.config.backends[profile])
            except Exception:
                backend_health = None
            backend_model_ids = backend_health.get('model_ids') if isinstance(backend_health, dict) else None
            if not isinstance(backend_model_ids, list) or backend_health.get('ok') is not True or expected_model not in backend_model_ids:
                return self._drain_refused(profile, reason, 'backend_model_identity_unconfirmed', not_ready=True)
            with self._lock:
                if profile not in self._draining or self._active[profile] != active_before or active_before != 0 or (profile in self._uncertain) or (self._generation.get(profile) != cached_generation):
                    self._mark_uncertain_locked(profile, 'drain_raced', not_ready=True)
                    raced = True
                else:
                    raced = False
                    self._generation[profile] = live_generation
                    self._model_id[profile] = expected_model
                    self._ready[profile] = True
                    self._health[profile] = {'ok': True, 'reason_code': 'ok', 'model_ids': backend_model_ids, 'checked_at': now}
                    if live_generation != cached_generation:
                        self._drain_attempts[profile] = (live_generation, 1)
            if raced:
                self.store.record_event('drain_raced', profile=profile, generation=live_generation)
                return {'profile': profile, 'stopped': False, 'reason': reason, 'reason_code': 'drain_raced'}
            try:
                raw = self.facade.safe_drain_and_stop(profile=profile, generation=live_generation, reason=reason)
            except Exception as exc:
                return self._drain_refused(profile, reason, f'facade_error_{type(exc).__name__}', not_ready=True)
            reply = validate_drain_reply(raw, expected_generation=live_generation)
            if not (reply['available'] and reply['stopped']):
                return self._drain_refused(profile, reason, reply['reason_code'])
            with self._lock:
                raced = self._active[profile] != active_before or active_before != 0 or profile in self._uncertain or (self._generation.get(profile) != live_generation) or (profile not in self._draining)
                if raced:
                    self._mark_uncertain_locked(profile, 'drain_raced', not_ready=True)
                else:
                    self._ready[profile] = False
                    self._resident[profile] = False
                    self._resident_since.pop(profile, None)
                    self._generation[profile] = None
                    self._model_id[profile] = None
                    self._health.pop(profile, None)
                    self._contested_since.pop(profile, None)
                    self._drain_attempts.pop(profile, None)
            if raced:
                self.store.record_event('drain_raced', profile=profile, generation=live_generation)
                return {'profile': profile, 'stopped': False, 'reason': reason, 'reason_code': 'drain_raced'}
            self.store.record_event('drain_done', profile=profile, generation=live_generation, reason_code=reason)
            return {'profile': profile, 'stopped': True, 'reason': reason, 'reason_code': reply['reason_code']}
        finally:
            with self._lock:
                self._draining.discard(profile)
                self._cv.notify_all()

    def _drain_refused(self, profile: str, reason: str, reason_code: str, *, not_ready: bool=False) -> dict[str, Any]:
        with self._lock:
            self._mark_uncertain_locked(profile, reason_code, not_ready=not_ready)
        self.store.record_event('drain_refused', profile=profile, reason_code=reason_code)
        return {'profile': profile, 'stopped': False, 'reason': reason, 'reason_code': reason_code}

    def _close_reconciling_requests(self, profile: str) -> int:
        closed = 0
        for row in self.store.requests_in_states({'reconciling'}):
            if row['profile'] != profile:
                continue
            self.store.finish_request(row['request_id'], state='failed', reason_code='reconciled_engine_idle', uncertain=True)
            closed += 1
        return closed

    def status(self) -> dict[str, Any]:
        with self._lock:
            profiles: dict[str, Any] = {}
            for name in sorted(self.config.backends):
                profiles[name] = {'alias_profiles': sorted((a for a, m in self.config.models.items() if m.profile == name)), 'ready': bool(self._ready.get(name)), 'resident': bool(self._resident.get(name)), 'generation': self._generation.get(name), 'active': int(self._active.get(name, 0)), 'queued': len(self._queues.get(name, ())), 'uncertain': name in self._uncertain, 'settlement_failures': {rid: stage for rid, (profile, stage) in self._settlement_failures.items() if profile == name}, 'contested_since': self._contested_since.get(name), 'reason_code': self._ensure_reason.get(name), 'wait_reason': self._last_reason.get(name), 'conflicts_with': sorted(self.conflicts.get(name, ())), 'draining': name in self._draining, 'drain_attempts': self._drain_attempts.get(name, (None, 0))[1]}
            return {'profiles': profiles, 'operator_maintenance': self._operator_maintenance}

    def active_count(self, profile: str) -> int:
        with self._lock:
            return int(self._active.get(profile, 0))

    def queued_count(self, profile: str) -> int:
        with self._lock:
            return len(self._queues.get(profile, ()))

    def bind_creative_manager(self, manager: Any) -> None:
        """Called once by the sole factory before listening/maintenance starts."""
        with self._lock:
            if self.manager is not None or manager is None:
                raise RuntimeError('sole_manager_binding_required')
            if getattr(self.facade, 'manager', None) is not manager:
                raise RuntimeError('same_facade_manager_required')
            self.manager = manager
            view = manager.store.profile_view('image-turbo-c')
            if view.get('owner') is not None:
                self._creative = {'job_id': None, 'generation': view['generation'], 'state': 'RECOVERY', 'token': object()}

    def _creative_profiles(self) -> set[str]:
        return {p for p, backend in self.config.backends.items() if 'spark-c' in backend.nodes}

    def _creative_blocks(self, profile: str) -> bool:
        if profile not in self._creative_profiles():
            return False
        if self._creative is not None:
            return True
        if self.manager is not None:
            node = self.manager.store.node_view('spark-c')
            return node.get('hold_profile') == 'image-turbo-c'
        return False

    def reserve_creative(self, job_id: str) -> object:
        with self._lock:
            if self._operator_maintenance:
                raise RuntimeError('operator_maintenance')
            if self.manager is None:
                raise RuntimeError('sole_manager_binding_required')
            peers = self._creative_profiles()
            if any((self._active[p] or p in self._uncertain or p in self._draining or (p in self._ensuring) or (p in self._dispatch_checks) for p in peers)):
                raise RuntimeError('creative_safe_boundary_pending')
            if self._creative is not None:
                if self._creative['job_id'] == job_id:
                    return self._creative['token']
                raise RuntimeError('creative_hold_or_recovery_present')
            token = object()
            self._creative = {'job_id': job_id, 'generation': None, 'state': 'INTENT', 'token': token}
            self._cv.notify_all()
            return token

    def assert_creative(self, job_id: str, token: object) -> dict[str, Any]:
        with self._lock:
            held = self._creative
            if held is None or held['token'] is not token or held['job_id'] != job_id:
                raise RuntimeError('creative_slot_identity_changed')
            if any((self._active[p] or p in self._uncertain or p in self._ensuring or (p in self._dispatch_checks) for p in self._creative_profiles())):
                raise RuntimeError('creative_slot_chat_race')
            return dict(held)

    def yield_for_creative(self, job_id: str, token: object) -> bool:
        """The reservation blocks new chat/ensure while original drain proves idle."""
        self.assert_creative(job_id, token)
        for profile in sorted(self._creative_profiles()):
            with self._lock:
                if self._has_fresh_lease(profile, self.clock()):
                    return False
                view = self.manager.store.profile_view(profile)
                if view.get('owner') is None:
                    continue
                if view.get('state') != 'READY' or view.get('owner') != 'dgx-hx-service':
                    return False
                self._resident[profile] = True
                self._generation[profile] = view['generation']
            result = self._drain(profile, self.clock(), reason='creative_yield')
            if not result or result.get('stopped') is not True:
                return False
            self.assert_creative(job_id, token)
        node = self.manager.store.node_view('spark-c')
        return node.get('hold_profile') is None and node.get('quarantined') is False

    def pin_creative(self, job_id: str, token: object, generation: int) -> None:
        with self._lock:
            self.assert_creative(job_id, token)
            if type(generation) is not int or generation <= 0:
                raise RuntimeError('creative_generation_required')
            old = self._creative['generation']
            if old not in (None, generation):
                raise RuntimeError('creative_generation_changed')
            self._creative.update(generation=generation, state='HELD')

    def cancel_creative_intent(self, job_id: str, token: object) -> None:
        """Drop only the scheduler intent before any Turbo lifecycle admission.

        An existing Qwen hold is allowed and stays untouched. No native/core
        resource release is performed by cancelling this in-memory intent.
        """
        with self._lock:
            held = self.assert_creative(job_id, token)
            view = self.manager.store.profile_view('image-turbo-c')
            node = self.manager.store.node_view('spark-c')
            if held['generation'] is not None or view.get('state') != 'STOPPED' or view.get('owner') is not None or (node.get('hold_profile') == 'image-turbo-c'):
                raise RuntimeError('only_unstarted_creative_intent_cancellable')
            self._creative = None
            self._cv.notify_all()

    def creative_uncertain(self, job_id: str, token: object) -> None:
        with self._lock:
            self.assert_creative(job_id, token)
            self._creative['state'] = 'UNCERTAIN'

    def release_creative(self, job_id: str, token: object) -> None:
        with self._lock:
            held = self.assert_creative(job_id, token)
            view = self.manager.store.profile_view('image-turbo-c')
            node = self.manager.store.node_view('spark-c')
            if view.get('state') != 'STOPPED' or view.get('owner') is not None or node.get('hold_profile') is not None:
                raise RuntimeError('creative_positive_lifecycle_release_required')
            self._creative = None
            self._cv.notify_all()
