# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Manager-backed lifecycle seam for the HX gateway.

The facade owns one immutable service identity. Caller identities and evidence
never enter control-plane lifecycle calls.
"""
from __future__ import annotations
import http.client
import json
import math
import re
import threading
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Protocol
from control_plane import manager as control_manager
from control_plane.store import READY_RESUME_FAILED_REASONS, COLD_RECOVERY_REASON
from llm_gateway import upstream
_REASON_RE = re.compile('[a-z][a-z0-9_]{0,127}\\Z')
_TOKEN_RE = re.compile('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\\Z')
_LOOPBACK_HTTP_HOSTS = frozenset({'127.0.0.1', '::1'})
_MAX_PROBE_BYTES = 65536
_FUTURE_TOLERANCE_SECONDS = 0.0

@dataclass(frozen=True)
class ProfileBinding:
    """Trusted, immutable mapping from a gateway profile to its fixed model."""
    nodes: tuple[str, ...]
    expected_model_id: str
    enabled: bool
    active_work_path: str

class ActiveWorkProbe(Protocol):

    def probe_active(self, *, profile: str) -> Mapping[str, Any]:
        ...

class EngineProbeError(RuntimeError):

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code

class LoopbackActiveWorkProbe:
    """Read the fixed engine active-work endpoint without proxies or redirects."""

    def __init__(self, backends: Mapping[str, Any], paths: Mapping[str, str], *, timeout: float=5.0):
        self._backends = dict(backends)
        self._paths = dict(paths)
        self._timeout = timeout

    def probe_active(self, *, profile: str) -> Mapping[str, Any]:
        backend = self._backends.get(profile)
        path = self._paths.get(profile)
        if backend is None or not isinstance(path, str) or (not path):
            raise EngineProbeError('active_probe_unconfigured')
        if backend.host not in _LOOPBACK_HTTP_HOSTS:
            raise EngineProbeError('unsafe_backend_host')
        try:
            authorization = upstream._load_auth_header(backend)
        except Exception as exc:
            raise EngineProbeError('backend_auth_unavailable') from exc
        if not authorization:
            raise EngineProbeError('backend_auth_required')
        conn: http.client.HTTPConnection | None = None
        try:
            conn = http.client.HTTPConnection(backend.host, backend.port, timeout=self._timeout)
            conn.request('GET', path, headers={'Accept': 'application/json', 'Authorization': authorization, 'Connection': 'close'})
            response = conn.getresponse()
            if response.status in {301, 302, 303, 307, 308} or response.getheader('Location') is not None:
                raise EngineProbeError('backend_redirect_refused')
            raw = response.read(_MAX_PROBE_BYTES + 1)
            if len(raw) > _MAX_PROBE_BYTES:
                raise EngineProbeError('active_probe_oversize')
            if response.status != 200:
                raise EngineProbeError('active_probe_http_error')
        except EngineProbeError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise EngineProbeError('active_probe_unavailable') from exc
        finally:
            if conn is not None:
                conn.close()
        try:
            document = json.loads(raw.decode('utf-8'), object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant, parse_float=_finite_float)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OverflowError) as exc:
            raise EngineProbeError('active_probe_malformed') from exc
        if not isinstance(document, dict):
            raise EngineProbeError('active_probe_malformed')
        return document

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result

def _reject_constant(_value: str) -> Any:
    raise ValueError('non-finite JSON number')

def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('non-finite JSON number')
    return value

def _reason(value: Any, default: str) -> str:
    if isinstance(value, str) and _REASON_RE.fullmatch(value):
        return value
    return default

def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value

def _timestamp_fresh(value: Any, *, now: float, max_age: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        finite = math.isfinite(value)
    except OverflowError:
        return False
    return finite and value <= now + _FUTURE_TOLERANCE_SECONDS and (now - value <= max_age)

def _clean_exception_reason(exc: BaseException, default: str) -> str:
    return _reason(getattr(exc, 'code', None) or getattr(exc, 'reason_code', None), default)

def _worker_process_proof(item: Mapping[str, Any]) -> bool:
    """Worker-role pinned-image evidence: adapter-verified live process proof.

    The node adapter reports healthy workers as ``role: worker`` with
    ``process_verified: true`` and a ``worker_proof`` bound to the pinned
    container/image; such a node never carries a ``model_id``. This is positive
    pinned-model evidence for that node, never a bare reachability pass.
    """
    return item.get('role') == 'worker' and item.get('process_verified') is True and isinstance(item.get('worker_proof'), Mapping)

class ManagerBackendFacade:
    """Four-method gateway facade backed by the accepted Manager and NodeAdapter."""

    def __init__(self, *, manager: Any, adapter: Any, service_owner: str, profiles: Mapping[str, ProfileBinding], active_work_probe: ActiveWorkProbe, clock: Any=time.time):
        if not _TOKEN_RE.fullmatch(service_owner):
            raise ValueError('service_owner must be a fixed opaque token')
        if getattr(manager, 'adapter', None) is not adapter or getattr(manager, 'adapter_explicit', False) is not True:
            raise ValueError('facade requires the exact explicitly injected Manager adapter')
        if getattr(manager, 'allow_fixture_ready', True) is not False or getattr(manager, 'allow_test_holds', True) is not False:
            raise ValueError('fixture lifecycle opt-ins are forbidden')
        for name in ('capabilities', 'probe', 'probe_ready', 'start', 'stop', 'confirm_stop', 'release'):
            if not callable(getattr(adapter, name, None)):
                raise ValueError(f'explicit adapter lacks public method {name}')
        if not callable(getattr(active_work_probe, 'probe_active', None)):
            raise ValueError('a fixed active-work probe is required')
        copied: dict[str, ProfileBinding] = {}
        for profile, binding in profiles.items():
            if not isinstance(profile, str) or not _TOKEN_RE.fullmatch(profile):
                raise ValueError('invalid trusted profile name')
            if not isinstance(binding, ProfileBinding) or not isinstance(binding.expected_model_id, str) or (not binding.expected_model_id.strip()) or (not isinstance(binding.enabled, bool)) or (not isinstance(binding.active_work_path, str)) or (not isinstance(binding.nodes, (tuple, list))) or (not binding.nodes) or any((not isinstance(node, str) or not _TOKEN_RE.fullmatch(node) for node in binding.nodes)) or (len(set(binding.nodes)) != len(binding.nodes)):
                raise ValueError(f'invalid trusted profile binding for {profile}')
            copied[profile] = ProfileBinding(nodes=tuple(binding.nodes), expected_model_id=binding.expected_model_id, enabled=binding.enabled, active_work_path=binding.active_work_path)
        if not copied:
            raise ValueError('at least one explicit profile binding is required')
        self.manager = manager
        self.adapter = adapter
        self.service_owner = service_owner
        self.profiles = MappingProxyType(copied)
        self.active_work_probe = active_work_probe
        self._clock = clock
        self._lifecycle_lock = threading.RLock()

    def ensure_ready(self, *, profile: str, request_id: str) -> dict[str, Any]:
        del request_id
        binding = self.profiles.get(profile)
        if binding is None:
            return self._ready_failure(False, 'unknown_profile')
        if not binding.enabled:
            return self._ready_failure(True, 'profile_disabled')
        with self._lifecycle_lock:
            if not self._adapter_available():
                return self._ready_failure(False, 'adapter_unavailable')
            try:
                view = self.manager.store.profile_view(profile)
            except Exception as exc:
                return self._ready_failure(False, _clean_exception_reason(exc, 'profile_state_unavailable'))
            if not self._qualified(view, binding):
                return self._ready_failure(True, 'profile_not_qualified')
            if view.get('state') == 'READY':
                if view.get('owner') != self.service_owner:
                    return self._ready_failure(True, 'profile_owner_mismatch')
                generation = _positive_int(view.get('generation'))
                if generation is None:
                    return self._ready_failure(True, 'profile_generation_unknown')
                ready, reason = self._actual_readiness(profile, binding, generation)
                if not ready:
                    return self._ready_failure(True, reason, generation=generation)
                return self._ready_success(generation, binding.expected_model_id)
            state = view.get('state')
            if state in {'DRAINING', 'STOPPING', 'QUARANTINED'}:
                return self._ready_failure(True, 'profile_busy_or_uncertain')
            if state in {'STARTING', 'RECONCILING', 'FAILED'}:
                return self._ensure_pending(profile, binding, view, state)
            if state != 'STOPPED' or view.get('owner') is not None:
                return self._ready_failure(True, 'profile_busy_or_uncertain')
            samples, sample_reason = self._collect_memory_samples(binding)
            if samples is None:
                return self._ready_failure(True, sample_reason)
            now = float(self._clock())
            try:
                needed = max(1, int(self.manager.store.policy_value('memory_samples_required', 3)))
                max_age = float(self.manager.store.policy_sample_max_age())
                gate_ok, _gate_reason = control_manager.memory_ready(self.manager.store.memory_view(profile), samples, now=now, required_count=needed, max_age=max_age)
            except Exception:
                return self._ready_failure(True, 'memory_gate_unavailable')
            if not gate_ok:
                return self._ready_failure(True, 'memory_gate_refused')
            try:
                result = self.manager.start_profile(profile, owner=self.service_owner, samples=samples, now=now)
            except Exception as exc:
                return self._ready_failure(True, _clean_exception_reason(exc, 'manager_start_failed'))
            generation = _positive_int(result.get('generation')) if isinstance(result, dict) else None
            if not isinstance(result, dict) or result.get('started') is not True or generation is None:
                if isinstance(result, dict) and result.get('pending') is True:
                    return self._ready_failure(True, 'profile_starting', generation=generation)
                reason = _reason(result.get('reason_code'), 'manager_start_refused') if isinstance(result, dict) else 'manager_reply_malformed'
                return self._ready_failure(True, reason, generation=generation)
            if result.get('state') != 'READY':
                return self._ready_failure(True, 'manager_ready_not_confirmed', generation=generation)
            ready, reason = self._actual_readiness(profile, binding, generation)
            if not ready:
                return self._ready_failure(True, reason, generation=generation)
            return self._ready_success(generation, binding.expected_model_id)

    def _ensure_pending(self, profile: str, binding: ProfileBinding, view: Mapping[str, Any], state: str) -> dict[str, Any]:
        """Evidence-based completion for STARTING / RECONCILING / resumable FAILED.

        Only the exact recorded service owner may complete; unowned, foreign, or
        unknown records refuse without probing. The manager derives a fresh
        adapter ``probe_ready`` itself (pinned to this binding's model) and the
        store CAS atomically re-verifies prior state, generation, every node
        hold, and quarantine before publishing READY. This path never calls
        ``adapter.start``: a completion can never become a duplicate model
        start. An unhealthy but identity-exact probe stays pending (the
        scheduler keeps polling); a STARTING load past the manager's bounded
        pending deadline is failed held.
        """
        if view.get('owner') != self.service_owner:
            return self._ready_failure(True, 'profile_busy_or_uncertain')
        generation = _positive_int(view.get('generation'))
        if generation is None:
            return self._ready_failure(True, 'profile_busy_or_uncertain')
        if state == 'FAILED' and view.get('reason') not in READY_RESUME_FAILED_REASONS:
            return self._ready_failure(True, 'profile_busy_or_uncertain', generation=generation)
        allow_states = {'FAILED'} if state == 'FAILED' else {'STARTING', 'RECONCILING'}
        try:
            result = self.manager.complete_readiness(profile, owner=self.service_owner, from_states=allow_states, expected_model_id=binding.expected_model_id, enforce_pending_deadline=state == 'STARTING' or (state == 'RECONCILING' and view.get('reason') == COLD_RECOVERY_REASON))
        except Exception as exc:
            return self._ready_failure(True, _clean_exception_reason(exc, 'readiness_completion_unavailable'), generation=generation)
        if not isinstance(result, dict) or result.get('completed') not in (True, False):
            return self._ready_failure(True, 'manager_reply_malformed', generation=generation)
        if result.get('completed') is True:
            if _positive_int(result.get('generation')) != generation:
                return self._ready_failure(True, 'profile_generation_or_owner_mismatch', generation=generation)
            ready, reason = self._actual_readiness(profile, binding, generation)
            if not ready:
                return self._ready_failure(True, reason, generation=generation)
            return self._ready_success(generation, binding.expected_model_id)
        code = _reason(result.get('reason_code'), 'profile_busy_or_uncertain')
        if code == 'readiness_pending':
            code = 'profile_starting' if state == 'STARTING' else 'profile_reconciling'
        return self._ready_failure(True, code, generation=generation)

    def get_generation(self, *, profile: str) -> dict[str, Any]:
        binding = self.profiles.get(profile)
        if binding is None:
            return self._generation_failure('unknown_profile')
        try:
            view = self.manager.store.profile_view(profile)
        except Exception as exc:
            return self._generation_failure(_clean_exception_reason(exc, 'profile_state_unavailable'))
        generation = _positive_int(view.get('generation'))
        state = view.get('state')
        if state != 'READY' or view.get('owner') != self.service_owner or generation is None:
            return {'available': True, 'generation': generation, 'ready': False, 'state': state if isinstance(state, str) else 'UNKNOWN', 'reason_code': 'profile_not_ready_or_not_owned'}
        ready, reason = self._actual_readiness(profile, binding, generation)
        return {'available': True, 'generation': generation, 'ready': ready, 'state': 'READY' if ready else 'UNKNOWN', 'reason_code': 'ready' if ready else reason}

    def health(self, *, profile: str) -> dict[str, Any]:
        binding = self.profiles.get(profile)
        if binding is None:
            return self._health_unknown(False, 'unknown_profile')
        if not self._adapter_available():
            return self._health_unknown(False, 'adapter_unavailable')
        try:
            view = self.manager.store.profile_view(profile)
        except Exception as exc:
            return self._health_unknown(False, _clean_exception_reason(exc, 'profile_state_unavailable'))
        generation = _positive_int(view.get('generation'))
        if view.get('state') != 'READY' or view.get('owner') != self.service_owner or generation is None:
            return self._health_unknown(True, 'profile_not_ready_or_not_owned')
        try:
            observation = self.active_work_probe.probe_active(profile=profile)
        except Exception as exc:
            return self._health_unknown(True, _clean_exception_reason(exc, 'active_probe_unavailable'))
        now = float(self._clock())
        try:
            max_age = float(self.manager.store.policy_sample_max_age())
        except Exception:
            return self._health_unknown(True, 'active_probe_policy_unavailable')
        if not isinstance(observation, Mapping):
            return self._health_unknown(True, 'active_probe_malformed')
        if observation.get('known') is not True:
            return self._health_unknown(True, 'active_count_unknown')
        if observation.get('profile') != profile:
            return self._health_unknown(True, 'active_probe_profile_mismatch')
        if _positive_int(observation.get('generation')) != generation:
            return self._health_unknown(True, 'active_probe_generation_mismatch')
        if observation.get('model_id') != binding.expected_model_id:
            return self._health_unknown(True, 'active_probe_model_mismatch')
        count = observation.get('active_requests')
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            return self._health_unknown(True, 'active_count_malformed')
        if not _timestamp_fresh(observation.get('observed_at'), now=now, max_age=max_age):
            return self._health_unknown(True, 'active_probe_stale')
        ready, _ready_reason = self._actual_readiness(profile, binding, generation)
        return {'available': True, 'known': True, 'active_requests': count, 'ready': ready, 'generation': generation, 'model_id': binding.expected_model_id, 'reason_code': 'ok' if ready else 'active_count_known_readiness_unknown'}

    def safe_drain_and_stop(self, *, profile: str, generation: int | None, reason: str) -> dict[str, Any]:
        del reason
        binding = self.profiles.get(profile)
        requested_generation = _positive_int(generation)
        if binding is None:
            return self._drain_failure(False, None, 'unknown_profile')
        if requested_generation is None:
            return self._drain_failure(True, None, 'generation_required')
        with self._lifecycle_lock:
            try:
                view = self.manager.store.profile_view(profile)
            except Exception as exc:
                return self._drain_failure(False, None, _clean_exception_reason(exc, 'profile_state_unavailable'))
            current_generation = _positive_int(view.get('generation'))
            if current_generation != requested_generation:
                self._audit_pending(profile, requested_generation, 'stale_generation')
                return self._drain_failure(True, None, 'stale_generation')
            if view.get('owner') != self.service_owner:
                self._audit_pending(profile, requested_generation, 'stale_owner')
                return self._drain_failure(True, None, 'stale_owner')
            if view.get('state') != 'READY':
                self._audit_pending(profile, requested_generation, 'profile_not_ready')
                return self._drain_failure(True, requested_generation, 'profile_not_ready')
            health = self.health(profile=profile)
            if health.get('available') is not True or health.get('known') is not True or health.get('active_requests') != 0 or (health.get('generation') != requested_generation) or (health.get('model_id') != binding.expected_model_id):
                code = 'active_work_present' if health.get('known') is True and health.get('active_requests') != 0 else _reason(health.get('reason_code'), 'active_work_unknown')
                self._audit_pending(profile, requested_generation, code)
                return self._drain_failure(True, None, code)
            try:
                stopped = self.manager.stop_profile(profile, owner=self.service_owner, expected_generation=requested_generation, actor=self.service_owner)
            except Exception as exc:
                code = _clean_exception_reason(exc, 'manager_stop_failed')
                self._audit_pending(profile, requested_generation, code)
                return self._drain_failure(True, None, code)
            if not self._positive_manager_stop(stopped, profile, requested_generation):
                code = _reason(stopped.get('reason_code'), 'manager_stop_unconfirmed') if isinstance(stopped, dict) else 'manager_stop_reply_malformed'
                self._audit_pending(profile, requested_generation, code)
                return self._drain_failure(True, None, code)
            try:
                node_release = self.adapter.release(profile, nodes=list(binding.nodes), generation=requested_generation)
            except Exception as exc:
                code = _clean_exception_reason(exc, 'node_release_failed')
                self._audit_pending(profile, requested_generation, code)
                return self._drain_failure(True, None, code)
            if not self._positive_node_release(node_release, profile, binding, requested_generation):
                code = 'node_release_unconfirmed'
                self._audit_pending(profile, requested_generation, code)
                return self._drain_failure(True, None, code)
            try:
                core_release = self.manager.release_profile(profile, owner=self.service_owner, generation=requested_generation)
            except Exception as exc:
                code = _clean_exception_reason(exc, 'core_release_failed')
                self._audit_pending(profile, requested_generation, code)
                return self._drain_failure(True, None, code)
            if not self._positive_core_release(core_release, profile, binding, requested_generation):
                self._audit_pending(profile, requested_generation, 'core_release_unconfirmed')
                return self._drain_failure(True, None, 'core_release_unconfirmed')
            return {'available': True, 'stopped': True, 'generation': requested_generation, 'reason_code': 'drained'}

    def _adapter_available(self) -> bool:
        try:
            capabilities = self.adapter.capabilities()
            return isinstance(capabilities, Mapping) and capabilities.get('available') is True and (capabilities.get('fixture_only') is not True)
        except Exception:
            return False

    @staticmethod
    def _qualified(view: Mapping[str, Any], binding: ProfileBinding) -> bool:
        stored_nodes = view.get('nodes')
        if view.get('hardware_validated') is not True or not isinstance(stored_nodes, (list, tuple)) or tuple(stored_nodes) != binding.nodes:
            return False
        calibration = view.get('min_start_available_gib')
        if not isinstance(calibration, Mapping) or set(calibration) != set(binding.nodes):
            return False
        for node in binding.nodes:
            value = calibration.get(node)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return False
            try:
                finite = math.isfinite(value)
            except OverflowError:
                return False
            if not finite or value <= 0:
                return False
        return True

    def _collect_memory_samples(self, binding: ProfileBinding) -> tuple[dict[str, list[dict[str, Any]]] | None, str]:
        try:
            count = max(1, int(self.manager.store.policy_value('memory_samples_required', 3)))
        except Exception:
            return (None, 'memory_sample_policy_unavailable')
        samples: dict[str, list[dict[str, Any]]] = {}
        for node in binding.nodes:
            sequence: list[dict[str, Any]] = []
            for _ in range(count):
                try:
                    result = self.adapter.probe(node)
                except Exception as exc:
                    return (None, _clean_exception_reason(exc, 'memory_probe_unavailable'))
                if not isinstance(result, Mapping) or result.get('reachable') is not True or result.get('healthy') is not True:
                    return (None, 'memory_probe_unknown')
                memory = result.get('memory')
                available = memory.get('mem_available_bytes') if isinstance(memory, Mapping) else None
                total = memory.get('mem_total_bytes') if isinstance(memory, Mapping) else None
                stamp = result.get('observed_at')
                try:
                    max_age = float(self.manager.store.policy_sample_max_age())
                except Exception:
                    return (None, 'memory_sample_policy_unavailable')
                if isinstance(total, bool) or not isinstance(total, int) or total <= 0 or isinstance(available, bool) or (not isinstance(available, int)) or (available < 0) or (available > total) or (not _timestamp_fresh(stamp, now=float(self._clock()), max_age=max_age)):
                    return (None, 'memory_probe_malformed_or_stale')
                try:
                    available_gib = available / 1024 ** 3
                except OverflowError:
                    return (None, 'memory_probe_malformed_or_stale')
                if not math.isfinite(available_gib):
                    return (None, 'memory_probe_malformed_or_stale')
                sequence.append({'timestamp': float(stamp), 'available_gib': available_gib, 'reachable': True})
            samples[node] = sequence
        return (samples, 'ok')

    def _actual_readiness(self, profile: str, binding: ProfileBinding, generation: int) -> tuple[bool, str]:
        try:
            before = self.manager.store.profile_view(profile)
            if before.get('state') != 'READY' or before.get('owner') != self.service_owner or _positive_int(before.get('generation')) != generation or (tuple(before.get('nodes', ())) != binding.nodes):
                return (False, 'profile_generation_or_owner_mismatch')
            reply = self.adapter.probe_ready(profile, nodes=list(binding.nodes), generation=generation, owner=self.service_owner)
            now = float(self._clock())
            max_age = float(self.manager.store.policy_sample_max_age())
            if not isinstance(reply, Mapping):
                return (False, 'ready_probe_malformed')
            per_node = reply.get('nodes')
            if reply.get('healthy') is not True or reply.get('profile') != profile or reply.get('owner') != self.service_owner or (_positive_int(reply.get('generation')) != generation) or (reply.get('model_id') != binding.expected_model_id) or (not _timestamp_fresh(reply.get('observed_at'), now=now, max_age=max_age)) or (not isinstance(per_node, Mapping)) or (set(per_node) != set(binding.nodes)):
                return (False, 'ready_probe_identity_or_model_mismatch')
            for node in binding.nodes:
                item = per_node.get(node)
                if not isinstance(item, Mapping) or item.get('healthy') is not True:
                    return (False, 'ready_probe_node_unknown')
                if item.get('model_id') != binding.expected_model_id and (not _worker_process_proof(item)):
                    return (False, 'ready_probe_node_unknown')
                if not _timestamp_fresh(item.get('observed_at'), now=now, max_age=max_age):
                    return (False, 'ready_probe_node_unknown')
            after = self.manager.store.profile_view(profile)
            if after.get('state') != 'READY' or after.get('owner') != self.service_owner or _positive_int(after.get('generation')) != generation:
                return (False, 'profile_changed_during_ready_probe')
            return (True, 'ready')
        except Exception as exc:
            return (False, _clean_exception_reason(exc, 'ready_probe_unavailable'))

    def _audit_pending(self, profile: str, generation: int, reason: str) -> None:
        try:
            self.manager.store.audit('hx_release_pending', actor=self.service_owner, profile=profile, generation=generation, reason=_reason(reason, 'release_pending'))
        except Exception:
            pass

    @staticmethod
    def _positive_manager_stop(reply: Any, profile: str, generation: int) -> bool:
        return isinstance(reply, Mapping) and reply.get('stopped') is True and (reply.get('confirmed') is True) and (reply.get('profile') == profile) and (_positive_int(reply.get('generation')) == generation)

    @staticmethod
    def _positive_node_release(reply: Any, profile: str, binding: ProfileBinding, generation: int) -> bool:
        if not isinstance(reply, Mapping) or reply.get('released') is not True or reply.get('profile') != profile or (_positive_int(reply.get('generation')) != generation):
            return False
        outcomes = reply.get('nodes')
        return isinstance(outcomes, Mapping) and set(outcomes) == set(binding.nodes) and all((isinstance(item, Mapping) and item.get('released') is True for item in outcomes.values()))

    @staticmethod
    def _positive_core_release(reply: Any, profile: str, binding: ProfileBinding, generation: int) -> bool:
        if not isinstance(reply, Mapping) or reply.get('released') is not True or reply.get('profile') != profile or (_positive_int(reply.get('generation')) != generation):
            return False
        nodes = reply.get('nodes')
        return isinstance(nodes, (list, tuple)) and len(nodes) == len(binding.nodes) and all((isinstance(node, str) for node in nodes)) and (set(nodes) == set(binding.nodes))

    @staticmethod
    def _ready_failure(available: bool, reason: str, *, generation: int | None=None) -> dict[str, Any]:
        return {'available': available, 'ready': False, 'generation': generation, 'model_id': None, 'reason_code': _reason(reason, 'lifecycle_unavailable'), 'retry_after_seconds': None}

    @staticmethod
    def _ready_success(generation: int, model_id: str) -> dict[str, Any]:
        return {'available': True, 'ready': True, 'generation': generation, 'model_id': model_id, 'reason_code': 'ready', 'retry_after_seconds': None}

    @staticmethod
    def _generation_failure(reason: str) -> dict[str, Any]:
        return {'available': False, 'generation': None, 'ready': False, 'state': 'UNKNOWN', 'reason_code': _reason(reason, 'profile_unavailable')}

    @staticmethod
    def _health_unknown(available: bool, reason: str) -> dict[str, Any]:
        return {'available': available, 'known': False, 'active_requests': None, 'ready': False, 'generation': None, 'model_id': None, 'reason_code': _reason(reason, 'health_unknown')}

    @staticmethod
    def _drain_failure(available: bool, generation: int | None, reason: str) -> dict[str, Any]:
        return {'available': available, 'stopped': False, 'generation': generation, 'reason_code': _reason(reason, 'drain_refused')}
