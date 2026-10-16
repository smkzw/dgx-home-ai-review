# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""[REDACTED large text/source constant; see extracted source files]"""
from __future__ import annotations
import importlib.util
import math
import sys
from pathlib import Path
from typing import Any
from .adapter import NullAdapter, require_adapter
from .errors import AdapterUnavailableError, CapabilityDisabledError, ControlPlaneError, GenerationFenceError, NotValidatedError, ProfileStateError, QuarantinedError, StaleCompletionError, StaleMemorySampleError, ValidationError
from .store import Store, finite_number, positive_generation
MAX_JOB_PAYLOAD_BYTES = 256 * 1024
READINESS_PENDING_DEADLINE_SECONDS = 1800.0

def _load_memory_ready():
    """Reuse ``scripts/safety_contract.memory_ready`` unchanged (import, not copy)."""
    module_name = 'safety_contract'
    if module_name in sys.modules:
        return sys.modules[module_name].memory_ready
    for parent in Path(__file__).resolve().parents:
        candidate = parent / 'scripts' / 'safety_contract.py'
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location(module_name, candidate)
            if spec is None or spec.loader is None:
                break
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            sys.modules[module_name] = module
            return module.memory_ready
    raise ImportError('scripts/safety_contract.py not found; the control-plane core refuses to substitute its own memory gate')
memory_ready = _load_memory_ready()
KNOWN_WORKFLOWS = ('image.generate.v1', 'image.edit.v1', 'head.swap.bfs11.v1', 'video.generate.h3.v1')
FIXTURE_WORKFLOWS = ('noop', 'echo')

class Manager:
    """Single-owner orchestration facade used by the HTTP API and CLI.

    ``allow_fixture_ready`` and ``allow_test_holds`` exist ONLY for test
    harnesses. The loopback API is always constructed with both ``False``, so a
    fixture adapter can never publish ``READY`` nor create resource holds
    through the product surface.
    """

    def __init__(self, store: Store, *, adapter: Any | None=None, adapter_explicit: bool=False, allow_fixture_ready: bool=False, allow_test_holds: bool=False):
        self.store = store
        self.adapter = require_adapter(adapter if adapter is not None else NullAdapter())
        self.adapter_explicit = bool(adapter_explicit)
        self.allow_fixture_ready = bool(allow_fixture_ready)
        self.allow_test_holds = bool(allow_test_holds)
        self.readiness_pending_deadline = READINESS_PENDING_DEADLINE_SECONDS

    def _adapter_available(self) -> bool:
        return bool(self.adapter.capabilities().get('available'))

    def _fixture_only(self) -> bool:
        return bool(self.adapter.capabilities().get('fixture_only'))

    def capabilities(self) -> dict[str, Any]:
        caps = self.adapter.capabilities()
        available = bool(caps.get('available'))
        return {'contract_version': '1', 'service': 'dgx-v4-control-plane-core', 'production_ready': False, 'note': 'Offline-testable core only. No workflow executor, no G6 integration, no hardware validation. Workflows stay disabled until a real adapter is integrated and accepted.', 'lifecycle': {'adapter': caps.get('adapter'), 'available': available, 'fixture_only': bool(caps.get('fixture_only')), 'adapter_explicit': self.adapter_explicit, 'detail': caps.get('reason'), 'accepts_caller_evidence': False, 'ready_requires': ['adapter preflight', 'adapter start', 'adapter probe_ready'], 'release_requires': ['explicit expected generation', 'fresh adapter confirm_stop evidence']}, 'workflows': [{'id': wf, 'state': 'disabled'} for wf in KNOWN_WORKFLOWS] + [{'id': wf, 'state': 'test_only', 'note': 'fixture workflow; runs only via cli.py runjobs with an explicit adapter'} for wf in FIXTURE_WORKFLOWS], 'disabled_capabilities': ['workflow_execution', 'comfy_backend', 'asset_upload', 'artifact_streaming', 'model_start_stop_hardware', 'queue_policy_enforcement']}

    def require_workflow_enabled(self, workflow_id: str) -> None:
        """No executor exists in this core, so no workflow may be dispatched here.

        Product workflows and test-only fixture workflows are both refused with a
        distinct reason; neither is ever silently accepted.
        """
        if workflow_id in KNOWN_WORKFLOWS:
            raise CapabilityDisabledError('capability_disabled: no workflow executor is integrated in this core; refusing rather than faking output', details={'workflow_id': workflow_id})
        if workflow_id in FIXTURE_WORKFLOWS:
            raise CapabilityDisabledError('capability_disabled: fixture workflow without an executor; dispatch only via cli.py runjobs', details={'workflow_id': workflow_id, 'fixture_only': True})
        raise ValidationError(f'Unknown workflow_id {workflow_id!r}; only the v1 contract workflows are recognized', code='unknown_workflow')

    def _fail_state(self, profile: str, generation: int, reason: str, *, expected_owner: str | None=None, expected_states: frozenset[str] | set[str] | None=None) -> bool:
        """Record FAILED unless quarantined; hold-fenced when an owner is known.

        Returns True when the failure state was actually written. A hold-fenced
        write refuses with ``stale_completion`` when the reservation is no longer
        ours (e.g. a legitimate release happened during a slow adapter call), and
        the current state is then left untouched.
        """
        view = self.store.profile_view(profile)
        if view['state'] == 'QUARANTINED':
            self.store.audit('fail_skipped_quarantined', actor='system', profile=profile, generation=generation, reason=reason)
            return False
        try:
            self.store.set_profile_state(profile, 'FAILED', generation=generation, reason=reason, expected_owner=expected_owner, require_holds=expected_owner is not None, expected_states=expected_states)
        except (StaleCompletionError, GenerationFenceError, ProfileStateError, QuarantinedError) as exc:
            self.store.audit('stale_completion', actor='system', profile=profile, generation=generation, reason='failure completion no longer owns the reservation; state left unchanged', detail=str(exc))
            return False
        return True

    def start_profile(self, profile: str, *, owner: str, operation: str='start', samples: dict[str, list[dict[str, Any]]] | None=None, now: float | None=None) -> dict[str, Any]:
        """Ordered gate: reserve -> config/memory -> preflight -> start -> probe_ready -> READY.

        Fails closed at every step: null calibration, unvalidated profile, missing
        adapter, a fixture adapter without the test opt-in, absent/failed memory
        samples, a missing or negative preflight, or a probe that cannot name the
        exact profile/owner/generation all refuse before publishing anything.
        """
        if self._fixture_only() and (not self.allow_fixture_ready):
            self.store.audit('fixture_ready_refused', actor=owner, profile=profile, reason='fixture adapter cannot publish READY')
            return {'started': False, 'profile': profile, 'reason_code': 'fixture_adapter_cannot_publish_ready', 'detail': 'the configured adapter is a test fixture; READY may only be published by a real adapter (test harnesses must pass allow_fixture_ready=True explicitly)'}
        if not self._adapter_available():
            raise AdapterUnavailableError('adapter_unavailable: no lifecycle adapter is configured; refusing to start', details={'profile': profile, 'adapter': self.adapter.capabilities().get('adapter')})
        reservation = self.store.reserve_profile(profile, owner=owner, operation=operation)
        if not reservation.get('reserved'):
            return {'started': False, **reservation}
        generation = int(reservation['generation'])
        view = self.store.profile_view(profile)
        if not view['hardware_validated'] or view['min_start_available_gib'] is None:
            self._fail_state(profile, generation, 'profile not validated / calibration null', expected_owner=owner, expected_states={'STARTING'})
            raise NotValidatedError('profile_not_validated: hardware_validated must be true and per-node calibration present; null is unknown, never 0', details={'profile': profile})
        if samples is None or now is None:
            self._fail_state(profile, generation, 'no fresh memory samples', expected_owner=owner, expected_states={'STARTING'})
            raise StaleMemorySampleError('memory_samples_rejected: fresh per-node samples are required before start', details={'profile': profile})
        ok, reason = memory_ready(self.store.memory_view(profile), samples, now=now, required_count=_required_samples(self.store), max_age=float(_sample_max_age(self.store)))
        if not ok:
            self._fail_state(profile, generation, reason, expected_owner=owner, expected_states={'STARTING'})
            raise StaleMemorySampleError(f'memory_samples_rejected: {reason}', details={'profile': profile})
        preflight = self._run_preflight(profile, nodes=view['nodes'], generation=generation, owner=owner)
        if not preflight['clear']:
            self._fail_state(profile, generation, 'start preflight not clear', expected_owner=owner, expected_states={'STARTING'})
            return {'started': False, 'profile': profile, 'generation': generation, 'reason_code': 'preflight_failed', 'preflight': preflight}
        try:
            start_reply = self.adapter.start(profile, nodes=view['nodes'], generation=generation, env={'profile': profile, 'generation': generation, 'owner': owner})
        except Exception as exc:
            self._fail_state(profile, generation, f'adapter start failed: {exc}', expected_owner=owner, expected_states={'STARTING'})
            return {'started': False, 'profile': profile, 'generation': generation, 'reason_code': 'adapter_start_failed', 'detail': str(exc)}
        readiness = self._run_probe_ready(profile, nodes=view['nodes'], generation=generation, owner=owner)
        if not readiness['healthy'] and _readiness_is_pending(readiness, view['nodes']):
            try:
                self.store.set_profile_state(profile, 'STARTING', generation=generation, reason='adapter start accepted; readiness pending (model loading)', actor=owner, expected_owner=owner, require_holds=True, expected_states={'STARTING'})
            except ControlPlaneError as exc:
                self.store.audit('pending_state_write_refused', actor=owner, profile=profile, generation=generation, reason=getattr(exc, 'code', type(exc).__name__), detail=str(exc)[:512])
                return {'started': False, 'pending': False, 'profile': profile, 'generation': generation, 'state': self.store.profile_view(profile)['state'], 'reason_code': getattr(exc, 'code', 'pending_state_write_refused')}
            return {'started': False, 'pending': True, 'profile': profile, 'generation': generation, 'state': self.store.profile_view(profile)['state'], 'reason_code': 'readiness_pending', 'probe': readiness}
        if not readiness['healthy']:
            self._fail_state(profile, generation, 'post-start readiness probe failed', expected_owner=owner, expected_states={'STARTING'})
            return {'started': False, 'profile': profile, 'generation': generation, 'reason_code': 'probe_unhealthy', 'probe': readiness}
        try:
            self.store.complete_readiness(profile, owner=owner, generation=generation, from_states={'STARTING'}, actor=owner)
        except ControlPlaneError as exc:
            self.store.audit('readiness_completion_refused', actor=owner, profile=profile, generation=generation, reason=getattr(exc, 'code', type(exc).__name__), detail=str(exc)[:512])
            return {'started': False, 'profile': profile, 'generation': generation, 'state': self.store.profile_view(profile)['state'], 'reason_code': getattr(exc, 'code', 'readiness_completion_refused'), 'probe': readiness}
        return {'started': True, 'profile': profile, 'generation': generation, 'state': 'READY', 'adapter_reply': start_reply, 'preflight': preflight, 'probe': readiness}

    def _run_preflight(self, profile: str, *, nodes: list[str], generation: int, owner: str) -> dict[str, Any]:
        """Require a trustworthy, freshly observed clear-of-old-or-unknown preflight.

        The freshness clock is read immediately after the adapter returns and the
        same ``policy_sample_max_age()`` bound (and clock domain) used by the
        memory gate and release evidence is applied to the top-level *and*
        per-node ``observed_at`` values. Missing, bool, NaN/Inf, future or stale
        observations refuse the start and the actual reservation is retained
        (UNKNOWN never becomes READY).
        """
        max_age = float(self.store.policy_sample_max_age())
        try:
            reply = self.adapter.preflight(profile, nodes=nodes, generation=generation, owner=owner)
        except AdapterUnavailableError:
            return {'clear': False, 'reason_code': 'adapter_unavailable', 'nodes': {n: {'clear': False} for n in nodes}}
        now = self._now()
        return _validated_preflight(reply, profile=profile, nodes=nodes, generation=generation, owner=owner, now=now, max_age=max_age)

    def _run_probe_ready(self, profile: str, *, nodes: list[str], generation: int, owner: str) -> dict[str, Any]:
        """Require an identity-matching, healthy, freshly observed readiness probe.

        Same freshness/identity rules as the preflight: the observation must name
        this exact profile/owner/positive generation, cover exactly the requested
        nodes, and carry finite, non-future, non-stale timestamps. The adapter
        remains responsible for matching its exact pinned model via ``model_id``.
        """
        max_age = float(self.store.policy_sample_max_age())
        try:
            reply = self.adapter.probe_ready(profile, nodes=nodes, generation=generation, owner=owner)
        except AdapterUnavailableError:
            return {'healthy': False, 'reason_code': 'adapter_unavailable', 'nodes': {n: {'healthy': False} for n in nodes}}
        now = self._now()
        return _validated_ready(reply, profile=profile, nodes=nodes, generation=generation, owner=owner, now=now, max_age=max_age)

    def complete_readiness(self, profile: str, *, owner: str, from_states: frozenset[str] | set[str], expected_model_id: str | None=None, enforce_pending_deadline: bool=False) -> dict[str, Any]:
        """[REDACTED large text/source constant; see extracted source files]"""
        view = self.store.profile_view(profile)
        current_state = view['state']
        refused: dict[str, Any] = {'completed': False, 'profile': profile, 'state': current_state}
        if current_state not in from_states:
            return {**refused, 'reason_code': 'readiness_completion_state_refused'}
        try:
            generation = positive_generation(view['generation'])
        except ValidationError:
            return {**refused, 'reason_code': 'generation_unknown'}
        if view['owner'] != owner:
            return {**refused, 'reason_code': 'profile_owner_mismatch', 'generation': generation}
        if not self.store.still_owned(profile, owner=owner, generation=generation):
            return {**refused, 'reason_code': 'profile_hold_incomplete', 'generation': generation}
        nodes = view['nodes']
        readiness = self._run_probe_ready(profile, nodes=nodes, generation=generation, owner=owner)
        if readiness['healthy'] and expected_model_id is not None:
            pin_problems = _pinned_model_problems(readiness, nodes, expected_model_id)
            if pin_problems:
                readiness = {**readiness, 'healthy': False, 'reason_code': 'ready_refused', 'problems': list(readiness.get('problems') or []) + pin_problems}
        if not readiness['healthy']:
            if enforce_pending_deadline:
                started_at = self.store.reservation_started_at(profile, owner=owner, generation=generation)
                if started_at is not None and self._now() - started_at > float(self.readiness_pending_deadline):
                    wrote = self._fail_state(profile, generation, 'readiness pending deadline exceeded', expected_owner=owner, expected_states={current_state})
                    return {'completed': False, 'failed_held': wrote, 'state_written': wrote, 'profile': profile, 'generation': generation, 'state': self.store.profile_view(profile)['state'], 'reason_code': 'readiness_pending_deadline_exceeded', 'probe': readiness}
            return {**refused, 'generation': generation, 'reason_code': 'readiness_pending' if _readiness_is_pending(readiness, nodes) else 'ready_refused', 'probe': readiness}
        try:
            self.store.complete_readiness(profile, owner=owner, generation=generation, from_states=from_states, actor=owner)
        except ControlPlaneError as exc:
            self.store.audit('readiness_completion_refused', actor=owner, profile=profile, generation=generation, reason=getattr(exc, 'code', type(exc).__name__), detail=str(exc)[:512])
            return {**refused, 'generation': generation, 'reason_code': getattr(exc, 'code', 'readiness_completion_refused'), 'probe': readiness}
        return {'completed': True, 'profile': profile, 'generation': generation, 'state': 'READY', 'probe': readiness}

    def _probe_or_quarantine(self, profile: str, *, nodes: list[str], generation: int) -> dict[str, Any]:
        """Probe every node; a lost node is quarantined (generation-fenced) and held."""
        results: dict[str, Any] = {}
        all_reachable = True
        all_healthy = True
        for node in nodes:
            result = self.adapter.probe(node)
            results[node] = result
            self.store.touch_node(node)
            if result.get('reachable') is not True:
                all_reachable = False
                self.store.quarantine_node(node, reason='probe unreachable', observed_generation=generation)
            elif result.get('healthy') is not True:
                all_healthy = False
        return {'nodes': results, 'all_reachable': all_reachable, 'all_healthy': all_healthy}

    def stop_profile(self, profile: str, *, owner: str, expected_generation: int, actor: str | None=None) -> dict[str, Any]:
        """Owner/generation-scoped stop; STOPPED only on fresh positive confirmation.

        Sequence: atomic CAS (owner + exact expected generation + per-node holds)
        -> DRAINING -> STOPPING -> adapter stop -> fresh complete ``confirm_stop``
        -> hold-fenced STOPPED publish. The publish re-asserts inside one write
        transaction that this exact owner+generation still holds every node, so a
        slow stop that finishes after a legitimate release reports a stale
        completion and leaves the current state untouched (no fabricated
        lifecycle fact, no downgrade of freed or re-owned state).

        When the stop is not positively confirmed, per-node outcomes are
        persisted in the audit log and in the profile reason: a node that is
        known and still running keeps its hold with a ``run_uncertain`` marker, a
        node whose observation failed is quarantined. ``STOPPED`` is never
        published and no overbroad kill or independent restart is attempted.
        """
        expected_generation = positive_generation(expected_generation)
        gate = self.store.begin_stop(profile, owner=owner, expected_generation=expected_generation, actor=actor or owner)
        nodes = gate['nodes']
        try:
            self.store.set_profile_state(profile, 'STOPPING', generation=expected_generation, reason='adapter stop requested', actor=actor or owner, expected_owner=owner, require_holds=True)
        except (StaleCompletionError, GenerationFenceError) as exc:
            self.store.audit('stale_completion', actor=actor or owner, profile=profile, generation=expected_generation, reason='stop reservation changed before adapter dispatch; state left unchanged', detail=str(exc))
            return {'stopped': False, 'stale_completion': True, 'state_unchanged': True, 'hold_retained': False, 'profile': profile, 'generation': expected_generation, 'reason_code': 'stale_completion'}
        try:
            reply = self.adapter.stop(profile, nodes=nodes, generation=expected_generation)
        except Exception as exc:
            reason = f'adapter stop failed ({type(exc).__name__}): {exc}'[:512]
            self.store.audit('stop_failed', actor=actor or owner, profile=profile, generation=expected_generation, reason=reason[:512])
            wrote = self._fail_state(profile, expected_generation, reason, expected_owner=owner)
            return {'stopped': False, 'profile': profile, 'generation': expected_generation, 'reason_code': 'adapter_unavailable' if isinstance(exc, AdapterUnavailableError) else 'adapter_stop_failed', 'hold_retained': self.store.still_owned(profile, owner=owner, generation=expected_generation), 'state_updated': wrote, 'state_unchanged': not wrote}
        self.store.audit('stop_request', actor=actor or owner, profile=profile, generation=expected_generation, detail=f'adapter_reply={reply}')
        raw, confirmed = self._confirm_stop_observation(profile, generation=expected_generation)
        if confirmed is not None:
            try:
                self.store.set_profile_state(profile, 'STOPPED', generation=expected_generation, reason='stop positively confirmed', actor=actor or owner, expected_owner=owner, require_holds=True)
            except (StaleCompletionError, GenerationFenceError) as exc:
                self.store.audit('stale_completion', actor=actor or owner, profile=profile, generation=expected_generation, reason='stop finished after the hold was legitimately released; state left unchanged', detail=f'adapter_stop={reply}; {exc}')
                return {'stopped': False, 'confirmed': True, 'stale_completion': True, 'state_unchanged': True, 'hold_retained': False, 'profile': profile, 'generation': expected_generation, 'reason_code': 'stale_completion', 'adapter_reply': reply, 'confirmation': confirmed}
            return {'stopped': True, 'confirmed': True, 'profile': profile, 'generation': expected_generation, 'adapter_reply': reply, 'confirmation': confirmed}
        outcomes = _node_outcomes(raw, nodes)
        still_running = sorted((n for n, reason in outcomes.items() if reason == 'process_still_running'))
        failed_observation = sorted((n for n, reason in outcomes.items() if reason != 'process_still_running'))
        for node in failed_observation:
            try:
                self.store.quarantine_node(node, reason=f'stop unconfirmed: {outcomes[node]}', observed_generation=expected_generation, actor=actor or owner)
            except ControlPlaneError as exc:
                self.store.audit('quarantine_refused', actor=actor or owner, profile=profile, node=node, generation=expected_generation, reason=outcomes[node], detail=str(exc))
        reason = 'stop not confirmed (run_uncertain): ' + ', '.join((f'{n}={outcomes[n]}' for n in sorted(outcomes)))
        self.store.audit('stop_unconfirmed', actor=actor or owner, profile=profile, generation=expected_generation, reason=reason[:512], detail=f'still_running={still_running} failed_observation={failed_observation} adapter_reply={reply}')
        wrote = self._fail_state(profile, expected_generation, reason, expected_owner=owner)
        return {'stopped': False, 'confirmed': False, 'profile': profile, 'generation': expected_generation, 'reason_code': 'stop_unconfirmed', 'hold_retained': self.store.still_owned(profile, owner=owner, generation=expected_generation), 'node_outcomes': outcomes, 'still_running_nodes': still_running, 'failed_observation_nodes': failed_observation, 'state_updated': wrote, 'state_unchanged': not wrote, 'adapter_reply': reply}

    def _confirm_stop_observation(self, profile: str, *, generation: int) -> tuple[Any, dict[str, Any] | None]:
        """Raw and validated ``confirm_stop`` observation for one exact generation.

        Freshness is measured immediately after the adapter call, using the same
        clock domain and ``policy_sample_max_age()`` bound as the memory gate and
        release validation. Returns ``(raw_reply, None)`` when the adapter is
        unavailable or the observation is not usable, so callers can report the
        per-node reasons without ever turning them into evidence.
        """
        view = self.store.profile_view(profile)
        expected = positive_generation(generation)
        if int(view['generation']) != expected:
            raise GenerationFenceError('stale_generation: cannot derive evidence for a superseded generation', details={'requested_generation': expected, 'current_generation': view['generation']})
        nodes = view['nodes']
        try:
            reply = self.adapter.confirm_stop(profile, nodes=nodes, generation=expected)
        except AdapterUnavailableError:
            return (None, None)
        now = self._now()
        validated = _validated_confirmation(reply, nodes=nodes, generation=expected, profile=profile, now=now, max_age=float(self.store.policy_sample_max_age()))
        return (reply, validated)

    def confirmed_stop_evidence(self, profile: str, *, generation: int | None=None) -> dict[str, Any] | None:
        """Fresh adapter-derived stop evidence for one exact generation, or ``None``.

        The observation comes from a live ``confirm_stop`` call: requested profile,
        requested nodes, requested generation, per-node positive observation with
        the adapter's own timestamps. Nothing is cached, reused, or retimestamped.
        Unknown nodes and still-running processes yield ``None`` (which fails
        closed on release).
        """
        view = self.store.profile_view(profile)
        expected = positive_generation(generation if generation is not None else view['generation'])
        return self._confirm_stop_observation(profile, generation=expected)[1]

    def release_profile(self, profile: str, *, owner: str, generation: int, lose_quarantine: bool=False, override_reason: str | None=None) -> dict[str, Any]:
        """Release holds using ONLY live adapter-derived evidence.

        There is deliberately no ``evidence`` parameter: neither the HTTP API nor
        the CLI can supply stop observations. Evidence is obtained here from
        ``confirm_stop``; when it cannot be obtained the release is refused and
        the hold stays. Clearing a quarantine additionally needs a reasoned
        override, which is written to the audit log.
        """
        generation = positive_generation(generation)
        evidence = self.confirmed_stop_evidence(profile, generation=generation)
        if evidence is None:
            raise GenerationFenceError('adapter_confirmation_required: no fresh positive stop confirmation for every node; release refused and holds retained', code='adapter_confirmation_required', details={'profile': profile, 'generation': generation})
        return self.store.release_profile(profile, owner=owner, generation=generation, adapter_evidence=evidence, lose_quarantine=lose_quarantine, override_reason=override_reason)

    def _now(self) -> float:
        return float(self.store._clock())

    def reserve_admin(self, profile: str, *, owner: str, operation: str='maintenance', reason: str | None=None) -> dict[str, Any]:
        """Product-surface reservation. Refuses to create unreleasable holds.

        A hold can only be released with fresh positive stop evidence, which only
        an available, non-fixture adapter can produce. Therefore this path refuses
        when no safe adapter is configured instead of creating a hold the API
        could never release. Test holds belong to the local test tools
        (``Store.reserve_profile`` directly), not to the product API.
        """
        if operation not in {'start', 'maintenance'}:
            raise ValidationError('operation must be start|maintenance; test holds are local-only tools', code='invalid_operation')
        caps = self.adapter.capabilities()
        unsafe_fixture = caps.get('fixture_only') and (not self.allow_test_holds)
        if not caps.get('available') or unsafe_fixture:
            raise AdapterUnavailableError('adapter_unavailable_hold_refused: refusing to create a hold that no available safe adapter could ever confirm stopped', code='adapter_unavailable_hold_refused', details={'profile': profile, 'adapter': caps.get('adapter'), 'available': bool(caps.get('available')), 'fixture_only': bool(caps.get('fixture_only')), 'note': 'test holds belong to the local test tools, not the product API'})
        return self.store.reserve_profile(profile, owner=owner, operation=operation, reason=reason or f'admin {operation} reserve')

    def reconcile(self) -> dict[str, Any]:
        """Manager-start reconciliation: no SQLite state is trusted without probe evidence."""
        scan = self.store.recovery_scan()
        results: dict[str, Any] = {}
        for profile in scan['profiles_reconciling']:
            view = self.store.profile_view(profile)
            generation = int(view['generation'])
            try:
                probe = self._probe_or_quarantine(profile, nodes=view['nodes'], generation=generation)
            except AdapterUnavailableError as exc:
                self.store.set_profile_state(profile, 'QUARANTINED', generation=generation, reason=f'adapter_unavailable during reconcile: {exc}', actor='system')
                results[profile] = {'state': 'QUARANTINED', 'generation': generation, 'reason_code': 'adapter_unavailable'}
                continue
            if not probe['all_reachable']:
                results[profile] = {'state': self.store.profile_view(profile)['state'], 'generation': generation, 'reason_code': 'node_unreachable_hold_retained', 'probe': probe}
                continue
            results[profile] = {'state': self.store.profile_view(profile)['state'], 'generation': generation, 'reason_code': 'operator_decision_required', 'probe': probe}
        quarantined: dict[str, Any] = {}
        for profile in scan.get('quarantined_retained', []):
            view = self.store.profile_view(profile)
            quarantined[profile] = {'state': view['state'], 'generation': view['generation'], 'reason_code': 'quarantine_retained', 'note': 'quarantine is never cleared by recovery; it needs an evidenced release with a reasoned override'}
        return {'scan': scan, 'profiles': results, 'quarantined_retained': quarantined, 'jobs': scan['jobs_reconciling']}

    def submit_job(self, *, job_id: str, owner: str, request_key: str, workflow_id: str, inputs: dict[str, Any], parameters: dict[str, Any], parent_session_id: str | None=None, idempotency_key: str | None=None) -> dict[str, Any]:
        """Persist first; execution is deliberately absent in this core.

        The workflow capability check refuses dispatch, so a persisted job waits
        in ``waiting_resources`` with ``capability_disabled`` metadata: explicit
        and honest, never a fake result. Bodies are written as isolated 0600
        artifacts; SQLite stores only metadata and the digest, and no body or
        token is ever logged.
        """
        if idempotency_key is not None and idempotency_key != request_key:
            raise ValidationError('Idempotency-Key must equal request_key', code='idempotency_key_mismatch')
        payload = {'workflow_id': workflow_id, 'inputs': inputs, 'parameters': parameters, 'parent_session_id': parent_session_id}
        import json as _json
        from .store import canonical_digest
        blob = _json.dumps(payload, sort_keys=True, ensure_ascii=False).encode('utf-8')
        if len(blob) > MAX_JOB_PAYLOAD_BYTES:
            raise ValidationError('job payload exceeds the metadata limit', code='payload_too_large')
        digest = canonical_digest(payload)
        result = self.store.submit_job(job_id=job_id, owner=owner, request_key=request_key, workflow_id=workflow_id, payload_digest=digest, payload=payload, parent_session_id=parent_session_id)
        job = result['job']
        if result['idempotent_replay']:
            return result
        try:
            self.require_workflow_enabled(workflow_id)
        except CapabilityDisabledError:
            job = self.store.queue_job_for_resources(job['job_id'], reason_code='capability_disabled')
            job['reason_detail'] = 'no executor integrated: job persisted for lookup, never dispatched'
        return {'job': job, 'idempotent_replay': False}

    def run_jobs(self, *, profile: str, owner: str, runner: Any, limit: int=10) -> dict[str, Any]:
        """Operator-driven dispatch of queued jobs through a fixture runner.

        Every job is isolated: a concurrent cancel, a missing payload, a digest
        mismatch, or a runner error is recorded for that job and the loop
        continues, so one bad job can never block the rest of the batch. The
        lifecycle hold is only released when ``confirm_stop`` positively confirms
        the exact generation; engine uncertainty therefore retains the hold.
        """
        from .fixture_runner import load_payload
        rows = self.store.list_dispatchable_jobs()
        if not rows:
            return {'dispatched': [], 'skipped': [], 'note': 'no queued jobs'}
        reservation = self.store.reserve_profile(profile, owner=owner, operation='test', reason='fixture job batch (test operation)')
        if not reservation.get('reserved'):
            return {'dispatched': [], 'skipped': [], 'queued': True, 'reason_code': reservation.get('reason_code'), 'conflicts': reservation.get('conflicts')}
        generation = int(reservation['generation'])
        outcome: dict[str, Any] = {'profile': profile, 'generation': generation, 'dispatched': [], 'skipped': []}
        for row in rows[:int(limit)]:
            job_id = row['job_id']
            try:
                self._run_one_job(job_id, outcome, profile=profile, owner=owner, generation=generation, runner=runner, load_payload=load_payload)
            except Exception as exc:
                outcome['skipped'].append({'job_id': job_id, 'reason_code': f'unexpected: {type(exc).__name__}'})
        self._teardown_after_run(outcome, profile=profile, owner=owner, generation=generation)
        return outcome

    def _run_one_job(self, job_id: str, outcome: dict[str, Any], *, profile: str, owner: str, generation: int, runner: Any, load_payload: Any) -> None:
        current = self.store.job_row(job_id)
        if current['state'] not in {'queued', 'waiting_resources', 'waiting_session'}:
            outcome['skipped'].append({'job_id': job_id, 'state': current['state'], 'reason_code': 'not_dispatchable'})
            return
        try:
            self.store.mark_dispatched(job_id, profile=profile, generation=generation)
        except ProfileStateError as exc:
            outcome['skipped'].append({'job_id': job_id, 'state': self.store.job_view(job_id)['state'], 'reason_code': exc.code})
            return
        try:
            payload, digest = load_payload(self.store, job_id)
        except Exception as exc:
            self.store.finish_job(job_id, state='failed', reason_code=getattr(exc, 'code', 'payload_unavailable'))
            outcome['dispatched'].append({'job_id': job_id, 'state': 'failed', 'reason_code': getattr(exc, 'code', 'payload_unavailable')})
            return
        if digest != current['payload_digest']:
            self.store.finish_job(job_id, state='failed', reason_code='payload_digest_mismatch')
            outcome['dispatched'].append({'job_id': job_id, 'state': 'failed', 'reason_code': 'payload_digest_mismatch'})
            return
        try:
            result = runner.run(workflow_id=current['workflow_id'], parameters=payload.get('parameters', {}), payload_path=self.store.payload_path(job_id))
        except Exception as exc:
            view = self.store.finish_job(job_id, state='failed', reason_code=f'runner_error: {type(exc).__name__}')
            outcome['dispatched'].append({'job_id': job_id, 'state': view['state'], 'reason_code': view['reason_code'], 'overridden_by_cancellation': view['overridden_by_cancellation']})
            return
        view = self.store.finish_job(job_id, state='succeeded', stage='done', reason_code=None, artifact=result.get('artifact'))
        record: dict[str, Any] = {'job_id': job_id, 'state': view['state']}
        if view['overridden_by_cancellation']:
            record['overridden_by_cancellation'] = True
            record['engine_reported'] = view.get('engine_reported')
            record['reason_code'] = view['reason_code']
        else:
            record['artifact'] = bool(result.get('artifact'))
        outcome['dispatched'].append(record)

    def _teardown_after_run(self, outcome: dict[str, Any], *, profile: str, owner: str, generation: int) -> None:
        """Stop + release only when the profile is still ours at this generation.

        Release happens only through ``release_profile``, which requires a live,
        positive ``confirm_stop``; any uncertainty leaves the hold in place.
        """
        try:
            view = self.store.profile_view(profile)
            if view['owner'] != owner or int(view['generation']) != generation:
                outcome['released'] = False
                outcome['hold_retained'] = 'profile no longer owned by this run; teardown skipped'
                return
            stop = self.stop_profile(profile, owner=owner, expected_generation=generation, actor=owner)
            if not stop.get('stopped'):
                outcome['released'] = False
                outcome['hold_retained'] = f"stop not positively confirmed ({stop.get('reason_code')})"
                return
            self.release_profile(profile, owner=owner, generation=generation)
            outcome['released'] = True
        except QuarantinedError:
            outcome['released'] = False
            outcome['hold_retained'] = 'quarantine retained; needs a reasoned override'
        except Exception as exc:
            outcome['released'] = False
            outcome['release_error'] = f'{type(exc).__name__}: {exc}'
FUTURE_TOLERANCE_SECONDS = 1.0

def _generation_ok(value: Any, expected: int) -> bool:
    """Strict positive-integer generation equality: bool and float never pass."""
    return isinstance(value, int) and (not isinstance(value, bool)) and (value > 0) and (value == expected)

def _observed_at_ok(value: Any, *, now: float, max_age: float, future_tolerance: float=FUTURE_TOLERANCE_SECONDS) -> bool:
    """Finite, non-bool, not from the future, within the shared sample window."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or (not math.isfinite(value)):
        return False
    return value <= now + future_tolerance and now - float(value) <= max_age

def _node_outcomes(reply: Any, nodes: list[str]) -> dict[str, str]:
    """Per-node stop outcome reason taken from a (possibly malformed) reply.

    Never invents a positive outcome: a missing or unparsable node observation is
    reported as ``observation_missing``.
    """
    per_node = reply.get('nodes') if isinstance(reply, dict) else None
    outcomes: dict[str, str] = {}
    for node in nodes:
        item = per_node.get(node) if isinstance(per_node, dict) else None
        if not isinstance(item, dict):
            outcomes[node] = 'observation_missing'
            continue
        reason = item.get('reason')
        if not isinstance(reason, str) or not reason.strip():
            reason = 'stopped' if item.get('stopped') is True else 'not_stopped'
        outcomes[node] = reason.strip()[:64]
    return outcomes

def _validated_preflight(reply: Any, *, profile: str, nodes: list[str], generation: int, owner: str, now: float, max_age: float) -> dict[str, Any]:
    """A preflight is only trustworthy when it names this exact attempt and is fresh.

    Requires: exact profile (no ``None``), exact owner, strict positive
    non-bool generation equality, a non-empty exact node set, per-node ``clear``,
    and finite, non-future, non-stale top-level *and* per-node ``observed_at``.
    Malformed replies refuse instead of raising.
    """
    try:
        if not isinstance(reply, dict):
            return {'clear': False, 'reason_code': 'malformed_preflight', 'problems': ['not_a_mapping'], 'nodes': {n: {'clear': False} for n in nodes}}
        problems: list[str] = []
        if reply.get('profile') != profile:
            problems.append('profile_mismatch')
        if reply.get('owner') != owner:
            problems.append('owner_mismatch')
        if not _generation_ok(reply.get('generation'), generation):
            problems.append('generation_mismatch')
        if not nodes:
            problems.append('empty_node_set')
        per_node = reply.get('nodes')
        if not isinstance(per_node, dict) or set(map(str, per_node)) != set(nodes):
            problems.append('incomplete_node_set')
            per_node = per_node if isinstance(per_node, dict) else {}
        if reply.get('clear') is not True:
            problems.append('not_clear')
        if not _observed_at_ok(reply.get('observed_at'), now=now, max_age=max_age):
            problems.append('stale_or_missing_observation')
        for node in nodes:
            item = per_node.get(node)
            if not isinstance(item, dict) or item.get('clear') is not True:
                problems.append(f'node_not_clear:{node}')
                continue
            if not _observed_at_ok(item.get('observed_at'), now=now, max_age=max_age):
                problems.append(f'node_stale_or_missing_observation:{node}')
        return {'clear': not problems, 'reason_code': 'clear' if not problems else 'preflight_refused', 'problems': problems, 'generation': reply.get('generation'), 'nodes': per_node, 'observed_at': reply.get('observed_at'), 'observed_now': now, 'max_age': max_age}
    except Exception as exc:
        return {'clear': False, 'reason_code': 'malformed_preflight', 'problems': [type(exc).__name__], 'nodes': {}}

def _validated_ready(reply: Any, *, profile: str, nodes: list[str], generation: int, owner: str, now: float, max_age: float) -> dict[str, Any]:
    """Readiness must name the exact profile/owner/generation, be fresh, and be healthy.

    Requires: exact profile (no ``None``), exact owner, strict positive non-bool
    generation equality, a non-empty exact node set, a non-empty ``model_id``,
    per-node ``healthy``, and finite, non-future, non-stale top-level *and*
    per-node ``observed_at``. The adapter remains responsible for matching its
    exact pinned model.
    """
    try:
        if not isinstance(reply, dict):
            return {'healthy': False, 'reason_code': 'malformed_ready_probe', 'problems': ['not_a_mapping'], 'nodes': {n: {'healthy': False} for n in nodes}}
        problems: list[str] = []
        if reply.get('profile') != profile:
            problems.append('profile_mismatch')
        if reply.get('owner') != owner:
            problems.append('owner_mismatch')
        if not _generation_ok(reply.get('generation'), generation):
            problems.append('generation_mismatch')
        if not nodes:
            problems.append('empty_node_set')
        per_node = reply.get('nodes')
        if not isinstance(per_node, dict) or set(map(str, per_node)) != set(nodes):
            problems.append('incomplete_node_set')
            per_node = per_node if isinstance(per_node, dict) else {}
        if reply.get('healthy') is not True:
            problems.append('not_healthy')
        model_id = reply.get('model_id')
        if not isinstance(model_id, str) or not model_id.strip():
            problems.append('model_id_missing')
        if not _observed_at_ok(reply.get('observed_at'), now=now, max_age=max_age, future_tolerance=0.0):
            problems.append('stale_or_missing_observation')
        for node in nodes:
            item = per_node.get(node)
            if not isinstance(item, dict):
                problems.append(f'node_malformed:{node}')
                continue
            if item.get('healthy') is not True:
                problems.append(f'node_not_healthy:{node}')
            if not _observed_at_ok(item.get('observed_at'), now=now, max_age=max_age, future_tolerance=0.0):
                problems.append(f'node_stale_or_missing_observation:{node}')
        return {'healthy': not problems, 'reason_code': 'healthy' if not problems else 'ready_refused', 'problems': problems, 'model_id': model_id if isinstance(model_id, str) else None, 'nodes': per_node, 'observed_now': now, 'max_age': max_age}
    except Exception as exc:
        return {'healthy': False, 'reason_code': 'malformed_ready_probe', 'problems': [type(exc).__name__], 'nodes': {}}
_PENDING_TOLERATED_PROBLEMS = frozenset({'not_healthy', 'model_id_missing'})

def _readiness_is_pending(readiness: dict[str, Any], nodes: list[str]) -> bool:
    """True when an unhealthy probe is a still-loading signature, not a violation.

    A pending observation must be structurally valid: exact identity, exact node
    set, fresh top-level and per-node timestamps (any mismatch, staleness,
    malformed shape, or ``adapter_unavailable`` disqualifies it). Only then are
    ``not_healthy`` / per-node unhealthiness / a missing ``model_id`` tolerated
    as "not serving yet", which keeps the reservation STARTING instead of
    failing it. Unknown, stale, or foreign observations never count as pending.
    """
    if readiness.get('reason_code') not in {'healthy', 'ready_refused'}:
        return False
    problems = readiness.get('problems')
    if not isinstance(problems, list):
        return False
    tolerated = set(_PENDING_TOLERATED_PROBLEMS) | {f'node_not_healthy:{node}' for node in nodes}
    return all((problem in tolerated for problem in problems))

def _pinned_model_problems(readiness: dict[str, Any], nodes: list[str], expected_model_id: str) -> list[str]:
    """Pinned-model violations in a validated readiness probe, as problem strings.

    The top-level ``model_id`` must equal the pinned model strictly. Per node, a
    healthy node proves the pinned model either by carrying the pinned
    ``model_id`` or — for worker-role nodes, which report no ``model_id`` by
    contract — by an adapter-verified worker process proof bound to the pinned
    container/image. Unhealthy nodes are skipped: their health problems are
    already recorded and they never publish READY.
    """
    problems: list[str] = []
    if readiness.get('model_id') != expected_model_id:
        problems.append('model_pin_mismatch')
    per_node = readiness.get('nodes')
    per_node = per_node if isinstance(per_node, dict) else {}
    for node in nodes:
        item = per_node.get(node)
        if not isinstance(item, dict) or item.get('healthy') is not True:
            continue
        if item.get('model_id') == expected_model_id:
            continue
        if item.get('role') == 'worker' and item.get('process_verified') is True and isinstance(item.get('worker_proof'), dict):
            continue
        problems.append(f'model_pin_mismatch:{node}')
    return problems

def _validated_confirmation(reply: Any, *, nodes: list[str], generation: int, profile: str, now: float, max_age: float) -> dict[str, Any] | None:
    """Convert a confirm_stop reply into store evidence, or ``None`` if unusable.

    Requires: ``stopped is True``, the exact requested profile (no ``None``),
    strict positive non-bool generation equality, a non-empty exact node set,
    ``stopped is True`` per node, and finite, non-future, non-stale timestamps at
    both the top level and per node. Unknown nodes, still-running processes,
    malformed replies, and stale observations all yield ``None``.
    """
    try:
        if not isinstance(reply, dict):
            return None
        if reply.get('stopped') is not True:
            return None
        if reply.get('profile') != profile:
            return None
        if not _generation_ok(reply.get('generation'), generation):
            return None
        if not nodes:
            return None
        per_node = reply.get('nodes')
        if not isinstance(per_node, dict) or set(map(str, per_node)) != set(nodes):
            return None
        if not _observed_at_ok(reply.get('observed_at'), now=now, max_age=max_age):
            return None
        evidence_nodes: dict[str, dict[str, Any]] = {}
        for node in nodes:
            item = per_node.get(node)
            if not isinstance(item, dict) or item.get('stopped') is not True:
                return None
            try:
                observed = finite_number(item.get('observed_at'), name=f'confirm_stop.nodes.{node}.observed_at')
            except ValidationError:
                return None
            if not _observed_at_ok(observed, now=now, max_age=max_age):
                return None
            evidence_nodes[node] = {'stopped': True, 'observed_at': observed, 'reason': item.get('reason')}
        return {'stopped': True, 'generation': generation, 'profile': profile, 'nodes': evidence_nodes, 'observed_at': max((item['observed_at'] for item in evidence_nodes.values()))}
    except Exception:
        return None

def _required_samples(store: Store) -> int:
    return max(1, int(store.policy_value('memory_samples_required', 3)))

def _sample_max_age(store: Store) -> float:
    return float(store.policy_sample_max_age())
