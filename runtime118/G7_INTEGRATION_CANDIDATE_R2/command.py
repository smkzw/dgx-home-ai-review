# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Authenticated commands against one existing Manager; durable intent before dispatch."""
import os
import re
import threading
import time
from G7_INTEGRATION_CANDIDATE_R1.coordinator import CachePreparation
from G7_INTEGRATION_CANDIDATE_R1.compiler import PREP
from hx_service.facade import ProfileBinding
from llm_gateway.errors import GatewayError
from .durable import Ledger, need, Refusal, exclusive
from .publisher import publish
ACTIONS = {'start', 'poll', 'stop', 'verification_ticket', 'publish', 'release', 'status'}

class MaintenanceCommands:

    def __init__(self, runtime, lease, config, *, reload_config=None, clock=time.time):
        self.runtime = runtime
        self.lease = lease
        self.config = config
        self.reload_config = reload_config
        self.clock = clock
        self.lock = threading.Lock()

    def _guard(self):
        c = self.config
        need(c['enabled'] is True, 'maintenance_disabled')
        return CachePreparation(self.runtime, self.lease, c['binding'])

    def _held(self, generation, stopped=False):
        p = self._guard()
        p.generation = generation
        p._current_generation()
        v = self.runtime.manager.store.profile_view(PREP)
        if stopped:
            need(v['state'] == 'STOPPED', 'positively_stopped_held_required')
        return p

    def _samples(self):
        facade = self.runtime.facade
        while hasattr(facade, '_facade'):
            facade = facade._facade
        samples, reason = facade._collect_memory_samples(ProfileBinding(nodes=('spark-a', 'spark-b'), expected_model_id='DeepSeek-V4.1-Flash-TF-CachePrep', enabled=True, active_work_path=''))
        need(samples is not None and reason == 'ok', 'actual_fresh_memory_required')
        return samples

    def command(self, body, caller):
        need(isinstance(body, dict) and set(body) == {'action', 'run_id', 'key'}, 'fixed_command_fields')
        need(isinstance(body['action'], str) and body['action'] in ACTIONS and isinstance(body['key'], str) and re.fullmatch('[0-9a-f]{32}', body['key']), 'fixed_action_idempotency_key')
        with self.lock:
            if self.reload_config is not None:
                new = self.reload_config()
                need(all((new[k] == self.config[k] for k in ('caller_owner', 'run_id', 'run_root', 'publication_root', 'input_identity'))), 'fixed_run_identity_cannot_reload')
                self.config = new
            c = self.config
            need(caller == c['caller_owner'] and body['run_id'] == c['run_id'], 'exact_derived_caller_and_run')
            p = self._guard()
            ledger = Ledger(c['run_root'])
            try:
                ledger.initialize(c['run_id'], {'run_id': c['run_id'], 'input_identity': c['input_identity'], 'owner': 'dgx-hx-service'})
                cached = ledger.begin(body['key'], caller, body)
                if cached is not None:
                    return cached
                v = ledger.view(c['run_id'])
                action = body['action']
                try:
                    if action == 'start':
                        need(v['phase'] == 'PREPARED' and (not v['attempted']), 'start_once_no_blind_replay')
                        ledger.mark(c['run_id'], 'START_INTENT', attempted=True)
                        result = p.start(samples=self._samples(), now=self.clock())
                        generation = p.generation
                        ledger.mark(c['run_id'], 'STARTED_OR_HELD', generation=generation)
                    elif action == 'status':
                        result = {'run': v, 'profile': self.runtime.manager.store.profile_view(PREP), 'cache_accepted': v['phase'] in {'PUBLISHED', 'PUBLISHED_RELEASED'}, 'serving_accepted': False}
                    else:
                        g = v['generation']
                        need(type(g) is int and g > 0, 'actual_recorded_generation_required')
                        p = self._held(g, stopped=action in {'verification_ticket', 'publish', 'release'})
                        if action == 'poll':
                            need(v['phase'] == 'STARTED_OR_HELD', 'poll_only_started_held_run')
                            result = {'lifecycle': self.runtime.manager.complete_readiness(PREP, owner='dgx-hx-service', from_states={'STARTING', 'RECONCILING'}, expected_model_id='DeepSeek-V4.1-Flash-TF-CachePrep', enforce_pending_deadline=True), 'cache_accepted': False}
                        elif action == 'stop':
                            need(v['phase'] == 'STARTED_OR_HELD', 'stop_once_no_blind_replay')
                            ledger.mark(c['run_id'], 'STOP_INTENT')
                            result = p.stop()
                            if result.get('stopped') is True and result.get('confirmed') is True:
                                ledger.mark(c['run_id'], 'STOPPED_HELD')
                        elif action == 'verification_ticket':
                            need(v['phase'] == 'STOPPED_HELD', 'stop_before_CPU_verification')
                            st = os.fstat(self.lease._fd)
                            result = {'schema': 'g7-existing-manager-verification-ticket-r2/v1', 'run_id': c['run_id'], 'profile': PREP, 'owner': 'dgx-hx-service', 'generation': g, 'manager_pid': os.getpid(), 'lease_dev_inode': [st.st_dev, st.st_ino], 'input_identity': c['input_identity'], 'issued_at': self.clock(), 'GPU_lifecycle_permission': False}
                        elif action == 'publish':
                            need(v['phase'] == 'STOPPED_HELD', 'pair_publish_once_after_stop')
                            ledger.mark(c['run_id'], 'PUBLISH_INTENT')
                            result = publish(c, g, held_guard=lambda: self._held(g, stopped=True))
                            ledger.mark(c['run_id'], 'PUBLISHED')
                        elif action == 'release':
                            need(v['phase'] in {'STOPPED_HELD', 'PUBLISHED'}, 'release_only_safe_stopped_phase')
                            result = p.release()
                            if result.get('released') is True:
                                ledger.mark(c['run_id'], 'PUBLISHED_RELEASED' if v['phase'] == 'PUBLISHED' else 'RELEASED')
                    ledger.finish(body['key'], result)
                    return result
                except BaseException as exc:
                    exclusive(ledger.root / (body['key'] + '.failure.json'), {'action': action, 'run_id': c['run_id'], 'error_type': type(exc).__name__, 'actual_run': ledger.view(c['run_id']), 'recovery_requires_fresh_parent_inspection': True})
                    raise
            finally:
                ledger.close()
