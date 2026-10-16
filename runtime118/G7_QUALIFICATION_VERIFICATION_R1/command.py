# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Evidence commands against the same R3 runtime/R1 Manager, never a new owner."""
import os
import re
import threading
from pathlib import Path
from G7_INTEGRATION_CANDIDATE_R2.durable import Ledger, need, exclusive, digest, private_dir
from G7_INTEGRATION_CANDIDATE_R2.publisher import load_receipt
from G7_QUALIFICATION_IMPLEMENTATION_R1 import permit as qp
from G7_QUALIFICATION_IMPLEMENTATION_R1.manager import QualificationManager
from G7_QUALIFICATION_IMPLEMENTATION_R1.store import Store
from G7_QUALIFICATION_IMPLEMENTATION_R1.adapter import QualificationNodeAdapter
from G7_INTEGRATION_CANDIDATE_R1.compiler import PREP, PREP_MODEL, NODES
from hx_service.service import ServiceRuntime
from . import publisher
from .proof import explicit_stop, read_private_json
ACTIONS = {'observe_completion', 'verification_ticket', 'publish'}

class VerificationCommands:

    def __init__(self, runtime, lease, config, *, reload_config=None):
        self.runtime = runtime
        self.lease = lease
        self.config = config
        self.reload_config = reload_config
        self.lock = threading.Lock()

    def _guard(self, *, stopped=False):
        c = self.config
        m = self.runtime.manager
        need(c['enabled'] is True and c['parent_accepted'] is True, 'verification_not_parent_accepted')
        need(isinstance(self.runtime, ServiceRuntime) and type(m) is QualificationManager and (type(m.store) is Store), 'same_qualification_Manager_Store')
        need(isinstance(m.adapter, QualificationNodeAdapter) and m.adapter is self.runtime.adapter, 'same_qualification_adapter')
        need(hasattr(m, '_q_context') and m._q_context[0] is self.lease and (m._q_context[1] == c['permit_sha256']), 'bound_original_lease_and_permit_required')
        doc = m._q_document
        v = doc.check(now=m._now()).value
        need(v['profile'] == PREP and v['run_id'] == c['run_id'] and (v['input_identity'] == c['input_identity']), 'fixed_prep_run_inputs')
        m._held_physical_lease(v)
        m._trial_held(v)
        admission = m.store.qualification_run(v['run_id'])
        need(admission is not None and admission['permit_sha256'] == doc.sha256 and all((admission[k] == v[k] for k in ('profile', 'owner', 'generation'))), 'durable_qualification_admission_required')
        view = m.store.profile_view(PREP)
        need(view['hardware_validated'] is False and view['min_start_available_gib'] is None and (view['quarantined_at'] is None), 'uncalibrated_nonquarantined_only')
        need(view['state'] == ('STOPPED' if stopped else 'STARTING'), 'exact_qualification_core_state')
        return (m, doc)

    def _completion(self, m, doc):
        v = doc.value
        observations = m.adapter.observe_qualification(document=doc)
        need(type(observations) is dict and set(observations) == set(NODES), 'complete_AB_live_guards')
        for item in observations.values():
            need(type(item) is dict and item.get('verified') is True and (item.get('guard_state') == 'ACTIVE') and (item.get('reason_code') in ('active', 'active_warning')), 'actual_ACTIVE_prep_guards')
            need(0 <= m._now() - qp.c.number(item.get('observed_at')) <= 10, 'fresh_prep_guards')
            qp.c.number(item.get('remote_observed_at'))
        ready = m._run_probe_ready(PREP, nodes=list(NODES), generation=v['generation'], owner=v['owner'])
        need(ready.get('healthy') is True and ready.get('model_id') == PREP_MODEL, 'actual_pinned_prep_completion_probe')
        rows = ready.get('nodes')
        need(type(rows) is dict and set(rows) == set(NODES), 'exact_prep_probe_AB')
        for n, r in rows.items():
            need(r.get('healthy') is True and type(r.get('container_id')) is str and re.fullmatch('[0-9a-f]{64}', r['container_id']), 'actual_complete_CID_pair')
            if n == 'spark-a':
                need(r.get('model_id') == PREP_MODEL and r.get('api_checked') is True, 'leader_ready_API_proof')
            else:
                need(r.get('process_verified') is True and r.get('api_checked') is False, 'worker_actual_process_proof')
        self._guard()
        result = {'schema': 'g7-live-prep-completion-qv1/v1', 'run_id': v['run_id'], 'profile': PREP, 'owner': v['owner'], 'generation': v['generation'], 'permit_sha256': doc.sha256, 'manager_pid': os.getpid(), 'lease_dev_inode': v['lease_dev_inode'], 'input_identity': v['input_identity'], 'observed_at': m._now(), 'container_ids': {n: rows[n]['container_id'] for n in NODES}, 'live_guards': observations, 'probe_ready': ready, 'ready_published': False, 'hardware_validated': False, 'threshold_calibration_required': True}
        need(len(__import__('json').dumps(result, sort_keys=True, indent=2, allow_nan=False).encode()) + 1 <= 65536, 'bounded_complete_prep_evidence')
        path = private_dir(self.config['run_root']) / 'completion.json'
        h = exclusive(path, result)
        m.store.audit('qualification_prep_completion_observed', actor=v['owner'], profile=PREP, generation=v['generation'], detail='pinned healthy probe only; no READY/calibration publication')
        return {'completion_sha256': h, 'completion': str(path), 'prep_completion_observed': True, 'ready': False}

    def _saved_completion(self, doc):
        path = Path(self.config['run_root']) / 'completion.json'
        value, h = read_private_json(path, uid=os.geteuid(), mode=384, limit=65536)
        v = doc.value
        need(value.get('schema') == 'g7-live-prep-completion-qv1/v1' and all((value.get(k) == v[k] for k in ('run_id', 'profile', 'owner', 'generation', 'input_identity', 'lease_dev_inode', 'manager_pid'))) and (value.get('permit_sha256') == doc.sha256), 'same_durable_completion_identity')
        return (value, h)

    def _ticket(self, m, doc):
        completion, h = self._saved_completion(doc)
        v = doc.value
        _raw, confirmed = m._confirm_stop_observation(PREP, generation=v['generation'])
        need(confirmed is not None, 'fresh_complete_AB_confirm_stop')
        self._guard(stopped=True)
        return {'schema': 'g7-qualification-verification-ticket-qv1/v1', **{k: v[k] for k in ('run_id', 'profile', 'owner', 'generation', 'input_identity', 'manager_pid', 'lease_dev_inode')}, 'permit_sha256': doc.sha256, 'issued_at': m._now(), 'completion_sha256': h, 'completion': completion, 'confirmed_stop': confirmed, 'explicit_stop': explicit_stop(self.config['qualification_run_root'], v, doc.sha256), 'GPU_lifecycle_permission': False, 'core_state': 'STOPPED', 'hold_operation': 'qualification', 'hardware_validated': False, 'calibration_published': False, 'threshold_calibration_required': True}

    def command(self, body, caller):
        need(type(body) is dict and set(body) == {'action', 'run_id', 'key'}, 'fixed_verification_fields')
        need(type(body['action']) is str and body['action'] in ACTIONS, 'fixed_verification_action')
        need(body['run_id'] == self.config['run_id'] and type(body['key']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}', body['key']), 'fixed_run_bounded_key')
        with self.lock:
            if self.reload_config:
                new = self.reload_config()
                need(all((new[k] == self.config[k] for k in ('enabled', 'caller_owner', 'run_id', 'run_root', 'permit_sha256', 'input_identity', 'publication_root'))), 'fixed_bound_verification_config')
                self.config = new
            need(caller == self.config['caller_owner'], 'fixed_authenticated_owner')
            m = self.runtime.manager
            need(hasattr(m, '_q_lock'), 'trial_bound_before_evidence')
            with m._q_lock:
                stopped = body['action'] != 'observe_completion'
                m, doc = self._guard(stopped=stopped)
                ledger = Ledger(self.config['run_root'])
                try:
                    ledger.initialize(doc.value['run_id'], {'permit_sha256': doc.sha256, 'generation': doc.value['generation'], 'role': 'qualification-evidence'})
                    cached = ledger.begin(body['key'], caller, body)
                    if cached is not None:
                        return cached
                    try:
                        if body['action'] == 'observe_completion':
                            result = self._completion(m, doc)
                        elif body['action'] == 'verification_ticket':
                            result = self._ticket(m, doc)
                        else:
                            completion, h = self._saved_completion(doc)
                            result = publisher.publish(self.config, doc.value['generation'], held_guard=lambda: self._guard(stopped=True), completion_sha256=h, permit_sha256=doc.sha256)
                        result = dict(result, ready=False, hardware_validated=False, serving_accepted=False, calibration_published=False, threshold_calibration_required=True)
                        ledger.finish(body['key'], result)
                        return result
                    except BaseException as exc:
                        exclusive(ledger.root / (body['key'] + '.failure.json'), {'error_type': type(exc).__name__, 'action': body['action'], 'run_id': body['run_id'], 'no_replay': True})
                        raise
                finally:
                    ledger.close()
