# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Durable fixed trial commands against the already composed sole Manager."""
import threading
from G7_INTEGRATION_CANDIDATE_R2.durable import Ledger, need, exclusive
from G7_QUALIFICATION_IMPLEMENTATION_R1 import permit as qp
from G7_QUALIFICATION_IMPLEMENTATION_R1.manager import QualificationManager
from G7_QUALIFICATION_IMPLEMENTATION_R1.store import Store
from G7_QUALIFICATION_IMPLEMENTATION_R1.adapter import QualificationNodeAdapter
from hx_service.service import ServiceRuntime
ACTIONS = {'start_qualification', 'status', 'stop'}

class QualificationCommands:

    def __init__(self, runtime, lease, config, *, reload_config=None):
        self.runtime = runtime
        self.lease = lease
        self.config = config
        self.reload_config = reload_config
        self.lock = threading.Lock()

    def _guard(self, *, stop=False):
        c = self.config
        need(c['enabled'] is True and c['parent_accepted'] is True, 'qualification_not_parent_accepted')
        m = self.runtime.manager
        need(isinstance(self.runtime, ServiceRuntime) and type(m) is QualificationManager and (type(m.store) is Store), 'actual_same_qualification_Manager_Store')
        need(isinstance(self.runtime.adapter, QualificationNodeAdapter) and m.adapter is self.runtime.adapter, 'actual_same_qualification_adapter')
        if not hasattr(m, '_q_context'):
            doc = qp.load(qp.HX_PATH)
            need(doc.sha256 == c['permit_sha256'] and doc.value['run_id'] == c['run_id'], 'fixed_actual_root_permit')
            m.bind_qualification(self.lease, expected_permit_sha256=c['permit_sha256'])
        need(m._q_context[0] is self.lease and m._q_context[1] == c['permit_sha256'], 'same_bound_original_lease_and_permit')
        if stop:
            doc = m._q_document
            doc.check(now=m._now())
            m._held_physical_lease(doc.value)
        else:
            doc = m._qualification_guard(starting=False, run_id=c['run_id'])
        need(doc.value['run_id'] == c['run_id'], 'fixed_root_run')
        return (m, doc)

    def command(self, body, caller):
        need(type(body) is dict and set(body) == {'action', 'run_id', 'key'}, 'fixed_qualification_fields')
        need(type(body['action']) is str and body['action'] in ACTIONS, 'fixed_qualification_action')
        qp.c.request(body, self.config['run_id'])
        with self.lock:
            if self.reload_config:
                new = self.reload_config()
                need(all((new[k] == self.config[k] for k in ('enabled', 'caller_owner', 'run_id', 'run_root'))), 'fixed_startup_route_and_run')
                if hasattr(self.runtime.manager, '_q_context'):
                    need(new['permit_sha256'] == self.config['permit_sha256'], 'bound_permit_cannot_reload')
                self.config = new
            c = self.config
            need(caller == c['caller_owner'], 'exact_derived_qualification_owner')
            action = body['action']
            m, doc = self._guard(stop=action == 'stop')
            v = doc.value
            ledger = Ledger(c['run_root'])
            try:
                ledger.initialize(c['run_id'], {'run_id': v['run_id'], 'profile': v['profile'], 'owner': v['owner'], 'generation': v['generation'], 'permit_sha256': doc.sha256})
                cached = ledger.begin(body['key'], caller, body)
                if cached is not None:
                    return cached
                phase = ledger.view(v['run_id'])
                try:
                    if action == 'start_qualification':
                        need(phase['phase'] == 'PREPARED' and (not phase['attempted']), 'one_trial_start_no_replay')
                        ledger.mark(v['run_id'], 'START_INTENT', attempted=True, generation=v['generation'])
                        self.runtime.telemetry.arm(doc, c['run_root'])
                        result = m.start_qualification(run_id=v['run_id'])
                        if result.get('started') is True:
                            self.runtime.telemetry.bind_start_ack(result)
                            ledger.mark(v['run_id'], 'TRIAL_HELD')
                        elif result.get('cleanup', {}).get('stopped') is True and result['cleanup'].get('confirmed') is True:
                            ledger.mark(v['run_id'], 'STOPPED_HELD')
                        else:
                            ledger.mark(v['run_id'], 'FAILED_RETAINED')
                    elif action == 'stop':
                        need(phase['phase'] == 'TRIAL_HELD', 'one_explicit_stop_started_trial')
                        ledger.mark(v['run_id'], 'STOP_INTENT')
                        result = m.stop_qualification(run_id=v['run_id'])
                        if result.get('stopped') is True and result.get('confirmed') is True:
                            ledger.mark(v['run_id'], 'STOPPED_HELD')
                    elif phase['phase'] != 'TRIAL_HELD':
                        result = {'core': m.store.profile_view(v['profile']), 'run': phase, 'inspection_only': True}
                    else:
                        ledger.mark(v['run_id'], 'STATUS_INTENT')
                        result = m.qualification_status(run_id=v['run_id'])
                        stopped = result.get('stop')
                        if stopped is not None:
                            if stopped.get('stopped') is True and stopped.get('confirmed') is True:
                                ledger.mark(v['run_id'], 'STOPPED_HELD')
                            else:
                                ledger.mark(v['run_id'], 'STOP_INTENT')
                        elif m.store.profile_view(v['profile'])['state'] == 'STOPPED':
                            ledger.mark(v['run_id'], 'STOPPED_HELD')
                        else:
                            ledger.mark(v['run_id'], 'TRIAL_HELD')
                    if self.runtime.telemetry.started:
                        if action == 'stop' or (action == 'start_qualification' and result.get('started') is not True) or m.store.profile_view(v['profile'])['state'] in ('STOPPED', 'FAILED'):
                            self.runtime.telemetry.request_stop('original_command_terminal_' + action)
                        result = dict(result, telemetry=self.runtime.telemetry.summary())
                    need(result.get('ready') is not True and result.get('hardware_validated') is not True and (result.get('serving_enabled') is not True), 'trial_cannot_publish_capability')
                    result = dict(result, qualification='qualification_pending', ready=False, hardware_validated=False, serving_enabled=False, calibration_published=False)
                    ledger.finish(body['key'], result)
                    return result
                except BaseException as exc:
                    self.runtime.telemetry.request_stop('original_command_failure_' + action)
                    exclusive(ledger.root / (body['key'] + '.failure.json'), {'action': action, 'run_id': v['run_id'], 'error_type': type(exc).__name__, 'actual_run': ledger.view(v['run_id']), 'retained_no_replay': True})
                    raise
            finally:
                ledger.close()

def attach_to_runtime(runtime, lease, config, *, reload_config=None):
    """Called once by the sole factory; no Manager construction or listener."""
    from .runtime import TelemetryRuntime
    from .sampler import Sampler, identity_guard
    need(type(runtime) is TelemetryRuntime, 'same_actual_TelemetryRuntime')
    identity_guard(runtime, lease)
    need(not hasattr(runtime, 'telemetry'), 'one_sampler_per_sole_runtime')
    runtime.telemetry = Sampler(runtime, lease)
    return QualificationCommands(runtime, lease, config, reload_config=reload_config)
