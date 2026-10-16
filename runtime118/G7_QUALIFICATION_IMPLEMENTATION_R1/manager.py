# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Qualification on the original sole Manager; all ordinary methods inherited."""
import os
import time
import threading
from control_plane.manager import Manager
from control_plane.errors import ProfileStateError, ValidationError
from hx_service.service import MaintenanceLease, MAINTENANCE_LOCK_PATH
from . import permit as qp
from .store import Store

class QualificationManager(Manager):

    def bind_qualification(self, lease, *, expected_permit_sha256, permit_reader=None, wait=time.sleep):
        qp.c.need(not hasattr(self, '_q_context'), 'qualification_context_already_bound')
        qp.sha(expected_permit_sha256)
        qp.c.need(type(self.store) is Store, 'qualification_store_required')
        reader = permit_reader or (lambda: qp.load(qp.HX_PATH))
        self._q_context = (lease, expected_permit_sha256, reader, wait)
        try:
            self._q_document = self._qualification_guard(starting=False)
        except BaseException:
            del self._q_context
            raise
        self._q_lock = threading.RLock()
        self._q_monitor = None
        self._q_monitor_done = threading.Event()

    def _qualification_guard(self, *, starting, run_id=None):
        qp.c.need(hasattr(self, '_q_context'), 'sole_factory_context_required')
        lease, expected, reader, _wait = self._q_context
        qp.c.need(isinstance(lease, MaintenanceLease) and lease.held and (lease.path == MAINTENANCE_LOCK_PATH), 'same_original_held_lease_required')
        opened = os.fstat(lease._fd)
        named = lease.path.lstat()
        doc = reader()
        qp.c.need(type(doc) is qp.Document and doc.sha256 == expected, 'immutable_root_permit_required')
        v = doc.check(now=self._now(), starting=starting).value
        qp.c.need(v['manager_pid'] == os.getpid(), 'same_actual_manager_PID')
        qp.c.need((opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino) == tuple(v['lease_dev_inode']), 'same_physical_lease_identity')
        if run_id is not None:
            qp.c.need(run_id == v['run_id'], 'fixed_root_run')
        qp.c.need(self._adapter_available() and (not self._fixture_only()), 'real_nonfixture_adapter_required')
        return doc

    def reserve_admin(self, profile, *, owner, operation='maintenance', reason=None):
        if operation == 'qualification':
            raise ValidationError('private_qualification_method_required')
        return super().reserve_admin(profile, owner=owner, operation=operation, reason=reason)

    def complete_readiness(self, profile, **kwargs):
        if any((n.get('hold_profile') == profile and n.get('hold_operation') == 'qualification' for n in self.store.nodes_view())):
            raise ProfileStateError('qualification_pending_no_READY', code='qualification_pending_no_READY')
        return super().complete_readiness(profile, **kwargs)

    def _trial_held(self, v, *, dispatch=False):
        qp.c.need(self.store.still_owned(v['profile'], owner=v['owner'], generation=v['generation']), 'current_AB_owner_generation_holds_required')
        if dispatch:
            qp.c.need(self.store.profile_view(v['profile'])['state'] == 'STARTING', 'qualification_dispatch_state_changed')
        rows = {n['node']: n for n in self.store.nodes_view() if n['node'] in qp.c.NODES}
        qp.c.need(set(rows) == set(qp.c.NODES) and all((n.get('hold_operation') == 'qualification' for n in rows.values())), 'qualification_operation_holds_required')

    def _trial_samples(self, v):
        samples = {n: [] for n in qp.c.NODES}
        for round_id in range(3):
            for node in qp.c.NODES:
                reply = self.adapter.probe(node)
                qp.c.need(type(reply) is dict and reply.get('node') == node and (reply.get('reachable') is True) and (reply.get('healthy') is True), 'actual_node_probe_required')
                memory = reply.get('memory', {})
                qp.c.need(memory.get('source') == 'proc_meminfo' and memory.get('mem_total_bytes') == v['host_facts'][node]['total_bytes'], 'actual_MemTotal_binding')
                free = memory.get('mem_available_bytes')
                qp.c.need(type(free) is int and free >= 0, 'actual_available_memory')
                samples[node].append({'timestamp': reply.get('observed_at'), 'available_gib': free / qp.c.GIB, 'reachable': True})
            if round_id < 2:
                self._q_context[3](0.5)
        qp.c.memory_gate(samples, v['host_facts'], self._now())
        return samples

    def start_qualification(self, *, run_id):
        qp.c.need(hasattr(self, '_q_lock'), 'sole_factory_context_required')
        with self._q_lock:
            return self._start_qualification(run_id=run_id)

    def _start_qualification(self, *, run_id):
        doc = self._qualification_guard(starting=True, run_id=run_id)
        v = doc.value
        view = self.store.profile_view(v['profile'])
        qp.c.need(view['hardware_validated'] is False and view['min_start_available_gib'] is None, 'uncalibrated_trial_only')
        source = v['pins']['python' if v['profile'] == 'deepseek-cacheprep-ab' else 'engine']
        qp.c.need(view['source'] == source and view['nodes'] == list(qp.c.NODES), 'fixed_core_source_AB_profile')
        result = self.store.reserve_profile(v['profile'], owner=v['owner'], operation='qualification', qualification={'value': v, 'sha256': doc.sha256}, reason='one-shot uncalibrated qualification trial')
        if not result.get('reserved'):
            return {'qualification': 'qualification_pending', 'lifecycle': result, 'started': False, 'ready': False}
        try:
            self._trial_held(v, dispatch=True)
            samples = self._trial_samples(v)
            self._qualification_guard(starting=True, run_id=run_id)
            preflight = self._run_preflight(v['profile'], nodes=list(qp.c.NODES), generation=v['generation'], owner=v['owner'])
            qp.c.need(preflight.get('clear') is True, 'qualification_preflight_refused')
            self._trial_held(v, dispatch=True)
            self._qualification_guard(starting=True, run_id=run_id)
            reply = self.adapter.start(v['profile'], nodes=list(qp.c.NODES), generation=v['generation'], env={k: v[k] for k in ('profile', 'owner', 'generation')})
            self._trial_held(v, dispatch=True)
            qp.c.need(type(reply) is dict and reply.get('started') is True and (reply.get('uncertain') is not True), 'qualification_partial_or_unknown_start')
            qp.c.need(all((reply.get(k) == v[k] and type(reply.get(k)) is type(v[k]) for k in ('profile', 'owner', 'generation'))), 'qualification_start_identity')
            per_node = reply.get('nodes')
            qp.c.need(type(per_node) is dict and set(per_node) == set(qp.c.NODES) and all((type(n) is dict and n.get('started') is True for n in per_node.values())), 'qualification_complete_start_ack')
            self.store.audit('qualification_start_ack', actor=v['owner'], profile=v['profile'], generation=v['generation'], detail='start acknowledgement only; READY prohibited')
            self._start_monitor()
            return {'qualification': 'qualification_pending', 'started': True, 'ready': False, 'hardware_validated': False, 'serving_enabled': False, 'generation': v['generation'], 'samples': samples, 'adapter_reply': reply}
        except BaseException as exc:
            self._fail_state(v['profile'], v['generation'], 'qualification failure: ' + type(exc).__name__, expected_owner=v['owner'])
            cleanup = {'stopped': False, 'hold_retained': True}
            if self.store.still_owned(v['profile'], owner=v['owner'], generation=v['generation']):
                try:
                    cleanup = self.stop_profile(v['profile'], owner=v['owner'], expected_generation=v['generation'])
                except Exception as stop_error:
                    cleanup['error_type'] = type(stop_error).__name__
            self.store.audit('qualification_failed', actor=v['owner'], profile=v['profile'], generation=v['generation'], reason=type(exc).__name__, detail='no retry; stop attempted only for current exact identity; release not attempted')
            return {'qualification': 'qualification_pending', 'started': False, 'ready': False, 'hardware_validated': False, 'generation': v['generation'], 'failure_type': type(exc).__name__, 'cleanup': cleanup, 'holds_retained': self.store.still_owned(v['profile'], owner=v['owner'], generation=v['generation'])}

    def stop_qualification(self, *, run_id):
        qp.c.need(hasattr(self, '_q_lock'), 'sole_factory_context_required')
        with self._q_lock:
            v = self._q_document.check(now=self._now()).value
            qp.c.need(run_id == v['run_id'], 'fixed_root_run')
            self._held_physical_lease(v)
            self._trial_held(v)
            return self.stop_profile(v['profile'], owner=v['owner'], expected_generation=v['generation'])

    def _held_physical_lease(self, v):
        lease = self._q_context[0]
        qp.c.need(lease.held, 'sole_maintenance_lease_lost')
        opened = os.fstat(lease._fd)
        named = lease.path.lstat()
        qp.c.need((opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino) == tuple(v['lease_dev_inode']), 'same_physical_lease_identity')

    def qualification_status(self, *, run_id):
        qp.c.need(hasattr(self, '_q_lock'), 'sole_factory_context_required')
        with self._q_lock:
            return self._qualification_status(run_id=run_id)

    def _qualification_status(self, *, run_id):
        doc = self._qualification_guard(starting=False, run_id=run_id)
        v = doc.value
        view = self.store.profile_view(v['profile'])
        if view['generation'] != v['generation'] and view['owner'] is None:
            return {'qualification': 'qualification_pending', 'ready': False, 'core': view, 'trial_not_started': True}
        self._trial_held(v)
        if view['state'] in ('STOPPED', 'STOPPING', 'DRAINING', 'FAILED'):
            return {'qualification': 'qualification_pending', 'ready': False, 'hardware_validated': False, 'serving_enabled': False, 'core': view, 'holds_retained': True}
        try:
            qp.c.need(self._now() < v['expires_at'], 'qualification_absolute_deadline')
            observations = self.adapter.observe_qualification(document=doc)
            qp.c.need(type(observations) is dict and set(observations) == set(qp.c.NODES), 'exact_AB_guard_observations')
            for item in observations.values():
                qp.c.need(type(item) is dict and item.get('verified') is True, 'fresh_root_guard_observation_required')
                stamp = qp.c.number(item.get('observed_at'))
                now = qp.c.number(self._now())
                qp.c.need(0 <= now - stamp <= 10.0, 'qualification_guard_observation_stale')
                state = item.get('guard_state')
                reason = item.get('reason_code')
                qp.c.need(state == 'ACTIVE' and reason in ('active', 'active_warning') or (state == 'ARMING_HOLD_RETAINED' and reason in ('arming_startup', 'arming_startup_grace', 'arming_claimed')), 'qualification_guard_terminal_or_unknown')
            self._trial_held(v)
            return {'qualification': 'qualification_pending', 'ready': False, 'hardware_validated': False, 'serving_enabled': False, 'core': view, 'trial_guards': observations}
        except Exception as exc:
            stop = self.stop_qualification(run_id=run_id)
            return {'qualification': 'qualification_pending', 'ready': False, 'trial_watchdog_failure': type(exc).__name__, 'stop': stop, 'holds_retained': True}

    def _start_monitor(self):
        qp.c.need(self._q_monitor is None, 'qualification_monitor_already_started')
        self._q_monitor = threading.Thread(target=self._monitor_trial, name='g7-owned-qualification-watchdog', daemon=True)
        self._q_monitor.start()

    def _monitor_trial(self):
        try:
            while not self._q_monitor_done.wait(2.0):
                v = self._q_document.value
                with self._q_lock:
                    self._held_physical_lease(v)
                    if not self.store.still_owned(v['profile'], owner=v['owner'], generation=v['generation']):
                        break
                    if self.store.profile_view(v['profile'])['state'] in ('STOPPED', 'FAILED'):
                        break
                    try:
                        result = self._qualification_status(run_id=v['run_id'])
                    except Exception as exc:
                        self.store.audit('qualification_watchdog_failure', actor=v['owner'], profile=v['profile'], generation=v['generation'], reason=type(exc).__name__)
                        self.stop_qualification(run_id=v['run_id'])
                        break
                    if 'stop' in result:
                        break
        finally:
            self._q_monitor_done.set()
            self.store.close_thread_connection()

    def shutdown_qualification(self):
        if not hasattr(self, '_q_lock'):
            return
        failed_stop = False
        with self._q_lock:
            v = self._q_document.value
            self._held_physical_lease(v)
            admission = self.store.qualification_run(v['run_id'])
            qualified = admission is not None and admission['permit_sha256'] == self._q_document.sha256 and all((admission[k] == v[k] for k in ('profile', 'owner', 'generation')))
            if qualified and self.store.still_owned(v['profile'], owner=v['owner'], generation=v['generation']) and (self.store.profile_view(v['profile'])['state'] != 'STOPPED'):
                result = self.stop_qualification(run_id=v['run_id'])
                failed_stop = result.get('stopped') is not True
            self._q_monitor_done.set()
        if self._q_monitor is not None and self._q_monitor is not threading.current_thread():
            self._q_monitor.join(timeout=1.0)
        if self._q_monitor is not None and self._q_monitor.is_alive():
            raise TimeoutError('qualification_watchdog_still_owned_keep_lease')
        if failed_stop:
            raise RuntimeError('qualification_stop_unconfirmed_keep_stores_and_sole_lease')
