# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Private first trial on the same Manager, Store, Scheduler and physical lease.

No normal READY, restart or automatic calibration. Fixed cleanup releases only
the already positively stopped trial on this same runtime. All unresolved
intents persist in the existing private Ledger. Stop remains available after
permit revocation. Shutdown failure retains the original runtime and lease.
"""
import os
import math
import threading
import time
from pathlib import Path
from G7_INTEGRATION_CANDIDATE_R2.durable import Ledger, exclusive
from G7_QUALIFICATION_IMPLEMENTATION_R1.manager import QualificationManager
from G7_QUALIFICATION_IMPLEMENTATION_R1.store import Store
from G8_INTEGRATION_RUNTIME_CANDIDATE_R2.adapter import CreativeNodeAdapter
from hx_service.service import MaintenanceLease, MAINTENANCE_LOCK_PATH
from . import permit
from G8_C_FIRSTTRIAL_CANDIDATE_R1 import store_admission, adapter
from types import MethodType
cc = permit.cc

class Controller:

    def __init__(self, runtime, lease, root, *, permit_reader=None, clock=time.time, wait=None):
        cc.need(type(runtime.manager) is QualificationManager and type(runtime.control_store) is Store and (runtime.manager.store is runtime.control_store), 'same_actual_Manager_Store')
        cc.need(isinstance(runtime.adapter, CreativeNodeAdapter) and runtime.manager.adapter is runtime.adapter, 'same_existing_C_adapter')
        cc.need(isinstance(lease, MaintenanceLease) and lease.held and (lease.path == MAINTENANCE_LOCK_PATH) and (runtime.server.scheduler.manager is runtime.manager), 'same_lease_shared_Scheduler')
        self.runtime = runtime
        self.lease = lease
        self.root = Path(root)
        self.reader = permit_reader or (lambda: permit.load(permit.HX))
        self.clock = clock
        self.wait = wait or (lambda s: time.sleep(s))
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.thread = None
        self.document = None
        self.token = None
        self.cid = None
        self.error = None
        self.stop_result = None
        self.samples = None
        self.admitted = False
        self._cleanup_inflight = False
        cc.need(not hasattr(runtime.manager, 'start_c_firsttrial'), 'one_C_Manager_extension')
        runtime.manager.start_c_firsttrial = MethodType(start_c_firsttrial, runtime.manager)

    def identity(self, *, starting=False, stop=False):
        doc = self.document if stop else self.reader()
        cc.need(doc is not None, 'C_root_permit_required')
        doc.check(now=self.clock(), starting=starting)
        v = doc.value
        cc.need(self.lease.held and self.lease._fd is not None, 'original_physical_lease_required')
        st = os.fstat(self.lease._fd)
        named = self.lease.path.lstat()
        cc.need([st.st_dev, st.st_ino] == v['lease_dev_inode'] and (st.st_dev, st.st_ino) == (named.st_dev, named.st_ino) and (v['manager_pid'] == os.getpid()), 'actual_original_lease_and_PID')
        if self.document is not None:
            cc.need(doc.sha256 == self.document.sha256, 'C_permit_changed')
        return doc

    def command(self, body, caller):
        if body.get('action') == 'cleanup':
            return self.cleanup_command(body, caller)
        with self.lock:
            cc.need(not self._cleanup_inflight, 'C_cleanup_inflight_no_other_command')
            doc = self.identity(starting=body.get('action') == 'start', stop=body.get('action') == 'stop')
            v = doc.value
            permit.request(body, v['run_id'])
            cc.need(caller == v['caller_owner'], 'derived_C_trial_owner_only')
            ledger = Ledger(self.root)
            try:
                ledger.initialize(v['run_id'], {'run': v['run_id'], 'permit': doc.sha256, 'generation': v['generation'], 'owner': v['owner']})
                prior = ledger.begin(body['key'], caller, body)
                if prior is not None:
                    return prior
                phase = ledger.view(v['run_id'])
                action = body['action']
                this_start = False
                try:
                    if action == 'start':
                        cc.need(phase['phase'] == 'PREPARED' and (not phase['attempted']) and (self.document is None), 'single_C_trial_no_replay')
                        ledger.mark(v['run_id'], 'START_INTENT', generation=v['generation'], attempted=True)
                        this_start = True
                        self.document = doc
                        from G8_C_FIRSTTRIAL_CANDIDATE_R1.samples import Samples
                        self.samples = Samples(self.root, doc)
                        result = self.runtime.manager.start_c_firsttrial(controller=self, run_id=v['run_id'])
                        ledger.mark(v['run_id'], 'TRIAL_HELD')
                    elif action == 'stop':
                        cc.need(self.document is not None and phase['attempted'], 'actual_bound_trial_required')
                        ledger.mark(v['run_id'], 'STOP_INTENT')
                        result = self.stop()
                        if result.get('stopped') is True and result.get('confirmed') is True:
                            ledger.mark(v['run_id'], 'STOPPED_HELD')
                    else:
                        cc.need(self.cid is not None and phase['phase'] == 'TRIAL_HELD', 'C_started_same_process_trial_required')
                        if action == 'submit':
                            cc.need(not getattr(self, 'submitted', False), 'single_C_prompt_no_replay')
                            ledger.mark(v['run_id'], 'SUBMIT_INTENT')
                            self.submitted = True
                        result = adapter.call(self.runtime.adapter, action, doc, container_id=self.cid)
                        if action == 'submit':
                            ledger.mark(v['run_id'], 'TRIAL_HELD')
                    result = dict(result, ready=False, hardware_validated=False, serving_enabled=False, qualification='qualification_pending', threshold_calibration_required=True)
                    ledger.finish(body['key'], result)
                    return result
                except BaseException as exc:
                    if this_start and self.runtime.control_store.still_owned(permit.PROFILE, owner=permit.OWNER, generation=v['generation']):
                        try:
                            self.stop()
                        except BaseException:
                            self.error = 'start_failed_stop_unconfirmed'
                    exclusive(ledger.root / (body['key'] + '.failure.json'), {'error': type(exc).__name__, 'run_id': v['run_id'], 'intent': ledger.view(v['run_id']), 'no_replay': True})
                    raise
            finally:
                ledger.close()

    def start(self):
        doc = self.identity(starting=True)
        v = doc.value
        scheduler = self.runtime.server.scheduler
        jid = 'job_' + v['run_id']
        self.token = scheduler.reserve_creative(jid)
        cc.need(scheduler.yield_for_creative(jid, self.token), 'existing_chat_safe_yield_pending')
        store_admission.reserve(self.runtime.control_store, doc)
        self.admitted = True
        scheduler.pin_creative(jid, self.token, v['generation'])
        for i in range(3):
            self.identity(starting=True)
            scheduler.assert_creative(jid, self.token)
            r = adapter.call(self.runtime.adapter, 'preflight', doc)
            m = r.get('memory', {})
            cc.need(r.get('clear') is True and m.get('source') == 'proc_meminfo' and (m.get('mem_total_bytes') == v['host_facts']['total_bytes']) and (type(m.get('mem_available_bytes')) is int) and (m['mem_available_bytes'] / 2 ** 30 >= v['policy']['initial_available_gib']), 'fresh_actual_C_initial_memory_and_GPUclear')
            self.samples.append(r)
            if i < 2:
                self.wait(2.0)
        a = self.runtime.adapter
        with a._journal.transition(permit.PROFILE):
            a._check_recorded_owner(permit.PROFILE, v['generation'], permit.OWNER)
            a._journal.bind_preflight_clear(profile=permit.PROFILE, generation=v['generation'], owner=permit.OWNER, nodes=[permit.NODENAME])
            a._journal.record(profile=permit.PROFILE, generation=v['generation'], owner=permit.OWNER, nodes=[permit.NODENAME], status='start_requested')
        self.thread = threading.Thread(target=self.monitor, name='C-firsttrial-watchdog', daemon=False)
        self.thread.start()
        cc.need(adapter.call(a, 'claim', doc).get('claimed') is True, 'C_claim_refused')
        r = adapter.call(a, 'start', doc)
        cc.need(r.get('started') is True and cc.digest(r.get('container_id')), 'C_start_unknown_retained')
        self.cid = r['container_id']
        a._journal.record(profile=permit.PROFILE, generation=v['generation'], owner=permit.OWNER, nodes=[permit.NODENAME], status='started')
        return r

    def stop(self):
        doc = self.identity(stop=True)
        v = doc.value
        cc.need(self.runtime.control_store.still_owned(permit.PROFILE, owner=permit.OWNER, generation=v['generation']), 'C_exact_owned_stop_only')
        result = self.runtime.manager.stop_profile(permit.PROFILE, owner=permit.OWNER, expected_generation=v['generation'], actor=permit.OWNER)
        self.stop_result = result
        if result.get('stopped') is True and result.get('confirmed') is True:
            self.stop_event.set()
        return result

    def monitor(self):
        try:
            while not self.stop_event.wait(2.0):
                with self.lock:
                    if self.stop_event.is_set():
                        return
                    doc = self.identity()
                    v = doc.value
                    if self.clock() >= v['expires_at']:
                        self.stop()
                        return
                    r = adapter.call(self.runtime.adapter, 'status', doc, container_id=self.cid)
                    self.samples.append(r)
                    cc.need(r.get('guard_state') in ('ARMING_HOLD_RETAINED', 'ACTIVE'), 'C_guard_not_live')
        except BaseException as exc:
            self.error = type(exc).__name__
            try:
                with self.lock:
                    self.stop()
            except BaseException:
                self.error += ';owned_stop_unconfirmed'
        finally:
            self.runtime.control_store.close_thread_connection()

    def close(self):
        cc.need(not self._cleanup_inflight, 'C_cleanup_inflight_retain_runtime_lease')
        if self.document is not None and self.runtime.control_store.still_owned(permit.PROFILE, owner=permit.OWNER, generation=self.document.value['generation']):
            cc.need(self.lock.acquire(timeout=1.0), 'C_inflight_command_retain_runtime_lease')
            try:
                if self.stop_result is None or not self.stop_result.get('confirmed'):
                    self.stop()
            finally:
                self.lock.release()
            cc.need(self.stop_result.get('stopped') is True and self.stop_result.get('confirmed') is True, 'C_shutdown_stop_unconfirmed_retain_runtime_lease')
        if self.admitted:
            cc.need(self.stop_result is not None and self.stop_result.get('stopped') is True and (self.stop_result.get('confirmed') is True), 'C_admitted_stop_unconfirmed_retain_runtime_lease')
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(1.0)
            cc.need(not self.thread.is_alive(), 'C_watchdog_alive_retain_runtime_lease')
        if self.samples is not None:
            self.samples.close()

    def cleanup_identity(self):
        """Cached permit allows stop/release after expiry/revoke, never new start."""
        doc = self.identity(stop=True)
        v = doc.value
        rt = self.runtime
        s = rt.server.scheduler
        cc.need(type(rt.manager) is QualificationManager and type(rt.control_store) is Store and (rt.manager.store is rt.control_store) and (rt.manager.adapter is rt.adapter) and (s.manager is rt.manager), 'same_original_cleanup_Manager_Store_adapter_scheduler')
        cc.need(self.admitted and cc.digest(self.cid) and (self.token is not None), 'actual_bound_C_trial_cleanup_only')
        cc.need(self.thread is not None, 'actual_C_watchdog_lifecycle_required')
        cc.need(self.stop_result is not None and self.stop_result.get('stopped') is True and (self.stop_result.get('confirmed') is True) and (self.stop_result.get('profile') == permit.PROFILE) and (type(self.stop_result.get('generation')) is int) and (self.stop_result['generation'] == v['generation']) and self.stop_event.is_set(), 'original_exact_stop_confirmed_required')
        p = rt.control_store.profile_view(permit.PROFILE)
        n = rt.control_store.node_view(permit.NODENAME)
        cc.need(p['state'] == 'STOPPED' and p['owner'] == permit.OWNER and (p['generation'] == v['generation']) and (p['hardware_validated'] is False) and (p['min_start_available_gib'] is None) and (p['runtime_floor_gib'] is None), 'C_STOPPED_HELD_uncalibrated_required')
        cc.need(n['hold_profile'] == permit.PROFILE and n['hold_owner'] == permit.OWNER and (n['hold_generation'] == v['generation']) and (n['hold_operation'] == 'qualification') and (n['quarantined'] is False), 'exact_C_qualification_hold_required')
        held = s.assert_creative('job_' + v['run_id'], self.token)
        cc.need(held['state'] == 'HELD' and held['generation'] == v['generation'], 'same_C_scheduler_HELD_slot')
        with s._lock:
            cc.need(not s._creative_profiles() & s._draining, 'no_creative_drain_inflight')
        return doc

    def cleanup_command(self, body, caller):
        cc.need(self.lock.acquire(blocking=False), 'C_inflight_command_cleanup_refused')
        ledger = None
        owned = True
        flag = False
        try:
            cc.need(not self._cleanup_inflight, 'C_cleanup_already_inflight')
            doc = self.identity(stop=True)
            v = doc.value
            permit.request(body, v['run_id'])
            cc.need(caller == v['caller_owner'], 'derived_C_trial_owner_only')
            ledger = Ledger(self.root)
            ledger.initialize(v['run_id'], {'run': v['run_id'], 'permit': doc.sha256, 'generation': v['generation'], 'owner': v['owner']})
            prior = ledger.begin(body['key'], caller, body)
            if prior is not None:
                return prior
            cc.need(ledger.view(v['run_id'])['phase'] == 'STOPPED_HELD', 'C_cleanup_terminal_phase_required_no_replay')
            self.cleanup_identity()
            self._cleanup_inflight = True
            flag = True
            self.lock.release()
            owned = False
            if self.thread is not None:
                self.thread.join(1.0)
                cc.need(not self.thread.is_alive(), 'C_watchdog_alive_no_release')
            if self.samples is not None:
                self.samples.close()
            cc.need(self.lock.acquire(timeout=1.0), 'C_cleanup_lock_changed_no_release')
            owned = True
            self.cleanup_identity()
            ledger.mark(v['run_id'], 'CLEANUP_INTENT')
            observed = self.runtime.adapter.confirm_stop(permit.PROFILE, nodes=[permit.NODENAME], generation=v['generation'])
            now = self.clock()
            cc.need(type(observed) is dict and observed.get('stopped') is True and (observed.get('profile') == permit.PROFILE) and (type(observed.get('generation')) is int) and (observed['generation'] == v['generation']) and (type(observed.get('nodes')) is dict) and (set(observed['nodes']) == {permit.NODENAME}), 'fresh_exact_native_C_confirmation')
            node = observed['nodes'][permit.NODENAME]
            cc.need(type(node) is dict and node.get('stopped') is True and (node.get('record_state') == 'CLEAR'), 'native_C_GPUempty_CLEAR_required')
            for key in ('observed_at', 'source_observed_at'):
                t = node.get(key)
                cc.need(type(t) in (int, float) and math.isfinite(t) and (0 <= now - t <= self.runtime.control_store.policy_sample_max_age()), 'fresh_original_C_native_time')
            result = self.runtime.manager.release_profile(permit.PROFILE, owner=permit.OWNER, generation=v['generation'])
            cc.need(type(result) is dict and result.get('released') is True and (result.get('profile') == permit.PROFILE) and (result.get('generation') == v['generation']), 'original_core_release_unknown_no_replay')
            ledger.mark(v['run_id'], 'CORE_RELEASED_SCHEDULER_RETAINED')
            self.await_clear_guard()
            self.identity(stop=True)
            self.runtime.server.scheduler.release_creative('job_' + v['run_id'], self.token)
            self.admitted = False
            ledger.mark(v['run_id'], 'CLEANED_RELEASED')
            result = {'cleaned': True, 'core_released': True, 'scheduler_released': True, 'profile': permit.PROFILE, 'generation': v['generation'], 'ready': False, 'hardware_validated': False, 'serving_enabled': False, 'qualification': 'qualification_pending', 'threshold_calibration_required': True}
            ledger.finish(body['key'], result)
            return result
        except BaseException as exc:
            if ledger is not None:
                path = ledger.root / (body['key'] + '.failure.json')
                if not path.exists():
                    phase = ledger.view(v['run_id'])
                    observed = {'core': None, 'scheduler_slot_present': None}
                    try:
                        p = self.runtime.control_store.profile_view(permit.PROFILE)
                        observed['core'] = {k: p[k] for k in ('state', 'owner', 'generation')}
                        with self.runtime.server.scheduler._lock:
                            observed['scheduler_slot_present'] = self.runtime.server.scheduler._creative is not None
                    except Exception:
                        pass
                    exclusive(path, {'error': type(exc).__name__, 'run_id': v['run_id'], 'intent': phase, 'no_replay': True, 'core_may_already_be_released': phase['phase'] in ('CLEANUP_INTENT', 'CORE_RELEASED_SCHEDULER_RETAINED', 'CLEANED_RELEASED'), 'scheduler_may_already_be_released': phase['phase'] in ('CORE_RELEASED_SCHEDULER_RETAINED', 'CLEANED_RELEASED'), 'actual_local_observation': observed})
            raise
        finally:
            if flag:
                if not owned:
                    self.lock.acquire()
                    owned = True
                self._cleanup_inflight = False
            if ledger is not None:
                ledger.close()
            if owned:
                self.lock.release()

    def await_clear_guard(self):
        """Existing readonly wire: no new C root privilege or journal binding.

        Manager.release_profile's confirm_stop updates CLEAR.updated_at again.
        Keep the scheduler slot until the existing guard has observed that row.
        Only an explicit heartbeat-not-yet-observed refusal is polled; unknown
        transport/enumeration/action is terminal. A slow exchange retains slot
        and runtime lease, without claiming a hard 10s kernel I/O bound.
        """
        rt = self.runtime
        a = rt.adapter
        v = self.document.value
        qwen = rt.control_store.profile_view('qwen-a-c')
        cc.need(qwen['state'] == 'STOPPED' and qwen['owner'] is None and (type(qwen['generation']) is int) and (qwen['generation'] > 0), 'actual_idle_original_Qwen_generation_required')
        deadline = time.monotonic() + 10.0
        while True:
            cc.need(time.monotonic() < deadline, 'C_guard_clear_observation_deadline_partial')
            rt.server.scheduler.assert_creative('job_' + v['run_id'], self.token)
            a._require_usable()
            reply, meta = a._exchange(permit.NODENAME, 'preflight', profile='qwen-a-c', owner=permit.OWNER, generation=qwen['generation'])
            cc.need(time.monotonic() <= deadline and reply is not None, 'C_guard_clear_transport_unknown_partial')
            if reply.get('status') == 'refused' and reply.get('reason_code') == 'runtime_guard_unverified':
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
                continue
            gpu = reply.get('gpu', {})
            cc.need(reply.get('status') == 'ok' and reply.get('clear') is True and (reply.get('reason_code') == 'gpu_clear') and (gpu.get('enumeration') == 'complete') and (gpu.get('truncated') is False) and (gpu.get('empty') is True) and (type(gpu.get('process_count')) is int) and (gpu['process_count'] == 0) and (type(gpu.get('gpu_container_count')) is int) and (gpu['gpu_container_count'] == 0) and (gpu.get('processes') == []) and (gpu.get('containers') == []), 'C_fresh_complete_GPUempty_guard_clear_required')
            t = reply.get('observed_at')
            cc.need(type(t) in (int, float) and math.isfinite(t) and (0 <= self.clock() - t <= rt.control_store.policy_sample_max_age()), 'C_guard_clear_reply_fresh')
            return

def start_c_firsttrial(manager, *, controller, run_id):
    """Instance-bound definition; preserves exact frozen Manager class identity."""
    cc.need(type(manager) is QualificationManager and controller.runtime.manager is manager and (controller.document.value['run_id'] == run_id), 'sole_Manager_fixed_C_trial_method')
    return controller.start()
