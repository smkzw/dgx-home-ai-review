# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One non-daemon read-only thread; no lifecycle action or automatic recovery."""
import copy
import hashlib
import json
import math
import os
import re
from pathlib import Path
import stat
import threading
import time
from G7_INTEGRATION_CANDIDATE_R2.durable import need, private_dir, exclusive, fsync_dir, Refusal
from G7_QUALIFICATION_IMPLEMENTATION_R1 import permit as qp
from G7_QUALIFICATION_IMPLEMENTATION_R1.manager import QualificationManager
from G7_QUALIFICATION_IMPLEMENTATION_R1.store import Store
from G7_QUALIFICATION_TELEMETRY_R2.adapter import QualificationNodeAdapter, validate_telemetry
from node_adapter.client import NodeAdapter
from hx_service.service import MaintenanceLease
INTERVAL_S = 2.0
CAP_BYTES = 8 * 1024 * 1024
ROW_BYTES = 8192
FINAL_RESERVE_BYTES = 32768
ARM_TIMEOUT_S = 65.0
JOIN_TIMEOUT_S = 1.0

def identity_guard(runtime, lease):
    m = runtime.manager
    a = runtime.adapter
    need(type(m) is QualificationManager and type(m.store) is Store and (m.store is runtime.control_store), 'same_actual_Manager_Store')
    need(isinstance(a, QualificationNodeAdapter) and m.adapter is a, 'same_actual_qualification_adapter')
    for name, fn in (('observe_telemetry', QualificationNodeAdapter.observe_telemetry), ('observe_qualification', QualificationNodeAdapter.observe_qualification), ('_exchange', NodeAdapter._exchange)):
        need(getattr(getattr(a, name, None), '__func__', None) is fn, 'unchanged_bound_sampling_definition')
    need(isinstance(lease, MaintenanceLease) and lease.held, 'same_held_original_physical_lease')
    return m

class Journal:
    """Finite O_EXCL private evidence; fsync may block and is not cancellable."""

    def __init__(self, root, header):
        self.root = private_dir(root)
        self.path = self.root / 'telemetry.jsonl'
        self.used = 0
        self.fd = None
        self.digest = hashlib.sha256()
        self.tainted = False
        exclusive(self.root / 'telemetry.intent.json', header)
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
        try:
            fsync_dir(self.root)
            self._identity = self.identity()
        except BaseException:
            self.close()
            raise

    def identity(self):
        opened = os.fstat(self.fd)
        named = self.path.lstat()
        need(stat.S_ISREG(opened.st_mode) and opened.st_uid == os.geteuid() and (stat.S_IMODE(opened.st_mode) == 384) and (opened.st_nlink == 1), 'private_single_owned_telemetry_file')
        need((opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino), 'same_held_telemetry_inode')
        return (opened.st_dev, opened.st_ino)

    def write(self, value, *, final=False):
        need(not self.tainted, 'tainted_JSONL_no_append')
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        need(len(raw) <= ROW_BYTES, 'telemetry_row_budget')
        limit = CAP_BYTES if final else CAP_BYTES - FINAL_RESERVE_BYTES
        need(self.used + len(raw) <= limit, 'telemetry_total_byte_budget')
        need(self.identity() == self._identity and os.fstat(self.fd).st_size == self.used, 'telemetry_file_changed')
        offset = 0
        try:
            while offset < len(raw):
                n = os.write(self.fd, raw[offset:])
                need(n > 0, 'telemetry_short_write')
                self.digest.update(raw[offset:offset + n])
                offset += n
                self.used += n
            os.fsync(self.fd)
        except BaseException:
            self.tainted = True
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

class Sampler:

    def __init__(self, runtime, lease, *, monotonic=time.monotonic, wall=time.time):
        identity_guard(runtime, lease)
        self.runtime = runtime
        self.lease = lease
        self.monotonic = monotonic
        self.wall = wall
        self.stop_event = threading.Event()
        self.first = threading.Event()
        self.done = threading.Event()
        self.thread = None
        self.document = None
        self.journal = None
        self.started = False
        self._state_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self.error = None
        self.writer_finalized = False
        self.baseline_complete = False
        self.stop_reason = None
        self.end_reason = None
        self.start_ack_ids = None
        self.stats = {n: {'memory_samples': 0, 'qualified_samples': 0, 'incomplete_observations': 0, 'sampled_min_available_bytes': None, 'sampled_max_total_minus_available_bytes': None, 'sampled_max_baseline_minus_available_bytes': None, 'max_observed_gap_s': 0.0, 'baseline_available_bytes': None, 'first_monotonic_s': None, 'last_monotonic_s': None, 'container_id': None, 'last_bound_memory_remote_timestamp': None, 'max_bound_memory_remote_gap_s': 0.0, 'qualified_guard_states_seen': [], 'last_valid_memory_received_monotonic_s': None, 'max_valid_memory_received_gap_s': 0.0} for n in qp.c.NODES}

    def arm(self, document, root):
        with self._state_lock:
            need(not self.started, 'telemetry_one_attempt_no_restart')
            m = identity_guard(self.runtime, self.lease)
            need(type(document) is qp.Document and m._q_document.sha256 == document.sha256 and (m._q_document.check(now=m._now()).value == document.value) and (m._q_context[0] is self.lease), 'same_bound_document_and_original_lease')
            document.check(now=m._now(), starting=True)
            m._held_physical_lease(document.value)
            self.started = True
            self.document = document
            self.bound_document = m._q_document
            self.start_mono = qp.c.number(self.monotonic())
            self.start_wall = qp.c.number(self.wall())
            v = document.value
            header = {'schema': 'g7-qualification-telemetry-intent/v1', **{k: v[k] for k in ('run_id', 'profile', 'owner', 'generation', 'manager_pid', 'lease_dev_inode', 'input_identity')}, 'permit_sha256': document.sha256, 'monotonic_start_s': self.start_mono, 'local_wall_start': self.start_wall, 'cap_bytes': CAP_BYTES, 'row_bytes': ROW_BYTES, 'interval_s': INTERVAL_S, 'no_restart': True, 'threshold_calibration_required': True, 'hardware_validated': False, 'automatic_READY': False}
            try:
                self.journal = Journal(root, header)
                self.thread = threading.Thread(target=self._run, name='g7-same-owner-telemetry', daemon=False)
                self.thread.start()
            except BaseException:
                self.error = 'arm_failed'
                self.done.set()
                if self.journal is not None:
                    self.journal.close()
                raise
        if not self.first.wait(ARM_TIMEOUT_S):
            self.stop_event.set()
            raise TimeoutError('telemetry_pre_dispatch_sample_timeout_no_replay')
        need(self.baseline_complete and self.error is None, 'actual_pre_dispatch_AB_memory_required')

    def bind_start_ack(self, result):
        """Bind original Manager-returned real ACK; never accept a caller CID."""
        try:
            v = self.document.value
            r = result['adapter_reply']
            need(r['started'] is True and all((r[k] == v[k] and type(r[k]) is type(v[k]) for k in ('profile', 'owner', 'generation'))), 'actual_start_ack_identity')
            nodes = r['nodes']
            need(type(nodes) is dict and set(nodes) == set(qp.c.NODES), 'actual_start_ack_AB')
            ids = {}
            for node, item in nodes.items():
                cid = item.get('container_id')
                need(item.get('started') is True and type(cid) is str and re.fullmatch('[0-9a-f]{64}', cid), 'actual_start_ack_full_CID')
                ids[node] = cid
            with self._stats_lock:
                need(self.start_ack_ids is None, 'start_ack_already_bound')
                for node, cid in ids.items():
                    need(self.stats[node]['container_id'] in (None, cid), 'start_ack_differs_observed_CID')
                self.start_ack_ids = ids
        except (ValueError, KeyError, TypeError):
            self.error = 'actual_start_ack_binding_failed'
            self.request_stop('start_ack_binding_failed')

    def local_binding(self):
        m = identity_guard(self.runtime, self.lease)
        v = self.document.value
        need(m._q_document is self.bound_document and m._q_document.check(now=m._now()).value == self.document.check(now=m._now()).value and (m._q_context[0] is self.lease) and (m._q_context[1] == self.document.sha256), 'same_current_document')
        m._held_physical_lease(v)
        view = m.store.profile_view(v['profile'])
        admission = m.store.qualification_run(v['run_id'])
        held = False
        if admission is not None:
            need(all((admission[k] == v[k] and type(admission[k]) is type(v[k]) for k in ('profile', 'owner', 'generation'))) and admission['permit_sha256'] == self.document.sha256, 'same_durable_admission')
            m._trial_held(v)
            held = True
            need(view['generation'] == v['generation'] and view['owner'] == v['owner'], 'current_owner_generation')
        else:
            need(view['owner'] is None and view['generation'] < v['generation'], 'pre_admission_only_no_foreign_hold')
        need(view['hardware_validated'] is False and view['min_start_available_gib'] is None and (view['state'] != 'READY'), 'uncalibrated_no_READY')
        return {'core_state': view['state'], 'owner': view['owner'], 'generation': view['generation'], 'qualification_admitted': held, 'physical_lease_dev_inode': list(v['lease_dev_inode'])}

    def sample(self, node):
        before = self.local_binding()
        a = self.runtime.adapter
        v = self.document.value
        start = qp.c.number(self.monotonic())
        start_wall = qp.c.number(self.wall())
        a._require_usable()
        a._checked_nodes(v['profile'], list(qp.c.NODES))
        a._check_recorded_owner(v['profile'], v['generation'], v['owner'])
        reply, meta = a._exchange(node, 'probe')
        end = qp.c.number(self.monotonic())
        end_wall = qp.c.number(self.wall())
        after = self.local_binding()
        need(self.start_mono <= start <= end and self.start_wall <= start_wall <= end_wall, 'local_clock_discontinuity')
        row = {'schema': 'g7-qualification-telemetry-row/v1', 'node': node, **{k: v[k] for k in ('run_id', 'profile', 'owner', 'generation')}, 'permit_sha256': self.document.sha256, 'monotonic_start_s': self.start_mono, 'local_sent_monotonic_s': start, 'local_received_monotonic_s': end, 'local_sent_wall': start_wall, 'local_received_wall': end_wall, 'adapter_received_wall': meta['received_at'], 'node_reply_observed_at': meta.get('remote_observed_at'), 'local_binding_before': before, 'local_binding_after': after, 'local_binding_unchanged': before == after, 'memory': None, 'memory_source': None, 'telemetry': None, 'actual_start_ack_CID': self.start_ack_ids[node] if self.start_ack_ids else None, 'complete': False, 'reason_code': 'existing_transport_failure'}
        if reply is not None:
            row['node_reply_observed_at'] = qp.c.number(reply['observed_at'])
            row['reason_code'] = 'readonly_observation_incomplete'
            memory = a._memory_view(reply)
            if memory is not None and memory['mem_total_bytes'] == v['host_facts'][node]['total_bytes']:
                row['memory'] = memory
                row['memory_source'] = 'original_probe_top_memory_unbound'
            try:
                telemetry = validate_telemetry(reply, document=self.document, node=node)
                row['telemetry'] = telemetry
                if 'actual_memory_unknown' not in telemetry['missing']:
                    row['memory'] = telemetry['memory']
                    row['memory_source'] = 'bound_qualification_telemetry_memory'
                row['complete'] = telemetry['complete'] and before == after and after['qualification_admitted'] and (row['actual_start_ack_CID'] == telemetry['record']['container_id']) and (row['actual_start_ack_CID'] is not None)
                row['reason_code'] = 'qualified_actual_sample' if row['complete'] else 'readonly_observation_incomplete'
            except (ValueError, KeyError, TypeError):
                pass
        return row

    def update(self, row):
        node = row['node']
        memory = row['memory']
        end = row['local_received_monotonic_s']
        with self._stats_lock:
            s = self.stats[node]
            t = row['telemetry']
            if t is not None and t['complete'] and row['local_binding_after']['qualification_admitted']:
                cid = t['record']['container_id']
                need(s['container_id'] in (None, cid), 'current_CID_changed_no_adoption')
                need(self.start_ack_ids is None or self.start_ack_ids[node] == cid, 'observed_CID_differs_actual_start_ack')
                s['container_id'] = cid
            if s['last_monotonic_s'] is not None:
                need(end > s['last_monotonic_s'], 'strictly_ordered_local_samples')
                s['max_observed_gap_s'] = max(s['max_observed_gap_s'], end - s['last_monotonic_s'])
            s['first_monotonic_s'] = end if s['first_monotonic_s'] is None else s['first_monotonic_s']
            s['last_monotonic_s'] = end
            if not row['complete']:
                s['incomplete_observations'] += 1
            else:
                cid = row['telemetry']['record']['container_id']
                state = row['telemetry']['guard']['state']
                if state not in s['qualified_guard_states_seen']:
                    need(len(s['qualified_guard_states_seen']) < 32, 'guard_state_summary_budget')
                    s['qualified_guard_states_seen'].append(state)
                need(s['container_id'] in (None, cid), 'current_CID_changed_no_adoption')
                s['container_id'] = cid
                s['qualified_samples'] += 1
            if memory is not None:
                if row['memory_source'] == 'bound_qualification_telemetry_memory':
                    stamp = row['telemetry']['memory_observed_at']
                    previous = s['last_bound_memory_remote_timestamp']
                    if previous is not None:
                        need(stamp > previous, 'remote_memory_clock_discontinuity')
                        s['max_bound_memory_remote_gap_s'] = max(s['max_bound_memory_remote_gap_s'], stamp - previous)
                    s['last_bound_memory_remote_timestamp'] = stamp
                previous = s['last_valid_memory_received_monotonic_s']
                if previous is not None:
                    s['max_valid_memory_received_gap_s'] = max(s['max_valid_memory_received_gap_s'], end - previous)
                s['last_valid_memory_received_monotonic_s'] = end
                available = memory['mem_available_bytes']
                total = memory['mem_total_bytes']
                s['memory_samples'] += 1
                if s['baseline_available_bytes'] is None:
                    s['baseline_available_bytes'] = available
                s['sampled_min_available_bytes'] = available if s['sampled_min_available_bytes'] is None else min(s['sampled_min_available_bytes'], available)
                value = total - available
                s['sampled_max_total_minus_available_bytes'] = value if s['sampled_max_total_minus_available_bytes'] is None else max(s['sampled_max_total_minus_available_bytes'], value)
                value = s['baseline_available_bytes'] - available
                s['sampled_max_baseline_minus_available_bytes'] = value if s['sampled_max_baseline_minus_available_bytes'] is None else max(s['sampled_max_baseline_minus_available_bytes'], value)

    def summary(self):
        with self._stats_lock:
            stats = copy.deepcopy(self.stats)
        return {'schema': 'g7-qualification-telemetry-summary/v1', 'started': self.started, 'thread_alive': self.thread is not None and self.thread.is_alive(), 'error_code': self.error, 'writer_finalized': self.writer_finalized, 'baseline_complete': self.baseline_complete, 'stop_reason_code': self.stop_reason, 'end_reason_code': self.end_reason, 'stats_scope': 'successfully_fsynced_and_updated_rows_before_error; failing_row_may_be_retained_unupdated', 'stats': stats, 'actual_start_ack_container_ids': self.start_ack_ids, 'bytes_retained': self.journal.used if self.journal else 0, 'full_series_coverage_proven': False, 'instantaneous_peak_proven': False, 'threshold_calibration_required': True, 'hardware_validated': False, 'automatic_READY': False}

    def _run(self):
        try:
            first = True
            while not self.stop_event.is_set():
                baseline = True
                terminal = False
                for node in qp.c.NODES:
                    if self.stop_event.is_set():
                        baseline = False
                        break
                    row = self.sample(node)
                    self.journal.write(row)
                    self.update(row)
                    baseline = baseline and row['memory'] is not None
                    terminal = terminal or (row['local_binding_after']['qualification_admitted'] and row['local_binding_after']['core_state'] in ('STOPPED', 'FAILED', 'QUARANTINED'))
                if first:
                    self.baseline_complete = baseline
                    self.first.set()
                    first = False
                    need(baseline, 'actual_pre_dispatch_AB_memory_required')
                if terminal:
                    self.end_reason = 'terminal_core_observed'
                    break
                if self.wall() >= self.document.value['expires_at']:
                    self.end_reason = 'permit_deadline_observed'
                    break
                self.stop_event.wait(INTERVAL_S)
        except BaseException as exc:
            self.error = str(exc) if isinstance(exc, (Refusal, qp.c.Refusal)) and re.fullmatch('[A-Za-z0-9_]{1,128}', str(exc)) else type(exc).__name__
        finally:
            self.first.set()
            try:
                need(not self.journal.tainted, 'partial_or_unsynced_JSONL_preserved_no_final_acceptance')
                self.journal.write({'event': 'terminal', 'summary': self.summary()}, final=True)
                exclusive(self.journal.root / 'telemetry.finished.json', {'schema': 'g7-qualification-telemetry-finished/v1', 'run_id': self.document.value['run_id'], 'permit_sha256': self.document.sha256, 'jsonl_bytes': self.journal.used, 'jsonl_sha256': self.journal.digest.hexdigest(), 'summary_at_writer_completion': self.summary(), 'threshold_calibration_required': True})
                self.writer_finalized = True
            except BaseException as exc:
                self.error = self.error or 'final_write_' + type(exc).__name__
            finally:
                try:
                    self.journal.close()
                finally:
                    self.runtime.control_store.close_thread_connection()
                    self.done.set()

    def request_stop(self, reason_code='stop_requested'):
        need(type(reason_code) is str and re.fullmatch('[a-z0-9_]{1,128}', reason_code), 'fixed_stop_reason')
        if self.stop_reason is None:
            self.stop_reason = reason_code
        self.stop_event.set()

    def close(self):
        self.request_stop('runtime_shutdown')
        if self.thread is not None:
            self.thread.join(JOIN_TIMEOUT_S)
            if self.thread.is_alive():
                raise TimeoutError('telemetry_thread_or_writer_alive_stores_and_physical_lease_retained')
