# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""New once-only CPU reservation on the existing soleRuntime, never bf84 replay."""
import os
import math
import re
import threading
import time
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, strict, encode, sha, exclusive, metadata
from state import Originals
from prelaunch_recovery import Recovery
from asset_stage import Stages, ACTIONS as ASSET_ACTIONS
from contract import OPERATION, EPOCH_OPERATION, PC_ROOT
ROOT = Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d') / ('registry-' + OPERATION)
SERVICE = PC_ROOT
BUDGET = {'CPU': 1, 'memory_bytes': 4294967296, 'swap_bytes': 0, 'tasks': 256, 'io_read_bytes_per_second': 62914560, 'io_write_bytes_per_second': 62914560, 'runtime_seconds': 1800}
APPROVED_RELEASE = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
ACTIONS = frozenset(('reserve-registry-directfetch', 'pulse-registry-directfetch', 'finish-registry-directfetch', 'status-registry-source', 'activate-registry-source', 'recover-failed-registry', 'finish-failed-registry'))

class RegistryGrant:

    def __init__(self, runtime, lease, config, operator, *, negative, current_epoch, entry_ready, whole_clear, terminal, failure_terminal, clock=time.monotonic, root=ROOT):
        need(APPROVED_RELEASE is not None, 'registry_source_pending')
        bridge = operator.cpu_bridge
        need(runtime is operator.runtime is bridge.runtime and lease is operator.lease is bridge.lease and (runtime.server.scheduler is operator.scheduler is bridge.scheduler) and (runtime.manager is bridge.facade.manager) and (runtime.adapter is bridge.facade.adapter) and (runtime.manager.store is runtime.control_store), 'registry_same_sole_runtime_not_new_Bridge')
        need(not hasattr(operator, 'registry_grant'), 'registry_attached_once')
        self.runtime, self.lease, self.config, self.operator = (runtime, lease, config, operator)
        self.s, self.collector, self.facade = (bridge.scheduler, bridge.collector, bridge.facade)
        self.negative, self.whole_clear, self.terminal = (negative, whole_clear, terminal)
        self.failure_terminal = failure_terminal
        self.current_epoch, self.entry_ready = (current_epoch, entry_ready)
        self.live_baseline = None
        self.clock, self.root, self.lock = (clock, root, threading.Lock())
        self.active, self.deadline, self.ordinal, self.reserved = (False, None, 0, None)
        self.epoch = None
        self.closed = False
        self.finished = False
        with self.s._lock:
            try:
                self.prelaunch_recovery = Recovery(self)
                self.asset_stages = Stages(self, operator._asset_terminal)
            except BaseException:
                self.s.restore_operator_block()
                raise
        if self.root.exists():
            rows = Originals(self.root).snapshot()
            entries = set(rows)
            negative = {'intent.json', 'reserved.json', 'failed-terminal.json', 'failed-completed.json', 'failed-fence-released.json'}
            if negative <= entries and (not entries & {'terminal.json', 'completed.json', 'fence-finished.json'}):
                pulses = {n for n in entries if re.fullmatch('pulse-[1-9][0-9]*\\.json', n)}
                need(entries == negative | pulses and sorted((int(n[6:-5]) for n in pulses)) == list(range(1, len(pulses) + 1)), 'failed_finish_exact_entries')
                trusted = self.failure_terminal(historical=True)
                need(encode(trusted) == rows['failed-terminal.json'], 'historical_failed_terminal_full_Root_producer_consumer')
                done = strict(rows['failed-completed.json'])
                mark = strict(rows['failed-fence-released.json'])
                proof = strict(rows['failed-terminal.json'])
                need(done['operation'] == mark['operation'] == OPERATION and done['state'] == 'FAILED_REGISTRY_QUIESCENT' and (done['image_imported'] is done['CPU_success'] is False) and (done['terminal_sha256'] == sha(rows['failed-terminal.json'])) and (mark['completed_sha256'] == sha(rows['failed-completed.json'])) and (mark['operator_maintenance_observed'] is False) and (proof['operation'] == OPERATION) and (proof['source_release_sha256'] == APPROVED_RELEASE), 'historical_failed_finish_not_image_success')
                self.finished = True
                return
            required = {'intent.json', 'reserved.json', 'terminal.json', 'completed.json', 'fence-finished.json'}
            pulses = sorted((int(name[6:-5]) for name in entries - required))
            if not required <= entries or pulses != list(range(1, len(pulses) + 1)):
                self.s.restore_operator_block()
                self.closed = True
            else:
                terminal = strict(rows['terminal.json'])
                trusted = self.terminal(SERVICE / 'fetch-qualified.json', historical=True)
                need(terminal['operation'] == OPERATION and terminal['source_release_sha256'] == APPROVED_RELEASE and (terminal['actual_retained_EXIT0'] is True) and (terminal['models_started'] == 0) and (terminal['image_imported'] is True) and (encode(trusted) == rows['terminal.json']), 'registry_historical_original_terminal_not_service_owned_bool')
                done = strict(rows['completed.json'])
                mark = strict(rows['fence-finished.json'])
                need(done['source_release_sha256'] == APPROVED_RELEASE and done['operation'] == OPERATION and (done['terminal_sha256'] == sha(rows['terminal.json'])) and (mark['completed_sha256'] == sha(rows['completed.json'])) and (mark['operator_maintenance_observed'] is False), 'registry_historical_finish_bound')
                for ordinal in pulses:
                    pulse = strict(rows['pulse-' + str(ordinal) + '.json'])
                    need(pulse['operation'] == OPERATION and pulse['source_release_sha256'] == APPROVED_RELEASE and (pulse['ordinal'] == ordinal) and (pulse['observed_at'] <= done['finished_at']), 'registry_historical_pulses_original')
                self.finished = True

    def same(self):
        need(self.lease.held and self.lease._fd is not None, 'registry_physical_lease_held')
        held, named = (os.fstat(self.lease._fd), self.lease.path.lstat())
        need(metadata(held) == metadata(named) and [held.st_dev, held.st_ino] == [2096, 69257] and (self.runtime.manager.store is self.runtime.control_store) and (self.runtime.manager.adapter is self.runtime.adapter), 'registry_actual_same_owner_FD')

    def counters_locked(self):
        g = self.operator.c_arm_gate
        need(g.runtime is self.runtime and g.s is self.s and (not g.closed) and (not g.closing), 'registry_C_gate_not_open')
        need(all((type(getattr(g, k)) is int and getattr(g, k) == 0 for k in ('public_inflight', 'private_inflight', 'tick_inflight', 'pulse_inflight'))), 'registry_actual_shared_C_wrapped_calls')
        s = self.s
        need(not (s._operator_tick_inflight or s._operator_public_inflight or s._operator_creative_pulse_inflight or (s._creative is not None) or s._infos or any(s._queues.values()) or any(s._active.values()) or s._uncertain or s._ensuring or s._dispatch_checks or s._draining), 'registry_same_lock_all_counters')
        need(self.live_baseline is not None and set(self.live_baseline['Core_generations']) == {'glm-ab', 'qwen-a-c', 'image-turbo-c'}, 'registry_actual_new_epoch_Core_baseline')
        for profile, minimum in (('glm-ab', 10), ('qwen-a-c', 8), ('image-turbo-c', 1)):
            gen = self.live_baseline['Core_generations'][profile]
            need(type(gen) is int and gen > 0, 'qualified_actual_generation_not_request_selected')
            p = self.runtime.control_store.profile_view(profile)
            need(p['state'] == 'STOPPED' and p['owner'] is None and (p['generation'] == gen), 'registry_current_Core_no_fake_generation')
        for row in self.runtime.control_store.nodes_view():
            need(row['hold_profile'] is row['hold_owner'] is row['hold_generation'] is None and row['quarantined'] is False, 'registry_current_nodes_noholds_noQUAR')

    def current(self, phase, *, fenced):
        proof = self.whole_clear.collect(self.runtime, self.lease, self.config, phase, fenced=fenced)
        baseline = self.whole_clear(proof, self.config, self.runtime.manager._now(), fenced=fenced, baseline=self.live_baseline)
        if self.live_baseline is None:
            self.live_baseline = baseline
        self.same()
        return proof

    def command(self, body, uid):
        if body.get('action') in ASSET_ACTIONS:
            return self.asset_stages.command(body, uid)
        need(type(uid) is int and uid == 0 and (type(body) is dict) and (set(body) == ({'action', 'operation', 'request_nonce', 'duration_seconds'} if body.get('action') == 'reserve-registry-directfetch' else {'action', 'operation', 'request_nonce'})) and (body['action'] in ACTIONS) and (body['operation'] == (EPOCH_OPERATION if body['action'] == 'activate-registry-source' else OPERATION)) and (type(body['request_nonce']) is str) and re.fullmatch('[0-9a-f]{32}', body['request_nonce']), 'fixed_Root_registry_command')
        need(self.lock.acquire(blocking=False), 'registry_private_command_inflight')
        try:
            self.same()
            if body['action'] == 'finish-failed-registry':
                return self.finish_failed(body)
            need(not self.closed, 'registry_unresolved_or_closing')
            if body['action'] == 'status-registry-source':
                return self.source_status(body)
            if body['action'] == 'recover-failed-registry':
                return self.prelaunch_recovery.release(body)
            if body['action'] == 'activate-registry-source':
                return self.activate_source(body)
            if body['action'] == 'reserve-registry-directfetch':
                return self.reserve(body)
            need(self.active and self.deadline is not None and (self.clock() < self.deadline), 'registry_unknown_or_expired_hold_retained')
            if body['action'] == 'pulse-registry-directfetch':
                return self.pulse(body)
            return self.finish(body)
        except BaseException:
            if self.root.exists() and (not self.finished):
                self.s.restore_operator_block()
                self.closed = True
            raise
        finally:
            self.lock.release()

    def source_status(self, body):
        self.same()
        proof = self.whole_clear.collect(self.runtime, self.lease, self.config, 'registry-source-readonly', fenced=self.s._operator_maintenance)
        self.whole_clear(proof, self.config, self.runtime.manager._now(), fenced=self.s._operator_maintenance, baseline=self.live_baseline if self.active else None)
        with self.s._lock:
            gate = self.operator.c_arm_gate
            need(not gate.closed and (not gate.closing) and all((getattr(gate, k) == 0 for k in ('public_inflight', 'private_inflight', 'tick_inflight', 'pulse_inflight'))), 'current_source_shared_gate_inflight')
        return {'schema': 'registry-R26-source-current-status/v1', 'operation': OPERATION, 'request_nonce': body['request_nonce'], 'source118': self.config['PC_source_pins'], 'manager_pid': __import__('os').getpid(), 'current': proof, 'observed_at': self.runtime.manager._now(), 'models_started': 0}

    def activate_source(self, body):
        return self.prelaunch_recovery.release(body)

    def reserve(self, body):
        duration = body['duration_seconds']
        need(type(duration) is int and 1 <= duration <= 1800, 'strict_bounded_parent_duration_no_new1800')
        need(not self.active and (not self.root.exists()), 'registry_new_once_not_old_bf84')
        need(not self.operator.negative_cpu_release.pending, 'actual_new_epoch_qualification_activation_required')
        self.entry_ready()
        self.epoch = self.current_epoch()
        self.live_baseline = None
        n = self.negative()
        need(n['state'] == 'NEGATIVE_RELEASED' and n['CPU_success'] is False and (n['historical_only'] is True) and (n['requires_caller_fresh_current_idle'] is True), 'registry_real_typed_negative_release_required')
        before = self.current('registry-before-new-grant', fenced=False)
        with self.s._lock:
            self.counters_locked()
            need(not self.s._operator_maintenance, 'registry_original_negative_fence_not_released')
            self.root.mkdir(mode=448)
            os.chmod(self.root, 448)
            self.deadline = self.clock() + duration
            self.budget = dict(BUDGET, runtime_seconds=duration)
            exclusive(self.root / 'intent.json', {'schema': 'registry-new-CPU-once-intent/v1', 'operation': OPERATION, 'request': body, 'source_release_sha256': APPROVED_RELEASE, 'budget': self.budget, 'deadline_monotonic': self.deadline, 'duration_seconds': duration, 'negative_original_sha256': n['receipt_sha256'], 'before_sha256': sha(encode(before)), 'issued_at': self.runtime.manager._now(), 'automatic_retry': False, 'old_bf84_replayed': False})
            self.s.begin_operator_maintenance()
        with self.facade._lifecycle_lock:
            after = self.current('registry-new-grant-held', fenced=True)
        with self.s._lock:
            self.counters_locked()
            self.s.continue_operator_maintenance()
            need(self.clock() < self.deadline, 'registry_grant_preparation_deadline')
            self.reserved = after
            exclusive(self.root / 'reserved.json', {'operation': OPERATION, 'source_release_sha256': APPROVED_RELEASE, 'budget': self.budget, 'deadline_monotonic': self.deadline, 'before': before, 'after': after, 'observed_at': self.runtime.manager._now()})
            self.active = True
        return {'schema': 'registry-new-CPU-reserved/v1', 'operation': OPERATION, 'source_release_sha256': APPROVED_RELEASE, 'budget': self.budget, 'clear_reservation_sha256': sha(encode(after)), 'observed_at': self.runtime.manager._now()}

    def pulse(self, body):
        proof = self.current('registry-pulse-current-baseline', fenced=True)
        source = self.collector.source_and_lease()
        with self.s._lock:
            self.counters_locked()
            self.s.continue_operator_maintenance()
            self.same()
            need(self.clock() < self.deadline, 'registry_pulse_deadline')
            self.ordinal += 1
            value = {'schema': 'sole-Manager-private-CPU-reservation-pulse/v1', 'operation': OPERATION, 'source_release_sha256': APPROVED_RELEASE, 'config_sha256': self.config['_config_sha256'], 'ordinal': self.ordinal, 'request_nonce': body['request_nonce'], 'manager_epoch_sha256': sha(encode(self.config['PC_source_pins'])), 'budget': self.budget, 'remaining_seconds': self.deadline - self.clock(), 'manager_source': source, 'clear_reservation_original': self.reserved, 'clear_reservation_sha256': sha(encode(self.reserved)), 'observed_at': self.runtime.manager._now()}
            exclusive(self.root / ('pulse-' + str(self.ordinal) + '.json'), value)
            return value

    def finish(self, body):
        terminal = self.terminal(SERVICE / 'fetch-qualified.json', historical=False)
        need(terminal['operation'] == OPERATION and terminal['source_release_sha256'] == APPROVED_RELEASE and (terminal['models_started'] == 0) and (terminal['image_imported'] is True) and (terminal['actual_retained_EXIT0'] is True), 'registry_actual_file_scope_terminal_not_quality')
        with self.facade._lifecycle_lock:
            current = self.current('registry-after-actual-terminal', fenced=True)
        with self.s._lock:
            self.counters_locked()
            self.s.continue_operator_maintenance()
            exclusive(self.root / 'terminal.json', terminal)
            completed = {'schema': 'registry-CPU-assets-finished/v1', 'operation': OPERATION, 'source_release_sha256': APPROVED_RELEASE, 'terminal_sha256': sha(encode(terminal)), 'current': current, 'image_imported': True, 'hardware_validated': False, 'models_started': 0, 'finished_at': self.runtime.manager._now()}
            exclusive(self.root / 'completed.json', completed)
            self.s.finish_operator_maintenance()
            try:
                exclusive(self.root / 'fence-finished.json', {'operation': OPERATION, 'completed_sha256': sha(encode(completed)), 'operator_maintenance_observed': False, 'finished_at': self.runtime.manager._now()})
            except BaseException:
                self.s.restore_operator_block()
                raise
            self.active = False
            self.finished = True
        return completed

    def finish_failed(self, body):
        need(self.active and self.deadline is not None and (not self.finished) and self.root.exists(), 'failed_finish_requires_matching_actual_current_reservation')
        terminal = self.failure_terminal()
        need(terminal['operation'] == OPERATION and terminal['source_release_sha256'] == APPROVED_RELEASE and (terminal['CPU_success'] is terminal['image_imported'] is False), 'failed_finish_current_source_terminal')
        rows = Originals(self.root).snapshot()
        expected = {'intent.json', 'reserved.json'} | {'pulse-' + str(k) + '.json' for k in range(1, self.ordinal + 1)}
        need(set(rows) == expected, 'failed_finish_original_once_no_foreign_or_partial')
        i, r = (strict(rows['intent.json']), strict(rows['reserved.json']))
        need(i['operation'] == r['operation'] == OPERATION and i['source_release_sha256'] == r['source_release_sha256'] == APPROVED_RELEASE and (i['deadline_monotonic'] == r['deadline_monotonic'] == self.deadline) and (r['after'] == self.reserved), 'failed_finish_original_deadline_reservation_unchanged')
        context = strict(__import__('base64').b64decode(terminal['context_original']['raw_b64'], validate=True))
        pulse = context['initial_pulse_original']
        raw = __import__('base64').b64decode(pulse['original_raw_b64'], validate=True)
        v = strict(raw)
        need(sha(raw) == pulse['original_sha256'] and v['clear_reservation_original'] == r['after'] and (v['clear_reservation_sha256'] == sha(encode(r['after']))) and (v['operation'] == OPERATION) and (v['source_release_sha256'] == APPROVED_RELEASE) and (v['config_sha256'] == self.config['_config_sha256']), 'failed_finish_bound_original_A_context_reservation')
        self.current_epoch()
        with self.facade._lifecycle_lock:
            proof = self.current('registry-failed-terminal-current-quiescent', fenced=True)
            with self.s._lock:
                self.counters_locked()
                self.s.continue_operator_maintenance()
                self.same()
                self.current_epoch()
                exclusive(self.root / 'failed-terminal.json', terminal)
                done = {'schema': 'registry-R26-failed-quiescent-completed/v1', 'operation': OPERATION, 'source_release_sha256': APPROVED_RELEASE, 'state': 'FAILED_REGISTRY_QUIESCENT', 'CPU_success': False, 'image_imported': False, 'models_started': 0, 'terminal_sha256': sha(encode(terminal)), 'original_deadline_monotonic': self.deadline, 'work_deadline_extended': False, 'current': proof, 'observed_at': self.runtime.manager._now()}
                exclusive(self.root / 'failed-completed.json', done)
                try:
                    self.s.finish_operator_maintenance()
                    exclusive(self.root / 'failed-fence-released.json', {'operation': OPERATION, 'completed_sha256': sha(encode(done)), 'operator_maintenance_observed': False, 'observed_at': self.runtime.manager._now()})
                except BaseException:
                    self.s.restore_operator_block()
                    raise
                self.active = False
                self.closed = False
                self.finished = True
        return done

    def close(self):
        need(self.lock.acquire(blocking=False), 'registry_command_alive_retain_original_runtime_lease')
        try:
            need(not self.active and (not self.closed) and (self.asset_stages.active is None) and (not self.asset_stages.closed) and (not self.asset_stages.legacy_pending), 'registry_unresolved_hold_retain_original_runtime_lease')
            self.closed = True
        finally:
            self.lock.release()
