# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed root-peer operator socket inside the existing sole-runtime, disabled by default."""
from __future__ import annotations
import os, socket, stat, struct, threading, time
from pathlib import Path
from .common import need, Refused, strict, protected_read, encode, sha, metadata, exclusive, fresh
from .collector import Collector, unwrap, history_and_work, validate_before, validate_clear, PROFILE, OWNER, GEN, NODES
CONFIG = Path('/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json')
ROOT = Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d')
SOCKET = ROOT / 'operator.sock'
APPROVED_ACTIVATION_REVIEW_SHA256 = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
OLD_OPERATION = 'e56c2e2bf9de0ec3ceddbf28deed9afd'
NEW_OPERATION = '17d8f5ea0cc8db181c5b341f6ffb38ce'
PERMIT = Path('/etc/dgx-home-ai/b-owner-clock-continuation-r25-r1.json')
APPROVED_STOP0_CONTINUATION_REVIEW_SHA256 = '9065dd694133e3ba1a0cd4fe562c1b307f1f66794a8f7828ec8ff5509efb2f00'
OLD_FILES = {'intent.json': {'sha256': 'b5883a4595db24ddff63705dc9052243bc7cb676ae1e3b43af7c6a52a3297d96', 'stat': [2096, 42203, 448, 999, 989, 33152, 1, 1791866668430193649, 1791866668430193649]}, 'failed.json': {'sha256': '6f7a79c37e91a7846f56d2ed2d4fd53be7e3949fdccbdd4ffc5df2b647558246', 'stat': [2096, 42204, 161, 999, 989, 33152, 1, 1791866668434193650, 1791866668434193650]}}

def _read_9342_stop0():
    from .common import HeldParent, directory_identity
    old = ROOT / OLD_OPERATION
    with HeldParent(ROOT / 'C-parent-acceptance.json', legacy=True) as chain:
        before = os.stat(OLD_OPERATION, dir_fd=chain.parent_fd, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode) and (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) == (999, 989, 448), 'old_private_directory')
        fd = os.open(OLD_OPERATION, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        try:
            need(metadata(before) == metadata(os.fstat(fd)), 'old_directory_changed_at_open')
            need(sorted(os.listdir(fd)) == ['failed.json', 'intent.json'], 'old_stop0_exact_two_entries')
            rows = {}
            for name, pin in OLD_FILES.items():
                leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    s = os.fstat(leaf)
                    need(metadata(s) == pin['stat'] and stat.S_ISREG(s.st_mode), 'old_file_fullF9')
                    raw = os.pread(leaf, s.st_size + 1, 0)
                    need(len(raw) == s.st_size and sha(raw) == pin['sha256'] and (metadata(s) == metadata(os.fstat(leaf)) == metadata(os.stat(name, dir_fd=fd, follow_symlinks=False))), 'old_stop0_raw_identity')
                    rows[name] = {'raw_utf8': raw.decode(), 'sha256': sha(raw), 'stat': metadata(s)}
                finally:
                    os.close(leaf)
            need(metadata(before) == metadata(os.fstat(fd)) == metadata(os.stat(OLD_OPERATION, dir_fd=chain.parent_fd, follow_symlinks=False)), 'old_directory_changed_during_read')
            chain.recheck()
            i = strict(rows['intent.json']['raw_utf8'])
            f = strict(rows['failed.json']['raw_utf8'])
            need((i['operation'], i['profile'], i['owner'], i['generation'], i['actor']) == (OLD_OPERATION, PROFILE, OWNER, GEN, 'root-peer:0') and i['automatic_retry'] is False, 'old_original_owner_intent')
            need(f == {'automatic_retry': False, 'error_type': 'Refused', 'hold_release_not_inferred': True, 'observed_at': 1791866668.435745, 'reason': 'bounded_existing_transport_required'}, 'old_failure_before_stop_exact')
            return {'directory_stat': metadata(before), 'files': rows, 'old_operation': OLD_OPERATION, 'stop_calls': 0, 'release_calls': 0}
        finally:
            os.close(fd)
PREVIOUS_OPERATION = '2eaf2fb56ffb4315307a3108df6f5e63'
PREVIOUS_FILES = {'intent.json': None, 'failed.json': None}
PREVIOUS_DIRECTORY_STAT = [2096, 42452, 4096, 999, 989, 16832, 2, 1791879065094035109, 1791879065094035109]

def read_old_stop0():
    first = _read_9342_stop0()
    from .common import HeldParent
    with HeldParent(ROOT / 'C-parent-acceptance.json', legacy=True) as chain:
        before = os.stat(PREVIOUS_OPERATION, dir_fd=chain.parent_fd, follow_symlinks=False)
        need(metadata(before) == PREVIOUS_DIRECTORY_STAT, 'previous_failed_directory_F9')
        fd = os.open(PREVIOUS_OPERATION, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        try:
            need(sorted(os.listdir(fd)) == ['failed.json', 'intent.json'] and metadata(os.fstat(fd)) == PREVIOUS_DIRECTORY_STAT, 'previous_stop0_exact_two')
            rows = {}
            for name, item in PREVIOUS_FILES.items():
                f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    st = os.fstat(f)
                    need(metadata(st) == item['stat'] and stat.S_ISREG(st.st_mode), 'previous_raw_F9')
                    raw = os.pread(f, st.st_size + 1, 0)
                    need(len(raw) == st.st_size and raw == item['raw_utf8'].encode() and (sha(raw) == item['sha256']) and (metadata(st) == metadata(os.fstat(f)) == metadata(os.stat(name, dir_fd=fd, follow_symlinks=False))), 'previous_stop0_raw_changed')
                    rows[name] = {'raw_utf8': raw.decode(), 'sha256': sha(raw), 'stat': metadata(st)}
                finally:
                    os.close(f)
            need(metadata(os.fstat(fd)) == metadata(os.stat(PREVIOUS_OPERATION, dir_fd=chain.parent_fd, follow_symlinks=False)) == PREVIOUS_DIRECTORY_STAT, 'previous_directory_changed')
        finally:
            os.close(fd)
    intent = strict(rows['intent.json']['raw_utf8'])
    failure = strict(rows['failed.json']['raw_utf8'])
    need((intent['operation'], intent['old_operation'], intent['owner'], intent['profile'], intent['generation'], intent['actor']) == (PREVIOUS_OPERATION, OLD_OPERATION, OWNER, PROFILE, GEN, 'root-peer:0') and intent['automatic_retry'] is False, 'previous_original_owner_intent')
    need(failure == strict(PREVIOUS_FILES['failed.json']['raw_utf8']) and failure['reason'] == 'fresh_original_timestamp' and (failure['automatic_retry'] is False) and (failure['hold_release_not_inferred'] is True), 'previous_failed_before_stop')
    return {'schema': 'B-two-stop0-failed-originals/v1', 'old_operation': OLD_OPERATION, 'previous_operation': PREVIOUS_OPERATION, 'original_9342': first, 'previous_ce425': {'directory_stat': PREVIOUS_DIRECTORY_STAT, 'files': rows}, 'stop_calls': 0, 'release_calls': 0}

def validate_permit(c, raw, old):
    p = strict(raw)
    need(set(p) == {'schema', 'old_operation', 'new_once', 'owner', 'profile', 'generation', 'source_review_sha256', 'new_source_sha256', 'old_originals_sha256', 'one_root_peer_request', 'automatic_retry', 'operation_max_seconds', 'snapshot_percall_seconds', 'existing_sticky_fence_preserved', 'historical_foreign_cause_proven'}, 'exact_stop0_permit')
    need(APPROVED_STOP0_CONTINUATION_REVIEW_SHA256 is not None and p['source_review_sha256'] == APPROVED_STOP0_CONTINUATION_REVIEW_SHA256 == c['review_sha256'], 'continuation_review_pending')
    need((p['schema'], p['old_operation'], p['new_once'], p['owner'], p['profile'], p['generation']) == ('B-original-owner-stop0-continuation-permit/v1', OLD_OPERATION, NEW_OPERATION, OWNER, PROFILE, GEN) and type(p['generation']) is int, 'same_owner_new_nonce')
    need(p['one_root_peer_request'] is True and p['automatic_retry'] is False and (type(p['operation_max_seconds']) is int) and (p['operation_max_seconds'] == 300) and (type(p['snapshot_percall_seconds']) is int) and (p['snapshot_percall_seconds'] == 20) and (p['existing_sticky_fence_preserved'] is True) and (p['historical_foreign_cause_proven'] is False), 'finite_continuation_permit')
    need(p['new_source_sha256'] == sha(encode(c['PC_source_pins'])) and p['old_originals_sha256'] == sha(encode(old)), 'permit_source_and_old_full_originals')
    need(sha(raw) == c['continuation_permit_sha256'], 'Root_permit_config_bound')
    return p

def read_run_original(run, name):
    from .common import HeldParent, directory_identity
    need(run == ROOT / NEW_OPERATION and name in ('completed', 'fence-finished', 'after_core_release', 'before_stop', 'stop-result', 'node-release-result', 'core-release-result'), 'fixed_new_run_original')
    with HeldParent(ROOT / 'C-parent-acceptance.json', legacy=True) as ancestor:
        fd = os.open(NEW_OPERATION, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ancestor.parent_fd)
        try:
            s = os.fstat(fd)
            ident = directory_identity(s)
            need((s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (999, 989, 448), 'private_success_run')
            leaf = os.open(name + '.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                a = os.fstat(leaf)
                need(stat.S_ISREG(a.st_mode) and (a.st_uid, a.st_gid, stat.S_IMODE(a.st_mode), a.st_nlink) == (999, 989, 384, 1) and (a.st_size <= 1048576), 'private_terminal_original')
                raw = os.pread(leaf, a.st_size + 1, 0)
                need(len(raw) == a.st_size and metadata(a) == metadata(os.fstat(leaf)) == metadata(os.stat(name + '.json', dir_fd=fd, follow_symlinks=False)), 'terminal_original_changed')
                need(ident == directory_identity(os.fstat(fd)) == directory_identity(os.stat(NEW_OPERATION, dir_fd=ancestor.parent_fd, follow_symlinks=False)), 'terminal_directory_changed')
                return raw
            finally:
                os.close(leaf)
        finally:
            os.close(fd)

def validate_successful_reload(controller):
    c = historical_config()
    old = controller.old_original
    values = {n: strict(read_run_original(controller.run, n)) for n in ('completed', 'fence-finished', 'after_core_release', 'before_stop', 'stop-result', 'node-release-result', 'core-release-result')}
    result = values['completed']
    marker = values['fence-finished']
    final = values['after_core_release']
    before = values['before_stop']
    need(set(result) == {'schema', 'old_operation', 'old_originals_sha256', 'operation', 'owner', 'generation', 'actor', 'completed_at', 'historical_foreign_cause_proven', 'models_started', 'history9_preserved'}, 'exact_new_completed')
    need(result['schema'] == 'B-original-owner-stop0-continuation-completed/v1' and (result['operation'], result['old_operation'], result['owner'], result['generation'], result['actor']) == (NEW_OPERATION, OLD_OPERATION, OWNER, GEN, 'root-peer:0') and (type(result['generation']) is int) and (result['old_originals_sha256'] == sha(encode(old))) and (result['historical_foreign_cause_proven'] is False) and (type(result['models_started']) is int) and (result['models_started'] == 0) and (result['history9_preserved'] is True), 'typed_new_completed')
    need(set(marker) == {'schema', 'operation', 'old_operation', 'completed_sha256', 'after_core_release_sha256', 'old_originals_sha256', 'finished_at', 'historical_foreign_cause_proven', 'automatic_retry'} and marker['schema'] == 'B-stop0-fence-finished/v1' and (marker['operation'] == NEW_OPERATION) and (marker['old_operation'] == OLD_OPERATION) and (marker['completed_sha256'] == sha(encode(result))) and (marker['after_core_release_sha256'] == sha(encode(final))) and (marker['old_originals_sha256'] == sha(encode(old))) and (marker['historical_foreign_cause_proven'] is False) and (marker['automatic_retry'] is False), 'actual_finish_marker_bound')
    need(type(marker['finished_at']) in (float, int) and type(result['completed_at']) in (float, int) and (marker['finished_at'] >= result['completed_at']), 'finish_after_completed')
    need(set(final['nodes']) == set(NODES) == set(c['node_source_pins']) and all((len(c['node_source_pins'][n]) == 9 for n in NODES)), 'historical_exact_both_AB9')
    validate_clear(final, before, c, result['completed_at'])
    need(final['core_profile']['state'] == 'STOPPED' and final['core_profile']['owner'] is None and (final['core_profile']['generation'] == GEN), 'historical_final_Core_stopped')
    for row in final['core_nodes']:
        if row['node'] in NODES:
            need(row['hold_profile'] is None and row['hold_owner'] is None and (row['hold_generation'] is None) and (row['quarantined'] is False), 'historical_final_AB_noholds')
    need(final['rows']['active_requests'] == final['rows']['active_jobs'] == [] and final['rows']['historical_terminal_uncertain_count'] == 9 and (final['rows']['historical_terminal_uncertain_sha256'] == c['historical_terminal_uncertain_sha256']), 'historical_final_work_history9')
    need(set(final['PC_source_files']) == set(c['PC_source_pins']) and all((final['PC_source_files'][p]['sha256'] == h for p, h in c['PC_source_pins'].items())), 'historical_complete_PC_epoch')
    for node, item in final['nodes'].items():
        snap = item['reply']['snapshot']
        need(set(snap['sources']) == set(c['node_source_pins'][node]), 'historical_full_AB9')
        for p, h in c['node_source_pins'][node].items():
            entry = snap['sources'][p]
            need(entry['sha256'] == h and len(entry['stat']) == 9 and (entry['stat'][3] == 0) and (entry['stat'][6] == 1) and (not entry['stat'][5] & 18), 'historical_ABsource_Root_binding')
    f = controller.facade
    need(f._positive_manager_stop(values['stop-result'], PROFILE, GEN) and f._positive_node_release(values['node-release-result'], PROFILE, f.profiles[PROFILE], GEN) and f._positive_core_release(values['core-release-result'], PROFILE, f.profiles[PROFILE], GEN), 'all_historical_positive_stop_releases')
    return values

def load_config():
    try:
        raw, _ = protected_read(CONFIG)
    except FileNotFoundError:
        return None
    c = strict(raw)
    need(set(c) == {'schema', 'enabled', 'operation', 'review_sha256', 'lease_dev_inode', 'PC_source_pins', 'node_source_pins', 'container_ids', 'expected_model_id', 'image', 'historical_terminal_uncertain_sha256', 'max_age_seconds', 'C_actual_parent_acceptance_sha256', 'reason', 'continuation_permit_sha256'}, 'exact_operator_config')
    need(c['schema'] == 'B-original-owner-stop0-continuation-R25/v1' and type(c['enabled']) is bool, 'operator_schema')
    if not c['enabled']:
        return None
    need(APPROVED_ACTIVATION_REVIEW_SHA256 is not None and c['review_sha256'] == APPROVED_ACTIVATION_REVIEW_SHA256, 'activation_revision_pending')
    import re
    need(c['operation'] == NEW_OPERATION, 'fixed_once_operation')
    need(type(c['max_age_seconds']) in (int, float) and 0 < c['max_age_seconds'] <= 30, 'fresh_age_cap')
    need(c['expected_model_id'] == 'GLM-5.3-Flash-EXL3' and c['image'] == 'sha256:9b00719301e859f7b790b5c4d80ab1e49ef64bef63d3e7af2f3829cfc32cfee1', 'fixed_model_image')
    need(set(c['container_ids']) == set(NODES) and set(c['node_source_pins']) == set(NODES), 'whole_AB')
    need(c['reason'] == 'original owner gen10 maintenance stop; historical foreign cause unknown', 'fixed_reason')
    acceptance = ROOT / 'C-parent-acceptance.json'
    body, _ = protected_read(acceptance)
    need(sha(body) == c['C_actual_parent_acceptance_sha256'], 'C_actual_completion_bound')
    d = strict(body)
    need(d.get('C_source_repair_accepted') is True and d.get('Root_actual_process_exit0') is True and (d.get('actual_unarmed_CLEAR_GPUempty') is True), 'C_actual_required')
    old = read_old_stop0()
    permit_raw, _ = protected_read(PERMIT)
    validate_permit(historical_config(), permit_raw, old)
    oldpins = historical_config()['PC_source_pins']
    need(set(c['PC_source_pins']) == set(oldpins) and {p for p in oldpins if oldpins[p] != c['PC_source_pins'][p]} == set(CPU_CHANGED_PATHS), 'exact_CPU_and_samples_new118')
    c['_config_sha256'] = sha(raw)
    return c

class Controller:

    def __init__(self, runtime, lease, config):
        self.runtime = runtime
        self.lease = lease
        self.config = config
        self.lock = threading.Lock()
        self.facade = unwrap(runtime.facade)
        self.scheduler = runtime.server.scheduler
        need(self.facade.manager is runtime.manager and self.facade.adapter is runtime.adapter and (self.facade.service_owner == OWNER), 'same_existing_runtime')
        self.collector = Collector(runtime, lease, config)
        self.run = ROOT / config['operation']
        self.listener = None
        self.thread = None
        self.done = threading.Event()
        s = ROOT.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 999 and (stat.S_IMODE(s.st_mode) == 448), 'private_operator_root_required')
        self.cpu_bridge = None
        self.c_arm_gate = None
        self.old_original = read_old_stop0()
        if not self.run.exists():
            self.scheduler.restore_operator_block()
        else:
            s = self.run.lstat()
            need(stat.S_ISDIR(s.st_mode) and (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (999, 989, 448), 'private_existing_run')
            completed = (self.run / 'completed.json').exists()
            failed = (self.run / 'failed.json').exists()
            need(not (completed and failed), 'contradictory_run_terminal')
            if completed:
                validate_successful_reload(self)
            else:
                self.scheduler.restore_operator_block()

    def archive(self, name, value):
        return exclusive(self.run / (name + '.json'), value)

    def reload(self):
        c = load_config()
        need(c is not None and c == self.config, 'root_operator_configuration_changed')

    def command(self, body, peer_uid):
        need(peer_uid == 0, 'Root_operator_peer_required')
        need(body == {'action': 'continue-original-owner-stop0', 'old_operation': OLD_OPERATION, 'operation': NEW_OPERATION}, 'fixed_operator_request')
        need(self.lock.acquire(blocking=False), 'operator_command_inflight')
        began = False
        created = False
        try:
            self.reload()
            need(read_old_stop0() == self.old_original, 'old_stop0_changed_before_new_attempt')
            need(not self.run.exists(), 'once_attempt_already_exists_no_replay')
            self.run.mkdir(mode=448)
            created = True
            self.archive('intent', {'schema': 'B-owner-stop0-continuation-once-intent/v1', 'old_operation': OLD_OPERATION, 'old_originals_sha256': sha(encode(self.old_original)), 'operation': self.config['operation'], 'actor': 'root-peer:0', 'owner': OWNER, 'profile': PROFILE, 'generation': GEN, 'issued_at': self.runtime.manager._now(), 'source_review_sha256': self.config['review_sha256'], 'configuration_sha256': self.config['_config_sha256'], 'automatic_retry': False, 'historical_foreign_cause_proven': False})
            self.scheduler.continue_operator_maintenance()
            began = True
            with self.facade._lifecycle_lock:
                deadline = time.monotonic() + 300

                def room(seconds):
                    need(time.monotonic() + seconds <= deadline, 'absolute_operation_budget')
                room(90)
                before = self.collector.collect('before_stop')
                self.archive('before_stop', before)
                validate_before(before, self.config, self.runtime.manager._now())
                room(90)
                late = self.collector.collect('late_before_stop')
                self.archive('late_before_stop', late)
                validate_before(late, self.config, self.runtime.manager._now())
                need(late['rows']['requests'] == before['rows']['requests'], 'history_changed_before_stop')
                room(90)
                self.archive('stop-intent', {'generation': GEN, 'owner': OWNER, 'profile': PROFILE, 'observed_at': self.runtime.manager._now()})
                result = self.runtime.manager.stop_profile(PROFILE, owner=OWNER, expected_generation=GEN, actor='root-peer:0')
                self.archive('stop-result', result)
                need(self.facade._positive_manager_stop(result, PROFILE, GEN), 'stop_unconfirmed_holds_retained')
                room(70)
                self.archive('node-release-intent', {'generation': GEN, 'owner': OWNER, 'observed_at': self.runtime.manager._now()})
                release = self.runtime.adapter.release(PROFILE, nodes=list(NODES), generation=GEN)
                self.archive('node-release-result', release)
                need(self.facade._positive_node_release(release, PROFILE, self.facade.profiles[PROFILE], GEN), 'node_release_unconfirmed_core_hold_retained')
                clear = None
                poll_deadline = min(deadline, time.monotonic() + 35)
                for index in range(3):
                    need(time.monotonic() < poll_deadline, 'guard_CLEAR_deadline')
                    value = self.collector.collect('after_node_release', engine=False)
                    self.archive('clear-poll-' + str(index), value)
                    try:
                        validate_clear(value, before, self.config, self.runtime.manager._now())
                    except Refused as exc:
                        if str(exc) != 'guard_positive_CLEAR_pending':
                            raise
                        if index == 2:
                            raise
                        time.sleep(min(2, max(0, poll_deadline - time.monotonic())))
                    else:
                        clear = value
                        break
                need(clear is not None, 'positive_guard_CLEAR_required')
                room(50)
                self.archive('core-release-intent', {'generation': GEN, 'owner': OWNER, 'reason': self.config['reason'], 'observed_at': self.runtime.manager._now()})
                self.runtime.control_store.audit('operator_owner_recovery_release', actor='root-peer:0', profile=PROFILE, generation=GEN, reason=self.config['reason'], detail='operation=' + self.config['operation'])
                core = self.runtime.manager.release_profile(PROFILE, owner=OWNER, generation=GEN)
                self.archive('core-release-result', core)
                need(self.facade._positive_core_release(core, PROFILE, self.facade.profiles[PROFILE], GEN), 'core_release_unconfirmed')
                final = self.collector.collect('after_core_release', engine=False)
                self.archive('after_core_release', final)
                validate_clear(final, before, self.config, self.runtime.manager._now())
                need(final['core_profile']['state'] == 'STOPPED' and final['core_profile']['owner'] is None, 'final_core_stopped_released')
                for row in final['core_nodes']:
                    if row['node'] in NODES:
                        need(row['hold_profile'] is None and row['hold_owner'] is None and (row['hold_generation'] is None) and (row['quarantined'] is False), 'final_noholds')
                result = {'schema': 'B-original-owner-stop0-continuation-completed/v1', 'old_operation': OLD_OPERATION, 'old_originals_sha256': sha(encode(self.old_original)), 'operation': self.config['operation'], 'owner': OWNER, 'generation': GEN, 'actor': 'root-peer:0', 'completed_at': self.runtime.manager._now(), 'historical_foreign_cause_proven': False, 'models_started': 0, 'history9_preserved': True}
                need(read_old_stop0() == self.old_original, 'old_failed_history_changed')
                self.archive('completed', result)
                self.scheduler.finish_operator_maintenance()
                self.archive('fence-finished', {'schema': 'B-stop0-fence-finished/v1', 'operation': NEW_OPERATION, 'old_operation': OLD_OPERATION, 'completed_sha256': sha(encode(result)), 'after_core_release_sha256': sha(encode(final)), 'old_originals_sha256': sha(encode(self.old_original)), 'finished_at': self.runtime.manager._now(), 'historical_foreign_cause_proven': False, 'automatic_retry': False})
                return result
        except BaseException as exc:
            if created and (not (self.run / 'failed.json').exists()):
                self.archive('failed', {'error_type': type(exc).__name__, 'reason': str(exc)[:160], 'observed_at': self.runtime.manager._now(), 'automatic_retry': False, 'hold_release_not_inferred': True})
            if created:
                self.scheduler.restore_operator_block()
            raise
        finally:
            self.runtime.control_store.close_thread_connection()
            self.runtime.gateway_store.close_thread_connection()
            self.lock.release()

    def start(self):
        need(hasattr(socket, 'SO_PEERCRED'), 'Linux_peercred_required')
        need(not SOCKET.exists() and (not SOCKET.is_symlink()), 'operator_socket_exists_refuse')
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(SOCKET))
        os.chmod(SOCKET, 384)
        listener.listen(1)
        listener.settimeout(0.5)
        self.listener = listener
        self.thread = threading.Thread(target=self.serve, name='B-original-owner-operator', daemon=False)
        self.thread.start()

    def serve(self):
        try:
            while not self.done.is_set():
                try:
                    conn, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self.done.is_set():
                        break
                    raise
                with conn:
                    conn.settimeout(5)
                    try:
                        _pid, uid, _gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        need(uid == 0, 'Root_operator_peer_required')
                        raw = bytearray()
                        while len(raw) <= 4096:
                            chunk = conn.recv(4097 - len(raw))
                            need(chunk, 'operator_EOF')
                            raw.extend(chunk)
                            if b'\n' in raw:
                                break
                        need(len(raw) <= 4096 and raw.endswith(b'\n') and (raw.count(b'\n') == 1), 'one_bounded_request')
                        body = strict(raw)
                        if body.get('action') in C_ARM_ACTIONS:
                            need(self.c_arm_gate is not None, 'C_ARM_not_attached')
                            response = {'ok': True, 'result': self.c_arm_gate.command(body, uid)}
                        elif self.c_arm_gate is not None and self.c_arm_gate.closed:
                            raise Refused('C_ARM_sticky_no_other_private_mutation')
                        elif body.get('action') in NEGATIVE_ACTIONS:
                            response = dispatch_negative(self.negative_cpu_release, body, uid)
                        elif body.get('action') in REGISTRY_ACTIONS:
                            _v = self.registry_grant.command(body, uid)
                            response = {'ok': True, 'pulse' if body['action'] in ('reserve-registry-directfetch', 'pulse-registry-directfetch', 'reserve-asset-stage', 'pulse-asset-stage') else 'result': _v}
                        elif body.get('action') in CPU_ACTIONS:
                            need(self.cpu_bridge is not None, 'private_CPU_not_attached')
                            response = dispatch_cpu(self.cpu_bridge, body, uid)
                        else:
                            response = {'ok': True, 'result': self.command(body, uid)}
                        outgoing = encode(response)
                        need(len(outgoing) <= 1048576, 'bounded_CPU_reply_1MiB')
                        conn.sendall(outgoing)
                    except Exception as exc:
                        try:
                            conn.sendall(encode(_registry_callbacks().failure_reply(body, exc) if body.get('action') in REGISTRY_ACTIONS else {'ok': False, 'error': type(exc).__name__, 'reason': str(exc)[:160]}))
                        except OSError:
                            pass
        finally:
            self.runtime.control_store.close_thread_connection()
            self.runtime.gateway_store.close_thread_connection()

    def _registry_original_close(self):
        failure = None
        cleanup_errors = []
        try:
            if self.c_arm_gate is not None:
                self.c_arm_gate.close()
            if self.cpu_bridge is not None:
                self.cpu_bridge.close()
        except BaseException as exc:
            failure = exc
        finally:
            self.done.set()
            try:
                if self.listener is not None:
                    self.listener.close()
            except BaseException as exc:
                cleanup_errors.append(exc)
            try:
                if self.thread is not None:
                    self.thread.join(timeout=310)
                    need(not self.thread.is_alive(), 'operator_still_alive_keep_stores_lease')
            except BaseException as exc:
                cleanup_errors.append(exc)
        if failure is not None:
            if cleanup_errors:
                raise failure from cleanup_errors[0]
            raise failure
        if cleanup_errors:
            raise cleanup_errors[0]

    def close(self):
        error = None
        try:
            self.registry_grant.close() if hasattr(self, 'registry_grant') else None
        except BaseException as caught:
            error = caught
        finally:
            self._registry_original_close()
        if error is not None:
            raise error

def attach_owner_recovery(runtime, lease):
    _startup_step = 'load_config'
    c = None
    try:
        c = load_config()
        if c is None:
            return runtime
        need(not hasattr(runtime, 'owner_recovery'), 'one_controller_only')
        _startup_step = 'Controller'
        controller = Controller(runtime, lease, c)
        _startup_step = 'Bridge'
        controller.cpu_bridge = attach_cpu_bridge(runtime, lease, c)
        _startup_step = 'HistoricalNegative'
        controller.negative_cpu_release = _registry_callbacks().attach_history(runtime, lease, c, controller.cpu_bridge)
        original_route = runtime.server.route

        def route(method, *args, **kwargs):
            if method == 'POST':
                with runtime.server.scheduler.operator_public_call():
                    return original_route(method, *args, **kwargs)
            return original_route(method, *args, **kwargs)
        runtime.server.route = route
        runtime.owner_recovery = controller
        need(APPROVED_C_ARM_SOURCE_REVIEW is not None, 'C_ARM_source_revision_pending')
        _startup_step = 'CArmGate'
        controller.c_arm_gate = CArmGate(runtime, lease, controller)
        controller.c_arm_gate.install()
        _startup_step = 'RegistryGrant'
        _r = _registry_callbacks()
        controller.registry_grant = _r.attach_grant(runtime, lease, c, controller, _r.Grant)
        old_close = runtime.close

        def close():
            controller.close()
            return old_close()
        runtime.close = close
        _startup_step = 'private_listener'
        try:
            controller.start()
        except BaseException:
            controller.close()
            raise
        return runtime
    except BaseException as _startup_error:
        try:
            _record_startup_refusal(_startup_error, _startup_step, c)
        except BaseException as _diagnostic_error:
            try:
                os.write(2, encode({'reason_code': 'startup_diagnostic_write_failed', 'error_type': type(_diagnostic_error).__name__ if type(_diagnostic_error).__name__ in ('Refused', 'OSError', 'PermissionError', 'FileExistsError') else 'OtherException'}))
            except BaseException:
                pass
        raise
CPU_ROOT = Path('/opt/dgx-v4/hx/mimo-private-cpu-bridge-r25-r1')
CPU_ACTIONS = frozenset(('reserve-mimo-private-cpu', 'pulse-mimo-private-cpu', 'finish-mimo-private-cpu'))
CPU_CHANGED_PATHS = frozenset(('/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/wiring.py', '/opt/dgx-v4/hx/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/samples.py'))
HISTORICAL_CONFIG_SHA256 = 'be52a2b52546143527122497aba0eb81a8a7d49e7903a5d4618abfab35d5fa81'
APPROVED_CPU_HELPER_PINS = {'bridge.py': '2112805a70e783f887302cc383c09e1fe99e9077c04fb96a8dcf1da0cfe969fb', 'terminal_producer.py': '72a9c6089aef301d6ec225c1430ba918c3f9579659759aca92a98ebc4397e57e', 'plan.py': '52860a3f2bf8003669b54ecfdb71142802082856e8b55e0bcf1441185b3c67a2', 'private_config.py': '195656597017c459b009cc3d58a58e5131cc1b50deaa78daee969cccff852959', 'EXPECTED_DUMP.json': '10c1d4abf705284876465a43b59dc0c034cb80371b4a8a83bcae776a765c07f5'}

def historical_config():
    raw, _ = protected_read(CPU_ROOT / 'service/historical-config.json')
    need(sha(raw) == HISTORICAL_CONFIG_SHA256, 'actual_b003_historical_config')
    c = strict(raw)
    c['_config_sha256'] = sha(raw)
    return c

def dispatch_cpu(bridge, body, uid):
    raise Refused('bf84_consumed_no_cross_epoch_replay')

def attach_cpu_bridge(runtime, lease, c):
    import types, sys
    need(APPROVED_CPU_HELPER_PINS is not None, 'private_CPU_activation_pending')
    need(set(APPROVED_CPU_HELPER_PINS) == {'bridge.py', 'terminal_producer.py', 'plan.py', 'private_config.py', 'EXPECTED_DUMP.json'}, 'exact_CPU_helper_closure')
    modules = {}
    previous_aliases = {n: sys.modules.get(n) for n in ('plan', 'private_config')}
    for name, pin in APPROVED_CPU_HELPER_PINS.items():
        raw, _ = protected_read(CPU_ROOT / 'service' / name)
        need(sha(raw) == pin, 'CPU_helper_source_drift')
        if name.endswith('.py'):
            m = types.ModuleType('mimo_cpu_' + name[:-3])
            m.__file__ = str(CPU_ROOT / 'service' / name)
            modules[name] = m
            if name in ('plan.py', 'private_config.py'):
                sys.modules[name[:-3]] = m
    for name in ('private_config.py', 'plan.py', 'terminal_producer.py', 'bridge.py'):
        raw, _ = protected_read(CPU_ROOT / 'service' / name)
        need(sha(raw) == APPROVED_CPU_HELPER_PINS[name], 'CPU_helper_changed_before_exec')
        exec(compile(raw, modules[name].__file__, 'exec'), modules[name].__dict__)
    for n, old in previous_aliases.items():
        if old is None:
            sys.modules.pop(n, None)
        else:
            sys.modules[n] = old
    b = modules['bridge.py']
    b.positive_terminal = modules['terminal_producer.py'].positive_terminal
    b.APPROVED_SOLE_CONFIG_SHA = c['_config_sha256']
    bridge = b.Bridge(runtime, lease, c)
    bridge.OPERATION = b.OPERATION
    return bridge

def _c_fresh(stamp, now, seconds=300):
    need(type(stamp) in (int, float) and math.isfinite(stamp) and (0 <= now - stamp <= seconds), 'original_fresh_stamp')
APPROVED_C_ARM_SOURCE_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
C_ARM_ACTIONS = frozenset(('begin-c-arm', 'bind-c-arm-witness', 'finish-c-arm', 'status-c-arm'))
C_ARM_MIRRORS = Path('/opt/dgx-v4/hx/g8-c-new-arm-finite-r25-receipts')
C_ARM_SOURCE_CLOSURE = '590bf2dea906d4761a1e6f23ca283b082e50e5c2d4e9d18b1fbc5b121c9c5e61'
APPROVED_CPU_NEGATIVE_CONSUMER = '63212e73700f839877035de9e4fa01195f20a45e82b2c31926f0fec70544094b'
CPU_NEGATIVE_CONSUMER = Path('/opt/dgx-v4/hx/mimo-cpu-negative-startup-import-r25-r6-r1/negative_qualification.py')

def current_manager_identity():
    text = Path('/proc/self/stat').read_text()
    ticks = text.rsplit(') ', 1)[1].split()[19]
    inv = os.environ.get('INVOCATION_ID', '')
    need(__import__('re').fullmatch('[0-9a-f]{32}', inv) is not None, 'actual_original_service_invocation')
    return {'pid': os.getpid(), 'start_ticks': ticks, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': inv}

def negative_history(config, identity, now):
    return _registry_callbacks().current_negative(config, identity, now)

class CArmGate:

    def __init__(self, runtime, lease, operator):
        self.runtime = runtime
        self.lease = lease
        self.operator = operator
        self.s = runtime.server.scheduler
        self.lock = threading.RLock()
        self.closed = False
        self.closing = False
        self.phase = 'OPEN'
        self.doc = None
        self.root = None
        self.baseline = None
        self.public_inflight = 0
        self.private_inflight = 0
        self.tick_inflight = 0
        self.pulse_inflight = 0
        need(self.s.manager is runtime.manager and operator.runtime is runtime and (operator.lease is lease) and (runtime.c_firsttrial is runtime.server.c_firsttrial) and (runtime.c_firsttrial.lease is lease), 'same_runtime_Controller_scheduler_physical_lease')
        for path in ROOT.glob('c-arm-*'):
            st = path.lstat()
            need(stat.S_ISDIR(st.st_mode) and (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (999, 989, 448), 'protected_C_ARM_service_state')
            need((path / 'finished.json').exists() and (not (path / 'failed.json').exists()), 'C_ARM_pending_history_retains_service_lease')
        if os.path.lexists('/etc/dgx-home-ai/g8-c-firsttrial.json'):
            from G8_C_FIRSTTRIAL_CANDIDATE_R1 import permit as P
            d = P.load(P.HX)
            run = ROOT / ('c-arm-' + d.value['run_id'])
            if not (run / 'finished.json').exists():
                _legacy_C_startup(self.runtime, self.lease, self.operator, d)

    def same(self, doc):
        v = doc.value
        doc.check(now=self.runtime.manager._now())
        need(v['profile'] == 'image-turbo-c' and v['node'] == 'spark-c' and (v['owner'] == 'dgx-hx-service') and (self.baseline is not None) and (v['generation'] == self.baseline['Core_generations']['image-turbo-c'] + 1) and (v['source_closure_sha256'] == C_ARM_SOURCE_CLOSURE) and (v['manager_pid'] == os.getpid()), 'fixed_new_C_run2_original_manager')
        need(self.lease.held and self.lease._fd is not None, 'physical_lease_held')
        a = os.fstat(self.lease._fd)
        b = self.lease.path.lstat()
        need([a.st_dev, a.st_ino] == v['lease_dev_inode'] == [2096, 69257] and metadata(a) == metadata(b), 'original_same_physical_FD_named')

    def idle_locked(self):
        s = self.s
        need(not s._operator_maintenance, 'CPU_maintenance_not_finished')
        need(not (self.public_inflight or self.private_inflight or self.tick_inflight or self.pulse_inflight or s._operator_tick_inflight or s._operator_public_inflight or s._operator_creative_pulse_inflight or (s._creative is not None) or s._infos or any(s._queues.values()) or any(s._active.values()) or s._uncertain or s._ensuring or s._dispatch_checks or s._draining), 'same_lock_all_work_and_lifecycle_counters')

    def fresh_idle(self):
        callbacks = _registry_callbacks()
        proof = callbacks.collect_live_idle(self.runtime, self.lease, self.operator.config, 'C-ARM-current', fenced=False)
        verified = callbacks.validate_live_idle(proof, self.operator.config, self.runtime.manager._now(), fenced=False, baseline=self.baseline)
        need(all((verified[k] == self.baseline[k] for k in ('Core_generations', 'Node_records'))), 'whole_window_Core_and_AB_baseline_fixed')
        return proof

    def core_idle_locked(self, *, capture=False, finished=False):
        generations = {}
        for profile in ('qwen-a-c', 'image-turbo-c', 'glm-ab'):
            row = self.runtime.control_store.profile_view(profile)
            need(row['state'] == 'STOPPED' and row['owner'] is None and (type(row['generation']) is int) and (row['generation'] > 0), 'current_Core_idle_positive_generation')
            generations[profile] = row['generation']
        for row in self.runtime.control_store.nodes_view():
            need(row['hold_profile'] is row['hold_owner'] is row['hold_generation'] is None and row['quarantined'] is False, 'current_Core_nodes_unheld_unquarantined')
        if capture:
            return generations
        need(self.baseline is not None, 'fresh_shared_lock_baseline_required')
        expected = dict(self.baseline['Core_generations'])
        if finished:
            expected['image-turbo-c'] += 1
        need(generations == expected, 'whole_window_Core_generation_drift')

    def install(self):
        old = self.runtime.server.route
        gate = self

        def route(method, segments, query, identity, handler):
            private = segments == ['v1', 'maintenance', 'creative-firsttrial'] and method == 'POST'
            if method in ('GET', 'HEAD'):
                return old(method, segments, query, identity, handler)
            with gate.s._lock:
                if gate.closing or (gate.closed and (not private)):
                    from llm_gateway.errors import GatewayError
                    raise GatewayError('finite C ARM admission closed', code='C_ARM_admission_closed', http_status=503)
                registered_private = private and gate.closed
                if registered_private:
                    need(gate.phase in ('ARM_READY', 'TRIAL_INTENT', 'TRIAL_HELD'), 'C_ARM_not_live_no_model_start')
                    identity.require('models')
                    need(gate.doc is not None and identity.name == gate.doc.value['caller_owner'], 'original_authenticated_C_caller_not_Root_impersonation')
                    gate.private_inflight += 1
                else:
                    gate.public_inflight += 1
            try:
                if registered_private:
                    from llm_gateway.validation import parse_json_object
                    raw = handler._read_raw_body(limit=4096)
                    body = parse_json_object(raw, max_bytes=4096)
                    need(body['run_id'] == gate.doc.value['run_id'], 'fixed_C_run_body')
                    if body.get('action') == 'start':
                        gate.fresh_idle()
                        with gate.s._lock:
                            gate.core_idle_locked()
                            need(gate.phase == 'ARM_READY', 'single_C_start_after_ARM')
                            exclusive(gate.root / 'trial-intent.json', {'run_id': body['run_id'], 'key': body['key'], 'observed_at': gate.runtime.manager._now(), 'no_replay': True})
                            gate.phase = 'TRIAL_INTENT'
                    elif body.get('action') not in ('status', 'stop', 'cleanup', 'schema', 'submit', 'trace', 'result'):
                        raise Refused('fixed_private_C_actions')

                    class Buffered:

                        def _read_raw_body(self, *, limit):
                            need(len(raw) <= limit, 'same_original_body_limit')
                            return raw

                        def __getattr__(self, k):
                            return getattr(handler, k)
                    result = old(method, segments, query, identity, Buffered())
                    if body.get('action') == 'start':
                        with gate.s._lock:
                            gate.phase = 'TRIAL_HELD'
                    return result
                return old(method, segments, query, identity, handler)
            finally:
                with gate.s._lock:
                    if registered_private:
                        gate.private_inflight -= 1
                    else:
                        gate.public_inflight -= 1
                    gate.s._cv.notify_all()
        self.runtime.server.route = route
        tick = self.s.run_maintenance

        def maintenance():
            with self.s._lock:
                if self.closed:
                    return {'C_ARM_admission_closed': True}
                self.tick_inflight += 1
            try:
                return tick()
            finally:
                with self.s._lock:
                    self.tick_inflight -= 1
                    self.s._cv.notify_all()
        self.s.run_maintenance = maintenance
        pulse = self.s.creative_pulse
        if pulse is not None:

            def creative_pulse():
                with self.s._lock:
                    if self.closed:
                        return
                    self.pulse_inflight += 1
                try:
                    return pulse()
                finally:
                    with self.s._lock:
                        self.pulse_inflight -= 1
                        self.s._cv.notify_all()
            self.s.creative_pulse = creative_pulse

    def command(self, body, uid):
        need(APPROVED_C_ARM_SOURCE_REVIEW is not None, 'C_ARM_source_pending')
        need(type(uid) is int and uid == 0 and (type(body) is dict) and (set(body) == {'action', 'run_id', 'key'}) and (body['action'] in C_ARM_ACTIONS) and __import__('re').fullmatch('[0-9a-f]{32}', body['run_id']) and __import__('re').fullmatch('[0-9a-f]{32}', body['key']), 'fixed_Rootpeer_C_ARM_command')
        need(self.lock.acquire(blocking=False), 'C_ARM_private_inflight')
        try:
            need(not self.closing, 'C_ARM_shutdown_rejects_new_private_intent')
            if body['action'] == 'status-c-arm':
                return {'phase': self.phase, 'closed': self.closed, 'run_id': self.doc.value['run_id'] if self.doc is not None else None, 'permit_sha256': self.doc.sha256 if self.doc is not None else None, 'manager_pid': os.getpid(), 'source_review_sha256': APPROVED_C_ARM_SOURCE_REVIEW, 'observed_at': self.runtime.manager._now(), 'model_requests_issued_by_Root': 0}
            if body['action'] == 'begin-c-arm':
                from G8_C_FIRSTTRIAL_CANDIDATE_R1 import permit as P
                doc = P.load(P.HX)
                doc.check(now=self.runtime.manager._now(), starting=True)
                need(doc.value['run_id'] == body['run_id'] and self.doc is None, 'new_unbound_C_run_only')
                history = negative_history(self.operator.config, current_manager_identity(), self.runtime.manager._now())
                root = ROOT / ('c-arm-' + body['run_id'])
                need(not root.exists() and (not root.is_symlink()), 'new_C_ARM_once_namespace')
                with self.s._lock:
                    self.idle_locked()
                    core = self.core_idle_locked(capture=True)
                    need(self.runtime.c_firsttrial.document is None, 'original_C_controller_unbound')
                    self.closed = True
                    self.phase = 'BEGIN_INTENT'
                    self.doc = doc
                    self.root = root
                callbacks = _registry_callbacks()
                current = callbacks.collect_live_idle(self.runtime, self.lease, self.operator.config, 'C-ARM-before', fenced=False)
                baseline = callbacks.validate_live_idle(current, self.operator.config, self.runtime.manager._now(), fenced=False)
                need(baseline['Core_generations'] == core, 'shared_lock_Core_matches_genuine_Node_baseline')
                with self.s._lock:
                    self.idle_locked()
                    self.baseline = baseline
                    self.core_idle_locked()
                    self.same(doc)
                    root.mkdir(mode=448)
                    os.chmod(root, 448)
                    exclusive(root / 'begin-intent.json', {'body': body, 'permit_sha256': doc.sha256, 'CPU_negative_release_sha256': sha(encode(history)), 'current_whole_idle_sha256': sha(encode(current)), 'observed_at': self.runtime.manager._now(), 'no_replay': True})
                    self.phase = 'ARM_PENDING'
                result = {'phase': self.phase, 'run_id': body['run_id'], 'permit_sha256': doc.sha256, 'same_manager_pid': os.getpid(), 'source_review_sha256': APPROVED_C_ARM_SOURCE_REVIEW, 'C_ARM_admission_closed': True, 'CPU_operator_maintenance': False, 'GPU_model_start': 0}
                exclusive(root / (body['key'] + '.finished.json'), result)
                return result
            need(self.doc is not None and self.doc.value['run_id'] == body['run_id'], 'same_bound_C_run')
            self.same(self.doc)
            need(not (self.root / (body['key'] + '.finished.json')).exists(), 'C_ARM_command_key_no_replay')
            exclusive(self.root / (body['key'] + '.intent.json'), {'body': body, 'phase': self.phase, 'observed_at': self.runtime.manager._now(), 'no_replay': True})
            if body['action'] == 'bind-c-arm-witness':
                need(self.phase == 'ARM_PENDING' and self.closed, 'C_ARM_binding_phase')
                raw, st = protected_read(C_ARM_MIRRORS / (body['run_id'] + '.json'), limit=4194304)
                v = strict(raw)
                need(st[3] == 0 and st[4] == 989 and (st[5] == 33056), 'Root_origin_group989_readonly_mirror')
                validate_C_ARM_ready(v, self.doc)
                self.fresh_idle()
                with self.s._lock:
                    self.idle_locked()
                    self.core_idle_locked()
                    self.phase = 'ARM_READY'
                result = {'phase': self.phase, 'run_id': body['run_id'], 'Root_ready_raw_sha256': sha(raw), 'GPU_model_start': 0}
                exclusive(self.root / (body['key'] + '.finished.json'), result)
                return result
            need(body['action'] == 'finish-c-arm' and self.phase in ('TRIAL_INTENT', 'TRIAL_HELD'), 'C_ARM_finish_requires_trial_terminal_not_stop_response')
            c = self.runtime.c_firsttrial
            need(c.document is not None and c.document.sha256 == self.doc.sha256 and (c.admitted is False) and (c.stop_result is not None) and (c.stop_result.get('stopped') is c.stop_result.get('confirmed') is True) and (c.thread is None or not c.thread.is_alive()) and (c.samples is None or c.samples.fd is None), 'actual_C_cleanup_watchdog_samples_terminal')
            from G7_INTEGRATION_CANDIDATE_R2.durable import Ledger
            ledger = Ledger(c.root)
            try:
                need(ledger.view(body['run_id'])['phase'] == 'CLEANED_RELEASED', 'actual_C_core_and_scheduler_cleanup_ledger')
            finally:
                ledger.close()
            with self.s._lock:
                self.idle_locked()
                self.core_idle_locked(finished=True)
                row = self.runtime.control_store.profile_view('image-turbo-c')
                need(row['state'] == 'STOPPED' and row['owner'] is None and (row['generation'] == self.doc.value['generation']), 'same_current_C_released_core')
                result = {'phase': 'FINISHED', 'run_id': body['run_id'], 'C_ARM_admission_closed': False, 'model_quality_accepted': False}
                exclusive(self.root / (body['key'] + '.finished.json'), result)
                exclusive(self.root / 'finished.json', {'body': body, 'permit_sha256': self.doc.sha256, 'observed_at': self.runtime.manager._now(), 'C_cleanup_actual': True, 'model_quality_accepted': False})
                self.phase = 'FINISHED'
                self.closed = False
                self.s._cv.notify_all()
            return result
        except BaseException:
            raise
        finally:
            self.lock.release()

    def close(self):
        need(self.lock.acquire(blocking=False), 'C_ARM_Root_command_alive_retain_soleRuntime_stores_lease')
        try:
            with self.s._lock:
                need(not self.closed and self.private_inflight == self.public_inflight == self.tick_inflight == self.pulse_inflight == 0, 'C_ARM_closed_or_inflight_retain_soleRuntime_stores_lease')
                self.closing = True
        finally:
            self.lock.release()
import base64, math, re
C_LIVE_FIELDS = {'schema', 'observed_at', 'boot_id', 'run_id', 'generation', 'nonce', 'old_guard_pid', 'old_session_id', 'old_pid_absent', 'Guard_stop_calls', 'Guard_start_calls', 'stop_rc', 'start_rc', 'stop_stderr_b64', 'start_stderr_b64', 'unit_raw_b64', 'unit_raw_sha256', 'unit_observed_at', 'unit_cgroup_pids', 'proof_path', 'proof_raw_b64', 'proof_sha256', 'proof_F9', 'status_raw_b64', 'status_sha256', 'status_F9', 'state_raw_b64', 'state_sha256', 'state_F9', 'source19', 'source_receipt_sha256', 'old_proof_raw_sha256', 'old_proof_F9', 'node_record', 'root_origin_sha256'}

def _validate_C_live(v, doc, completed, current, *, now):
    need(set(v) == C_LIVE_FIELDS and v['schema'] == 'g8-C-newrun-live-Guard-source-handoff/v1', 'exact_post_normal_Guard_activation_fields')
    doc.check(now=now, starting=True)
    p = doc.value
    need(v['run_id'] == p['run_id'] == completed['run_id'] and v['generation'] == p['generation'] == completed['generation'] == 2 and (v['nonce'] == completed['nonce']), 'same_newrun_source_completed')
    _c_fresh(v['observed_at'], now, 10)
    _c_fresh(v['unit_observed_at'], now, 10)
    need(v['boot_id'] == current['boot_id'] and v['old_guard_pid'] == current['guard_pid'] == 1928162 and (v['old_session_id'] == current['session_id']) and (v['old_pid_absent'] is True) and (type(v['Guard_stop_calls']) is type(v['Guard_start_calls']) is int) and (v['Guard_stop_calls'] == v['Guard_start_calls'] == 1) and (type(v['stop_rc']) is type(v['start_rc']) is int) and (v['stop_rc'] == v['start_rc'] == 0) and (base64.b64decode(v['stop_stderr_b64'], validate=True) == base64.b64decode(v['start_stderr_b64'], validate=True) == b''), 'finite_normal_old_Guard_positive_exit_no_retry')
    uraw = base64.b64decode(v['unit_raw_b64'], validate=True)
    need(sha(uraw) == v['unit_raw_sha256'], 'actual_unit_raw_SHA')
    u = dict((line.split('=', 1) for line in uraw.decode().splitlines()))
    need(u['Id'] == 'dgx-v4-node-guard.service' and u['LoadState'] == 'loaded' and (u['ActiveState'] == 'active') and (u['SubState'] == 'running') and (u['NRestarts'] == '0') and (re.fullmatch('[0-9a-f]{32}', u['InvocationID']) is not None), 'same_original_unit_new_live_invocation')
    blobs = {}
    for name in ('proof', 'status', 'state'):
        raw = base64.b64decode(v[name + '_raw_b64'], validate=True)
        need(sha(raw) == v[name + '_sha256'], 'same_held_' + name + '_raw_SHA')
        st = v[name + '_F9']
        need(type(st) is list and len(st) == 9 and all((type(x) is int for x in st)) and (st[2] == len(raw)) and (st[3:7] == [0, 0, 33152, 1]), 'Root_held_' + name + '_F9')
        blobs[name] = strict(raw)
    proof, status, state = (blobs['proof'], blobs['status'], blobs['state'])
    pid = status['guard_pid']
    need(type(pid) is int and pid > 0 and (pid != v['old_guard_pid']) and (u['MainPID'] == u['ExecMainPID'] == str(pid)) and (v['unit_cgroup_pids'] == [pid]) and (proof['guard_pid'] == pid), 'new_owned_Guard_PID_not_filesystem_CAS_claim')
    _c_fresh(proof['observed_at'], now, 10)
    _c_fresh(status['observed_at'], now, 10)
    need(v['proof_path'] == '/var/lib/dgx-v4/node-runtime-guard/c-firsttrial-proof-' + p['run_id'] + '.json' and set(proof) == {'schema', 'permit_sha256', 'run_id', 'guard_pid', 'observed_at', 'session_id', 'policy'} and (proof['schema'] == 'g8-c-firsttrial-guard-proof/v1') and (proof['permit_sha256'] == doc.sha256) and (proof['run_id'] == p['run_id']) and (proof['policy'] == p['policy']) and (proof['session_id'] == state['session_id']) and (proof['session_id'] != v['old_session_id']), 'new_run_derived_actual_producer_witness_only')
    need(status['schema'] == 'dgx-v4-runtime-guard-v1' and status['node'] == 'spark-c' and (status['state'] == state['phase'] == 'IDLE_HOLD_RETAINED') and (status['reason_code'] == 'idle_db_clear') and all((status[k] is None for k in ('profile', 'owner', 'generation', 'container_id', 'image'))) and (state['schema'] == 'dgx-v4-runtime-guard-state-v1') and (state['arming_started_at'] is None) and (state['clear_authorized'] is True) and (state['tracked'] is state['terminal'] is None) and (state['retained_unknown'] is False) and (v['node_record'] == current['node_record']) and (state['last_record'] == {k: current['node_record'][k] for k in ('state', 'profile', 'owner', 'generation', 'container_id', 'updated_at', 'released_at')}), 'fresh_positive_newsession_unclaimed_CLEAR_no_ARM_trial_start')
    need(v['source19'] == completed['full_source19'] and len(v['source19']) == 19 and (v['source_receipt_sha256'] == completed['source_receipt_sha256'] == p['source_closure_sha256']) and (v['old_proof_raw_sha256'] == current['historical_proof']['sha256']) and (v['old_proof_F9'] == current['historical_proof']['stat9']) and (type(v['root_origin_sha256']) is str) and (re.fullmatch('[0-9a-f]{64}', v['root_origin_sha256']) is not None), 'actual_full19_source_originalproof_F9_preserved')
    return {'schema': 'g8-C-newrun-live-Guard-handoff-qualified/v1', 'run_id': p['run_id'], 'generation': 2, 'guard_pid': pid, 'session_id': proof['session_id'], 'source_live_observed': True, 'model_started': False, 'hardware_validated': False, 'threshold_calibration_required': True, 'MCP_quality_accepted': False}
C_CURRENT_SOURCE_ANCHOR = {'source19': {'/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/TURBO_T2I_API_CANDIDATE.json': {'sha256': 'd2705c1172ced106bb8161634e57adba9282736519f47b11c6dd024ba93acd6a', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/__init__.py': {'sha256': 'ad98a64b6c478223bdbb1adf4a1310e86df03d6d7bb8e1c60597393a8a5ccd49', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/contract.py': {'sha256': 'e7ed86132dbf05f02ea630ed33afd4e63f13b374fd7c12be39f403602940b749', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/graph_schema.py': {'sha256': '204fd365e6ff4d542b24545d245dcf821e721872acd8fea4b4dc719ed67218c3', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/guard_overlay.py': {'sha256': '53d8da9104da09b60c1d0bb24f92cae35b66e0931c0e4a95c8f0f176fdb53d40', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/http_loopback.py': {'sha256': 'e52eab7a828bce6f2d427e78cffa247159a38267c91dec0f38e43cf1b020d2fc', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/input_receipt.py': {'sha256': '7ff2a1f73edc6b623c61d28d2499ab75637a37a9adc79f2441d89428e853081f', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/permit.py': {'sha256': 'da843b398d0824022166a9dc3324438589e678e5c687b9c9ac73f30249c40890', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/port_owner.py': {'sha256': '7897238e67df546a04a065d0f5765ede37fa2c26364b7a338667181beb9800a1', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/root_overlay.py': {'sha256': 'd4c8db6c3f1f86f6ce757f2c31d9a2f604e63ac85a6d0559b97b32b022c07f71', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/schema_contract.json': {'sha256': 'c671c8fa874d402bf36262c90befa97827ca38be9d72dd27778151a8297267cb', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/source_receipts.py': {'sha256': '61a288bad886084d2ed493a3ea360e3b7aeed0e9d61c90b52498c41ecaed773c', 'stat': None}, '/opt/dgx-v4/runtime/G8_C_FIRSTTRIAL_CANDIDATE_R1/trace_proof.py': {'sha256': 'eef8336fb018b94eb0ac7e8d83b19494cfd113fff6b705b6cc76a43082085099', 'stat': None}, '/opt/dgx-v4/runtime/deployment_integrations/node_guard.py': {'sha256': 'a89d7836259f362fa0cc58cd976c376fa7a192fb46d93570f814ccb6887a96f8', 'stat': None}, '/opt/dgx-v4/runtime/node_adapter/node_wrapper.py': {'sha256': 'e5134ceb1cf739f48f0158cefb3687d1e97f92b9d412570f57d1412ebfc72402', 'stat': None}, '/usr/local/lib/dgx-v4/c-firsttrial/TURBO_T2I_API_CANDIDATE.json': {'sha256': 'd2705c1172ced106bb8161634e57adba9282736519f47b11c6dd024ba93acd6a', 'stat': None}, '/usr/local/lib/dgx-v4/c-firsttrial/native_bootstrap.py': {'sha256': '758686893346322f94d933b4d33ef4c7e3a1b6b93177b57e26be6a187226bbac', 'stat': None}, '/usr/local/lib/dgx-v4/c-firsttrial/native_sources.json': {'sha256': '4b284357812612253a639525c0fb475f6c8a4b135da1d3a6a16ca109abd66a60', 'stat': None}, '/usr/local/lib/dgx-v4/c-firsttrial/trace_ast.py': {'sha256': '3a9dd0e3afa66766ad4c60cb90a2160903d9d72c4f5ae5d7dc2b8f173c2e1fda', 'stat': None}}, 'controls': {'/etc/dgx-v4/g8-comfy-model-paths.yaml': {'sha256': 'c79e44afb425804bdca675c26dff9dd24b5064e063c72355bde603477506e6e1', 'stat': None}, '/etc/dgx-v4/node-manifest.json': {'sha256': '0290b7f47b3a09f560537a2bd6c8db929b4e85b9b0f145a92175949a270b9854', 'stat': None}, '/etc/dgx-v4/node-runtime-guard-policy.json': {'sha256': '65019e35b62e8c2f7f277ff2f94c6d36b6f913aff867dc46e6a60a318077ea84', 'stat': None}, '/etc/systemd/system/dgx-v4-node-guard.service': {'sha256': '3aafc1958b4eae70bbb888e9884f8aafb90a55cde3685c4e1e41dd5b315d93d4', 'stat': None}, '/opt/dgx-v4/bin/node-guard-bootstrap.py': {'sha256': '8f4c7add21d9971a9bc3b0923b920e2c5b902b1c04d5526d5edf770987a2b920', 'stat': None}}, 'source_receipt': {'sha256': 'e3b07d60f31a560a2999fd89d39846ec7e9e101270b2670436020e5eae0b72f6', 'stat': None}, 'boot_id': 'redacted-b80b4ff3866e', 'resource_lock': None, 'node_record': {'claimed_at': 1791816298.24122, 'container_id': '76b23f0f2d89ded119966820b815448967ccea0cad42ba95eb73894da3925f0e', 'generation': 1, 'id': 1, 'note': None, 'owner': 'dgx-hx-service', 'profile': 'image-turbo-c', 'quarantine_reason': None, 'released_at': 1791816402.425244, 'state': 'CLEAR', 'updated_at': 1791816402.425244}, 'guard_pid': 1928162, 'session_id': '1bb29e0e387b5d7fb55ba695a4c82d45', 'historical_proof': None, 'input_receipt_sha256': '441ebb261880f6de7dbfd96acce7e3cd370a57ef2f13d4696d18a517c4afabf6', 'qualification_raw_sha256': '52bbab13969f2972b25f73856c8b4d8396ca47c62dc6b156715cf8af585ea67a', 'accepted_origin_sha256': '7100deca208018d79fb6a7e6853ae3516cb24101dcb72e55923b9f48b2aa76f0', 'acceptance_sha256': '8a66f359178fb935810cafa0d4185139165ac53848939462e3f006f826f8d356'}

def validate_C_ARM_ready(v, doc):
    need(set(v) == {'schema', 'qualified', 'current_live'} and v['schema'] == 'g8-C-new-arm-Root-qualified-mirror/v1', 'exact_Root_ARM_qualification')
    q = _qualified_C_scope(v['qualified'], role='c', now=time.time())
    result = q['actual_result']
    need(result['permit_sha256'] == doc.sha256 and result['models_started'] == 0 and (result['hardware_validated'] is False) and (result['MCP_accepted'] is False), 'actual_ARM_no_model_no_hardware_promotion')
    old = result['live']
    new = v['current_live']
    for k in ('run_id', 'generation', 'nonce', 'old_guard_pid', 'old_session_id', 'old_pid_absent', 'Guard_stop_calls', 'Guard_start_calls', 'stop_rc', 'start_rc', 'stop_stderr_b64', 'start_stderr_b64', 'proof_path', 'source19', 'source_receipt_sha256', 'old_proof_raw_sha256', 'old_proof_F9', 'node_record', 'root_origin_sha256'):
        need(old[k] == new[k], 'same_activation_current_witness')
    return _validate_C_live(new, doc, result['history_completed'], C_CURRENT_SOURCE_ANCHOR, now=time.time())
C_SCOPE_UNITS = {'pc': 'dgx-v4-g8-c-new-arm-pc-readonly-r25.service', 'c': 'dgx-v4-g8-c-new-arm-r25.service'}
C_SCOPE_ROOTS = {'pc': '/opt/dgx-v4/hx/g8-c-new-arm-finite-r25', 'c': '/opt/dgx-v4/g8-c-new-arm-finite-r25'}
C_SCOPE_SCHEMAS = {'pc': 'g8-C-new-PC-post-negative-closed-readonly/v1', 'c': 'g8-C-new-arm-Root-returned/v1'}

def _qualified_C_scope(v, *, role, now=None):
    need(role in C_SCOPE_UNITS and v['schema'] == 'g8-C-new-arm-managed-qualified/v1' and (v['role'] == role), 'fixed_role_actual_qualification')
    intent = v['intent']
    o = v['actual_retained_EXIT0']
    u = o['unit']
    root = C_SCOPE_ROOTS[role]
    raw = base64.b64decode(o['unit_raw_b64'], validate=True)
    need(sha(raw) == o['unit_raw_sha256'] and dict((x.split('=', 1) for x in raw.decode().splitlines())) == u, 'actual_retained_unit_raw')
    need(intent['unit'] == C_SCOPE_UNITS[role] and u['Id'] == C_SCOPE_UNITS[role] and (u['LoadState'] == 'loaded') and (u['ActiveState'] == 'active') and (u['SubState'] == 'exited') and (u['MainPID'] == '0') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['Result'] == 'success') and (u['NRestarts'] == '0') and (u['Type'] == 'exec') and (u['User'] == u['Group'] == 'root') and (u['KillMode'] == 'control-group') and (u['InvocationID'] == intent['invocation_id']) and (re.fullmatch('[0-9a-f]{32}', u['InvocationID']) is not None) and (int(u['ExecMainPID']) == intent['worker_pid']) and (o['boot_id'] == intent['boot_id']) and (o['cgroup_procs'] == []), 'retained_true_EXIT0_exact_worker_boot_invocation')
    need('argv[]=/usr/bin/python3 -I -B ' + root + '/worker.py --worker ;' in u['ExecStart'] and u['CPUQuotaPerSecUSec'] == '1s' and (u['MemoryMax'] == '201326592') and (u['MemorySwapMax'] == '0') and (u['TasksMax'] == '32') and (u['Nice'] == '10') and (u['IOSchedulingClass'] == '3') and (u['RuntimeMaxUSec'] == '2min') and (u['SendSIGKILL'] == 'no') and (u['Restart'] == 'no') and (u['RemainAfterExit'] == 'yes'), 'fixed_managed_command_kernel_resources')
    need(v['source_review_sha256'] == intent['source_review_sha256'] and re.fullmatch('[0-9a-f]{64}', v['source_review_sha256']) is not None, 'fixed_review_source')
    blobs = {}
    for n in ('intent.json', 'returned.json', 'worker-completed.json', 'stdout.raw', 'stderr.raw'):
        b = v['originals'][n]
        r = base64.b64decode(b['raw_b64'], validate=True)
        st = b['stat']
        need(sha(r) == b['sha256'] and len(st) == 9 and (st[2] == len(r)) and (st[3:7] == [0, 0, 33152, 1]), 'actual_Root_raw_fullF9')
        blobs[n] = r
    need(strict(blobs['intent.json']) == intent and strict(blobs['returned.json']) == v['returned'] and (strict(blobs['worker-completed.json']) == v['worker_completed']), 'original_structured_raw_exact')
    need(not blobs['stderr.raw'] and v['returned']['child_rc'] == 0 and (sha(blobs['stdout.raw']) == v['returned']['stdout_sha256'] == v['worker_completed']['stdout_sha256']) and (sha(blobs['stderr.raw']) == v['returned']['stderr_sha256']) and (strict(blobs['stdout.raw']) == v['actual_result']) and (v['actual_result']['schema'] == C_SCOPE_SCHEMAS[role]), 'actual_child_output_not_outer_SSH')
    for x in (v['returned'], v['worker_completed']):
        need(all((x[k] == intent[k] for k in ('worker_pid', 'worker_sha256', 'worker_stat', 'boot_id', 'invocation_id', 'five_source', 'source_review_sha256'))), 'same_worker_source_and_invocation')
    need(v['actual_result']['observed_at'] <= v['returned']['observed_at'] <= v['worker_completed']['observed_at'] <= o['observed_at'] <= v['observed_at'], 'original_observation_order_no_restamp')
    if now is not None:
        need(0 <= now - v['observed_at'] <= 300, 'fresh_actual_managed_qualification')
    return v
NEGATIVE_ACTIONS = frozenset(('negative-release-mimo-metadata', 'status-negative-mimo-metadata'))
APPROVED_NEGATIVE_HOOK_SHA = 'c3bde4973fddcdcc029fd567a35ee1c18c19627f88f8e5f2f1267b3c670fa353'

def _negative_hook():
    import types
    raw, _ = protected_read(Path('/opt/dgx-v4/hx/mimo-cpu-negative-startup-import-r25-r6-r1') / 'wiring_hook.py')
    need(APPROVED_NEGATIVE_HOOK_SHA is not None and sha(raw) == APPROVED_NEGATIVE_HOOK_SHA, 'negative_hook_source_pending')
    m = types.ModuleType('held_same_runtime_negative_hook')
    m.__file__ = str(Path('/opt/dgx-v4/hx/mimo-cpu-negative-startup-import-r25-r6-r1') / 'wiring_hook.py')
    exec(compile(raw, m.__file__, 'exec'), m.__dict__)
    return m

def attach_negative(runtime, lease, c, bridge):
    return _negative_hook().attach_negative(runtime, lease, c, bridge)

def dispatch_negative(helper, body, uid):
    return _negative_hook().dispatch_negative(helper, body, uid)
APPROVED_LEGACY_C_HISTORY_SHA = 'dfaab5cab5b798991de1cd9fe3c4f67735e0fb331628b89145b2673927d58cc6'

def _legacy_C_startup(runtime, lease, operator, document):
    import types
    path = Path('/opt/dgx-v4/hx/mimo-registry-r16/c-arm-r30/cold_history.py')
    raw, _ = protected_read(path, limit=2097152)
    need(APPROVED_LEGACY_C_HISTORY_SHA is not None and sha(raw) == APPROVED_LEGACY_C_HISTORY_SHA, 'fixed_R26_legacy_C_source_pending')
    m = types.ModuleType('held_R26_legacy_C')
    m.__file__ = str(path)
    exec(compile(raw, m.__file__, 'exec'), m.__dict__)
    return m.classify(runtime, lease, operator, document, _registry_callbacks().historical, _registry_callbacks().validate_stopped_idle, _registry_callbacks().consume_installation)
NEW_NEGATIVE_SOURCE_ROOT = '/opt/dgx-v4/hx/mimo-cpu-negative-startup-import-r25-r6-r1'
REGISTRY_ACTIONS = frozenset(('reserve-registry-directfetch', 'pulse-registry-directfetch', 'finish-registry-directfetch', 'status-registry-source', 'activate-registry-source', 'recover-failed-registry', 'finish-failed-registry', 'reserve-asset-stage', 'pulse-asset-stage', 'finish-asset-stage', 'finish-failed-asset-stage', 'status-asset-stage', 'prepare-not-launched-asset-stage', 'finish-not-launched-asset-stage', 'prepare-empty-asset-range-repair'))
REGISTRY_HELPER_PINS = {'plan.py': '8e1cbff62464de2c24e6dc230de6bfac14c2ca14c0fbf806d93755e02f23be8f', 'bounded_process.py': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f', 'root_io.py': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e', 'state.py': '00c4cf4af1a768b995c0f07ce1a99f4b2dc53e5d11e78455d5298d1eb7f2f9e4', 'contract.py': '2be138163b815665bd2e0c1dfe37db4d5bbf6c954f8af60b7e9d7fe7370456e8', 'lineage.py': 'b999a26d489e00ed7feedffd154cb1e3739073d2afa9420e6d7db32bd4511478', 'managed_scope.py': '13277133c0670097e0e8aac1877a99c39ed3899cbe108e25312c5bb5cb8b266f', 'ancestor.py': 'fc6d353080ac2b2eca2457665d5e69049e626d89cde53022ba1f8e5b2356ade2', 'history_bootstrap.py': '1b54e5976c115ed5058e674a129cae61cd3ecda1575d5bccdc078251002f8643', 'prelaunch_stop.py': 'e7975c01de8561a99dbbbf8e4870717c0624485e7f6f23287ca48a71745e4e9e', 'live_idle.py': '0e9b31ca5cc387bfb60200d8a676b720d16b052645945c75892661838388d19f', 'restart_qualification.py': '60c5f89a6c613bfa2d118e3ad56752b29c2c9d0230429ae2e3273f49fcb50466', 'current_epoch.py': 'a0607d40dd0535199068d72091fed15ee5dd1dbe32413baf476b11d3e94ced12', 'observer.py': 'ab162251ba0e2a01fb749da8f9f329a10e1a4fe404cc9141d600eafce90f87ef', 'stage_naming.py': '65fbbcbf74a9b19ca37621f06f72a26825a18a0086f9c1d4a0eb86ac52f8a38d', 'entry_clock.py': '4549c760c0a90471b06509d5b526050ceb7eab8219ea9e61acd72b297e2bf69c', 'entry_clock_store.py': '37152e0b47b81670b6c45dd4bdd83884a59fd69754a3a296664dd84ed996d095', 'budget_contract.py': '5c4ad06e9dbaa3175da44a5678ae04daeb3efb4a4b62c6e1dc0542efcd0f37ae', 'safe_error.py': '2359d58a5357eb65e4a61940470c798f4e514e537029b023f24ac5c83565b203', 'terminal.py': 'edd10b0cc0cfdef9a1f1b7b2c827eadf3a7dbb5982b0e5ce55f4ba5702f272cb', 'negative_contract.py': 'abbf8c1be3b4c1f0d1f6080b0346ba7e5df3e5da1f589287528309478cca9fef', 'history_namespace.py': 'feb2331fb9df9d87c4478e3a16422f59a42f4b27aa40b4ce9204b112df2c0186', 'prelaunch_legacy.py': 'e397ff2f4e354d47aa6fed58d9c468db36794782447750cc5ccca5de5db93675', 'proc_lifetime.py': 'fa2d321e9a46ede57423a3d075352ec9b5df5c162cc624218b00c777396d503d', 'old_failed_kernel.py': 'a3c74562c51f8f72d257603dc97182e12ad7ffddefd1771af2ca9303f8946bdd', 'prelaunch_history.py': 'da7c07360adafad2c28feb50e07e0260ba13b0409425729c3b404a53c50e8822', 'prelaunch_readonly.py': '3723bbd78602a684a188d2d1068b8ae23f6c6fb1fd12e9af132109b4c6b4a3f1', 'prelaunch_proof.py': '114a454cbf68e14f74b47465cf374e4c53ab8495509d5d7a1247eaabd8a045ef', 'recovered_history.py': '17b23a8a078b40fed2827d2429cffd3896da0cbd2f29528b7c429aaf95193243', 'released_stage_history.py': 'a4454b08e462ad69866b183803d612b7547b8e9215f01d625c1781cda1ded86a', 'legacy_stage.py': 'b16faa894d235a719d918737e19ed514c40488fe1b395c53934c5fde19955cc2', 'receipt_codec.py': '997db57eb1daf81b185a9c1cf9417f936167e3ca937433fe49db7e251d0e1312', 'ready_history.py': '3409bf6dbc76be748e28e2f2c605c251e7286501b81f8be09372a0f37ac2b8d5', 'prelaunch_negative.py': '674ba1e45dfceff77a2abbdfc8b65993448417956aba00b3f1514b072688eed7', 'gate_protocol.py': 'bc9e38540640dc8ce7a6489099ab24f6c649e80ed943395830dacc72be9a4f3e', 'scope_receipt.py': '486fe94dbdb31db662807864e2b3f696418a2efea6f42da7037870dcb7c5a1bb', 'legacy_actor.py': '4fff2fb255f9775b0d2f5e97f8b8dee47a14d31a401f18013ae54f56f3c030eb', 'pc_clock.py': 'cb5b36e640faf8323b1d5b217b0be32aa5c63d8b9f38294a41bd84804184df06', 'pc_recovery.py': '359ec98c2d7667627f9c06b679131ddae7ec03c3bc572385baf63f5f418132a6', 'prestart_history.py': '935e30c6879dc682f685d34db611cef4db036b6c14b7a2f4ed44e87a8dcb4fd5', 'prelaunch_recovery.py': '6bd659dcaaef0769fb2ce95b6619676a5747e1cc96128c41d7112c47d523040b', 'failed_terminal.py': '3221cd26165654504ca8bd6c904440f8c92c4149e4a21bcd962c0788eb3cbd55', 'range_catalog.py': 'c40742117ba2da064a93dc8717ac22425ce91895e8839c809725643a3c8e1fde', 'range_transport.py': 'ae0e06e60226dc4759a95df8281115fbcaf84f4a2147de19be109b7d9f85433c', 'range_fetch.py': '4ab3dca44b7db63471f873f82f5da282580dfc6189950f0e34bb513aebc2b8a0', 'range_http.py': 'c1888164e00a619f7316ace69952484b43903667fe5b931193abd96964240762', 'range_component.py': '46ea4378229ada599beecb4e4c1b78d4d9be0ef77bb9d43ba32bec8e3c5233ad', 'asset_segments.py': '6fc4aad206356c587e5830c267b89a16f9b796c87db829c0208db69ae16bde10', 'stage_entry_clock.py': '07a409988b4905fea479ac58d71eea8010791c67d39ca94be82f28e500952a0f', 'segment_clock.py': '4fcbb8a297ed980ade98f6e4fe3b8bf4060e1fe35334c8141a94b6bb19f443b3', 'segment_terminal.py': '22b2941a926e2ea7cce37f9d8ba8884302de0e5778e80c7c4f8c84bd3eb46d43', 'asset_stage.py': '8960088fa6cea502c52db75ece7aa1969c3b255cc988e0169cc8c7effdb7850c', 'segment_publication.py': '38b98806cd695012b618383e5171d454214ed6dacad05c72bb3d7edcd7db07db', 'callbacks.py': '8b23b3342c855b5607fa43ce0ffeb40942c1d9fa98d7d0cf2504c35be796fb78', 'grant.py': '5ddec1dc173999fe76fe08dbbb4c88719b5695c3dc88e6e2f05e50e1c3bf69e2', 'history_reader.py': '2273f86b869adc45ef2cb81b3cf9db4906497de40eb548af264eeacdecc08aa8', 'not_launched_history.py': 'cca5257979a91ddbd906eb34547c764963b8eef3de5a520962513e2810899f81', 'zero_negative.py': '5cf0471bb32ace417eef015d1a30729ff6e9b4eacdc70db9b3253d15be275679', 'zero_scope.py': 'd4a2ec63279c7d07116e0a0af17a4703f86acc696719dfcb081862f01ebb8e16', 'zero_qualified.py': 'd6014ff3ab39619fe960c8f498456bae8b5072b3b5d441366a886b05014cce86', 'zero_recovery.py': '68e92923e6294d801255b1edc79e6760da03dba8aafa0666412ceca080bbbc74', 'retired_family.py': 'b0ad75aa200233143c874c0e3fac86e2443a2684f8478b96f493afd2b9e279d4', 'ffc2_history.py': '38a3448dc22f547859dca1cf8c7c4a0e57ea4fcd615776130c9d200dc1adb3fc', 'late_scope_context.py': '0e829a61212ac1089a9eb75377492ca719304c423f7cc99f92610ca45094eb92', 'known_prior_assets.py': 'f04e2c1bb7a5331bd1bec41d32530e3cebbb31495b42e630587e07b273b03c47', 'current_negative.py': '5187857874f57fc384934a40b8a06357ab735f95d6733239e16f4cf93fb872fc', 'current_prebind.py': '9ebcfd7ce75f0cb647420b4446f3b2622fdb7e8fe4ec77e3d91f47e293c2a550', 'empty_range_repair.py': '53c3959fdd766d9f3ced8ffcfeff98043a95dce97a5ecdb6b92d23b5fc497f93'}
REGISTRY_HELPER_CACHE = None

def _registry_callbacks():
    global REGISTRY_HELPER_CACHE
    if REGISTRY_HELPER_CACHE is not None:
        return REGISTRY_HELPER_CACHE
    import sys, types
    root = Path('/opt/dgx-v4/hx/mimo-registry-r16/service')
    order = ('plan.py', 'bounded_process.py', 'root_io.py', 'state.py', 'contract.py', 'lineage.py', 'managed_scope.py', 'ancestor.py', 'history_bootstrap.py', 'prelaunch_stop.py', 'live_idle.py', 'restart_qualification.py', 'current_epoch.py', 'observer.py', 'stage_naming.py', 'entry_clock.py', 'entry_clock_store.py', 'budget_contract.py', 'safe_error.py', 'terminal.py', 'negative_contract.py', 'history_namespace.py', 'prelaunch_legacy.py', 'proc_lifetime.py', 'old_failed_kernel.py', 'prelaunch_history.py', 'prelaunch_readonly.py', 'prelaunch_proof.py', 'recovered_history.py', 'released_stage_history.py', 'legacy_stage.py', 'receipt_codec.py', 'ready_history.py', 'prelaunch_negative.py', 'gate_protocol.py', 'scope_receipt.py', 'legacy_actor.py', 'pc_clock.py', 'pc_recovery.py', 'ffc2_history.py', 'prestart_history.py', 'history_reader.py', 'not_launched_history.py', 'zero_negative.py', 'zero_scope.py', 'zero_qualified.py', 'late_scope_context.py', 'zero_recovery.py', 'retired_family.py', 'prelaunch_recovery.py', 'failed_terminal.py', 'range_catalog.py', 'range_transport.py', 'range_fetch.py', 'range_http.py', 'range_component.py', 'asset_segments.py', 'stage_entry_clock.py', 'segment_clock.py', 'segment_terminal.py', 'known_prior_assets.py', 'current_negative.py', 'current_prebind.py', 'empty_range_repair.py', 'asset_stage.py', 'segment_publication.py', 'callbacks.py', 'grant.py')
    previous = {n[:-3]: sys.modules.get(n[:-3]) for n in order}
    modules = {}
    _declared = set(order)
    import builtins
    _base_import = builtins.__import__
    _approved_external = {'B_OWNER_RECOVERY_R25_WIRING.common': ('/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/common.py', 'c8274cbfde34d3e3111336dbd8017ae582dfd1fbc13acf9e321f6dae10be81bb'), 'B_OWNER_RECOVERY_R25_WIRING.collector': ('/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/collector.py', '3dce410687504747982d7280c709f996a96cb7f7ee0077f077944d4a75b37aa5'), 'node_adapter': ('/opt/dgx-v4/hx/runtime/node_adapter/__init__.py', 'c52939a70b86fb48139a1813b1fd2bb36305dea6b48af4040a6c8142717dc5c3'), 'node_adapter.client': ('/opt/dgx-v4/hx/runtime/node_adapter/client.py', '979444d64b0c36bc1608a0b280c9d90ee50ccda4f1a92ceb258a3d7ccf129f60'), 'node_adapter.protocol': ('/opt/dgx-v4/hx/runtime/node_adapter/protocol.py', '0af77b01e289b90544a0a07955b5ffcf794896e39a3dc68aa882c3123f39146a')}

    def held_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level:
            raise ImportError('R11_service_relative_import_not_reviewed')
        key = name + '.py'
        if key in _declared:
            if key not in modules:
                raise ImportError('R11_service_dependency_order')
            return modules[key]
        if name.split('.', 1)[0] in sys.stdlib_module_names:
            return _base_import(name, globals, locals, fromlist, level)
        if name not in _approved_external:
            raise ImportError('R11_service_unknown_nonstdlib_import')
        check = [name]
        if name == 'node_adapter':
            if tuple(fromlist) != ('protocol',):
                raise ImportError('R11_service_exact_node_protocol_import')
            check.append('node_adapter.protocol')
        for dependency in check:
            obj = sys.modules.get(dependency)
            path, pin = _approved_external[dependency]
            if obj is None or getattr(obj, '__file__', None) != path:
                raise ImportError('R11_service_external_module_origin')
            body, source_F9 = protected_read(path, limit=2097152)
            if sha(body) != pin:
                raise ImportError('R11_service_external_module_SHA')
        if name == 'node_adapter' and getattr(sys.modules[name], 'protocol', None) is not sys.modules.get('node_adapter.protocol'):
            raise ImportError('R11_service_exact_node_protocol_module')
        return sys.modules[name]
    try:
        for name in order:
            raw, st = protected_read(root / name)
            need(sha(raw) == REGISTRY_HELPER_PINS[name] and st[3:7] == [0, 989, 33056, 1], 'Rootheld_complete_UID999_readable_service_source')
            m = types.ModuleType(name[:-3])
            m.__file__ = str(root / name)
            sys.modules[name[:-3]] = m
            modules[name] = m
            m.__dict__['__builtins__'] = dict(vars(builtins), __import__=held_import)
            exec(compile(raw, m.__file__, 'exec'), m.__dict__)
        result = modules['callbacks.py']
        result.Grant = modules['grant.py'].RegistryGrant
        REGISTRY_HELPER_CACHE = result
        return result
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
_STARTUP_OPERATION = '2b9e9b631cebc13ae6b1550ee59c13ed'
_STARTUP_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
_STARTUP_SAFE_REASONS = ('6279_actual_CAS2_start0_failure_no_inferred_cause', '6279_adopted_exact_old_history_not_rewritten', '6279_failed180_same_old95aa_identity', '63_layer_manifest_config_index_exact_content_set', 'A_entry_current_exact_request_epoch', 'A_local_scope_clock_order_and90', 'A_remote_clock_audit_not_future_freshness', 'C24_MAC_embedded_original_F9_SHA', 'C24_actual_stderr_stdout_not_success', 'C3_Cleaf_unchanged', 'CA_required', 'CPU_helper_changed_before_exec', 'CPU_helper_source_drift', 'CPU_maintenance_not_finished', 'C_ARM_Root_command_alive_retain_soleRuntime_stores_lease', 'C_ARM_binding_phase', 'C_ARM_closed_or_inflight_retain_soleRuntime_stores_lease', 'C_ARM_command_key_no_replay', 'C_ARM_finish_requires_trial_terminal_not_stop_response', 'C_ARM_not_attached', 'C_ARM_not_live_no_model_start', 'C_ARM_pending_history_retains_service_lease', 'C_ARM_private_inflight', 'C_ARM_shutdown_rejects_new_private_intent', 'C_ARM_source_pending', 'C_ARM_source_revision_pending', 'C_ARM_sticky_no_other_private_mutation', 'C_actual_completion_bound', 'C_actual_required', 'C_renewal_originals_immutable', 'Core_AB_present', 'Core_drift_during_live_idle_collect', 'HTTP_200_required', 'Linux_peercred_required', 'MAC_C24_terminal', 'OCI_stream_named_F9_unchanged', 'PC_actual_whole_readonly90', 'PC_collection_monotonic_order', 'PC_local_conservative_age300_not_remote_wall', 'R11_actual_duration', 'R11_actual_fixed_worker_exec', 'R11_actual_owned_stop_order_rc0', 'R11_actual_scope_resource_caps', 'R11_archived_capture_exact', 'R11_body_original_identity', 'R11_body_time_order', 'R11_collected_exact_missing_not_EXIT0', 'R11_complete_ownedstop_three', 'R11_exact_new_phase_request', 'R11_fixed_phase_nonce', 'R11_full_scope_envelope', 'R11_inner_outer_same_nonce_operation', 'R11_loaded_poststop_exact_original_inv', 'R11_original_return_before_collect', 'R11_poststop_original_current_negative', 'R11_protected_PC_phase_context_SHA', 'R11_returned_actual_leaf_not_derived_bool', 'R11_same_boot_inv_PID_source', 'R11_scope_original_raw', 'R11_scope_same_request_phase', 'R11_true_retained_owned_EXIT0', 'R11_worker_actual_kernel', 'R13_complete_original_R12_activation_and_zero_causal_chain', 'R13_complete_retired_history_before_new_activation', 'R13_exact_retired_source_order_not_new_source', 'R13_first_independent_suffix_only_not_blind_retry', 'R13_no_unknown_retired_actor_siblings', 'R13_retired_Root127_after_complete_consumption', 'R13_retired_actor_fullF9_after_constructor', 'R13_retired_all_eight_actor_originals_not_summary', 'R13_retired_complete_original_helper_source', 'R13_retired_exact_oldcfg_no_rebase', 'R13_retired_failed_interval_preserved_in_original_family', 'R13_retired_failure_not_success_or_accepted_bytes', 'R13_retired_family_SOURCE_pending', 'R13_retired_history_not_raced_at_single_activation', 'R13_retired_immutable_private_context', 'R13_retired_only_fixed_completed_failed_stage', 'R13_retired_original_current_qualification_full_consumer', 'R13_retired_original_exact_fullraw_F9', 'R13_retired_service7_after_complete_consume', 'R13_retired_service_held_fullraw_F9', 'R13_retired_zero_release_complete_not_released_again', 'R2_private_original_unit_whole_bytes_stat', 'R9_actual_negative_completion_required', 'R9_actual_released_history_not_new_negative', 'R9_complete_Root98_original_source_SHA_F9', 'R9_complete_original_negative_and_actor_chain', 'R9_completed_original_operations_and_states', 'R9_exact_old_current_source_and_failed_stage', 'R9_history_never_image_CPU_or_future_source_authority', 'R9_installation_original_identity_not_future_PID', 'R9_original_causal_completion_and_release_hashes', 'R9_original_qualified_release_full_SHA_F9', 'R9_protected_original_helper_closure', 'R9_released_history_source_pending', 'Root_ancestor_actual_identity', 'Root_ancestor_held_recheck', 'Root_ancestor_named_held_binding', 'Root_ancestry_segment_fullF9', 'Root_capture_UID', 'Root_capture_reviewed_policy_literal_pending', 'Root_collected_current_Core_envelope_not_caller_selected_generation', 'Root_fixed_stage_publication', 'Root_held_leaf', 'Root_historical_readonly_only', 'Root_leaf_fullSHA_F9_stable', 'Root_operator_peer_required', 'Root_origin_group989_readonly_mirror', 'Root_owned_CG_tree', 'Root_permit_config_bound', 'Root_private_readonly_peer', 'Root_private_segment_directory', 'Root_private_token_FD', 'Root_protected_stage_plan_exact_schema', 'Root_stage_clock_begin', 'Root_stage_clock_finish', 'Root_stage_terminal_clock_begin', 'Rootheld_complete_UID999_readable_service_source', 'TLS_or_hostname_failed', 'absolute_operation_budget', 'accepted_segment_receipt_origin', 'activation_revision_pending', 'actual_999_original_leaf', 'actual_AB_current_idle_source_install_pending', 'actual_AB_route_and_connect5', 'actual_ARM_no_model_no_hardware_promotion', 'actual_A_EXIT1_preserved_never_success', 'actual_A_Root_stage_origin_fullF9', 'actual_C24_failed_MAC_origin', 'actual_C24_rc1_identity', 'actual_CPU1_aggregate', 'actual_C_cleanup_watchdog_samples_terminal', 'actual_C_core_and_scheduler_cleanup_ledger', 'actual_Code1Status2_not_timeout_signal_or_fabricated_EXIT0', 'actual_Guard_root_raw_F9', 'actual_NVMe_dual_identity_SOURCE_pending', 'actual_OCI_stream_full_descriptor_SHA', 'actual_R4_history_pending', 'actual_R7_completed_history_pending', 'actual_Root_AB_snapshot', 'actual_Root_raw_fullF9', 'actual_actor3_F9_full_SHA', 'actual_actor_directory_same_old_three', 'actual_b003_historical_config', 'actual_check_not_service_start', 'actual_child_output_not_outer_SSH', 'actual_clamped_runtime_seconds', 'actual_classification_source_fullF9', 'actual_cleanup_only_original_supervisor_no_fake_success', 'actual_complete_AB9', 'actual_completed_negative_exact_entries', 'actual_completed_negative_original_SHA', 'actual_configured_clock_policy30_not_loosened', 'actual_current_idle_transport', 'actual_current_idle_wrapper_installed', 'actual_current_invocation_root', 'actual_current_scheduler_idle', 'actual_current_stage_plan_origin', 'actual_direct_wired_route', 'actual_entry_send_original', 'actual_expected_live_maintenance', 'actual_expected_scheduler_fence', 'actual_finish_marker_bound', 'actual_fixed_ancestor_source_qualified', 'actual_full19_source_originalproof_F9_preserved', 'actual_live_nodes_noholds_noQUAR', 'actual_live_old_owner_source', 'actual_memory_swap_tasks', 'actual_native_after_original_return', 'actual_new_current_invocation', 'actual_new_current_readonly', 'actual_new_epoch_qualification_activation_required', 'actual_new_epoch_source_qualification_pending', 'actual_new_kernel_dead_old_failed_worker', 'actual_no_daemon_import_outputs', 'actual_normal_same_strict_classification', 'actual_normal_stopped_original_fullraw_SHA', 'actual_old_R7_full80_source', 'actual_old_R7_independent_current_qualification', 'actual_old_R7_module_closure', 'actual_old_config_archive_source', 'actual_old_negative_completion_not_new_authority', 'actual_original_deadline_never_extended', 'actual_original_reservation_causal_fence', 'actual_original_service_invocation', 'actual_original_unit_independent_bytes_F9', 'actual_owned_cgroup', 'actual_owned_cleanup_original_SHA_F9', 'actual_owned_original_lease_not_foreign', 'actual_parent_intent_original', 'actual_pre_daemon_failed_phase_unknown_first_RPC_cause', 'actual_prior_identity_not_template', 'actual_private_daemon_dirs_empty_before_recovery', 'actual_private_daemon_storage_empty', 'actual_proc_root_directory', 'actual_protected_CurrentReader_old_owner', 'actual_provisional_raw_source_current', 'actual_qualified_old_config_readable_Root_original', 'actual_qualified_original_negative_history', 'actual_readonly_output_not_static_bool', 'actual_readonly_worker_result_bound', 'actual_released_NodeRecord', 'actual_restart_invocation', 'actual_retained_unit_raw', 'actual_same_PID_new_C_renewal_source', 'actual_same_lease_Cleaf', 'actual_saved_terminal_PIDgone_fullCGempty', 'actual_scope_resource_caps', 'actual_scope_worker_loader_source_fullF9', 'actual_send_moment_full_original_binding', 'actual_service999_private_registry_directory', 'actual_service_directory_identity_entries_stable', 'actual_service_leaf_full_F9', 'actual_stage_EXIT0_partial_success_not_import', 'actual_stage_history_directory', 'actual_stage_terminal_state_no_import_success', 'actual_stop_time_chain', 'actual_stopped_prior_source_pending', 'actual_store_nodes_not_released_by_bootstrap', 'actual_store_nohold_not_history_bool', 'actual_success_stage_archive_then_stop', 'actual_successful_live_reserved_predecessor', 'actual_transactional_live_record_raw', 'actual_unit_raw_SHA', 'actual_whole_NVMe_IO_device_required', 'after_stop_actual_registry_fullread', 'all118_Cleaf_original_physicallease_after_stop', 'all_69_layers', 'all_actor_three', 'all_actual_failed_registry_originals_no_terminal_or_gap', 'all_historical_positive_stop_releases', 'all_nodes_unheld', 'all_profiles_stopped', 'all_selected_segments_complete', 'already_installed_AB9_no_mutation', 'ancestor_history_nonfuture_no_refresh', 'approved_negative_review_required', 'archive_fixed_leaf_name', 'arm64_linux_config', 'bf84_consumed_no_cross_epoch_replay', 'blob_HTTP_failed', 'blob_digest', 'blob_size', 'body_fullraw_F9_scope_return_binding', 'both_original_private_directories', 'bounded_CPU_reply_1MiB', 'bounded_IO_charge', 'bounded_OCI_workspace', 'bounded_Root_receipt', 'bounded_clock_base64_type', 'bounded_clock_original_bytes', 'bounded_complete_proc_raw', 'bounded_exact_range', 'bounded_fixed_interval', 'bounded_fixed_ranges', 'bounded_headers', 'bounded_historical_raw_total', 'bounded_original_bytes', 'bounded_original_wait', 'bounded_owned_CG_tree', 'bounded_proc_enumeration', 'bounded_proc_identity_events', 'bounded_proc_lifetime_deadline', 'bounded_range_headers', 'bounded_redirect_path', 'bounded_same_private_socket_readonly_original', 'bounded_segment_body', 'bounded_sizes_and_payload_type', 'bounded_stage_bytes', 'bounded_stage_history_namespaces', 'bounded_window', 'callback_rows_source_lease_stable', 'canonical_clock_base64', 'certificate_hostname_command_failed', 'certificate_hostname_refused', 'certificate_original_local_and_remote_order', 'combined_current_idle_age30', 'commands_actual_local_time', 'commands_actual_observation_order', 'commands_canonical_original_SHA', 'commands_complete_original_schema', 'commands_exact_original_file_stat', 'commands_final_current_after_actual_retained_scope', 'commands_original_bytes_SHA_F9_unchanged', 'commands_original_capture_time_order', 'commands_original_observation_nonfuture', 'commands_preserved_complete_capture_chain', 'complete_PC_stopped_idle_raw', 'complete_actual_new_scope_owned_stop_originals', 'complete_bounded_ancestor_originals', 'complete_commands_three_observations_time_chain', 'complete_current_A34_no_owned_engine', 'complete_live_Core_and_AB', 'complete_live_GPUempty', 'complete_new_shared_leaf_set', 'complete_original_pulse_ordinal_source_binding', 'complete_qualified_reference', 'complete_response_clock_original', 'complete_segment_reference', 'complete_source_and_originals', 'complete_source_set', 'config_scope_only_pins_review', 'connected_peer_identity', 'consume_original_A_order', 'context_FS_and_IO_fields_derived_from_qualified_dual_producer', 'continuation_review_pending', 'contradictory_run_terminal', 'core_release_unconfirmed', 'current004bc_fa33_not_rebased95aa', 'current118_exact_map', 'current_AB_source_F9', 'current_Core_idle_positive_generation', 'current_Core_nodes_unheld_unquarantined', 'current_Core_stopped_positive_generation', 'current_PID_readonly_qualification_pending', 'current_actor_directory_unchanged', 'current_actor_exact_entries', 'current_actor_held_raw_F9', 'current_actor_recheck_original_rows', 'current_baseline_changed_no_rebase_during_grant', 'current_container_known_inactive', 'current_entry_clock_certificate_not_historical', 'current_epoch118_and_physical_lease', 'current_exact_AB9', 'current_identity_source_lease_history_stable', 'current_idle_transport20', 'current_prebind_A_PC_same_plan', 'current_prebind_A_exact_current', 'current_prebind_A_whole30', 'current_prebind_SOURCE_None', 'current_prebind_active_reserved_equal_original', 'current_prebind_actor_cap2MiB', 'current_prebind_actor_causal_order', 'current_prebind_actor_current', 'current_prebind_actor_request_same_stage', 'current_prebind_actual_Root', 'current_prebind_actual_active_reserved_actor', 'current_prebind_actual_held_plan', 'current_prebind_actual_saved_ready_PID', 'current_prebind_all_Root_anchors', 'current_prebind_all_original_pulses', 'current_prebind_body_cannot_select_actor', 'current_prebind_each_pulse_full_source_F9', 'current_prebind_each_pulse_same_physical_source118', 'current_prebind_exact_actor_no_terminal_partial', 'current_prebind_exact_directory_record', 'current_prebind_exact_live_identity118', 'current_prebind_exact_request', 'current_prebind_exact_shared_late_context_source', 'current_prebind_exact_source_index', 'current_prebind_exact_typed_origin', 'current_prebind_existing_private_reply_1MiB_no_increase', 'current_prebind_existing_service999', 'current_prebind_existing_service_request_root', 'current_prebind_finish_owned_active', 'current_prebind_fixed_namespaces', 'current_prebind_fixed_private_leaf', 'current_prebind_fixed_request_directory', 'current_prebind_fixed_service_request_root', 'current_prebind_fixed_source_leaf', 'current_prebind_full118_plan', 'current_prebind_full_ordinal_count', 'current_prebind_full_original_plan_actor', 'current_prebind_history_complete_before_private_consumer', 'current_prebind_kernel_time', 'current_prebind_known_prior_version', 'current_prebind_latest_actor_unchanged', 'current_prebind_new_active_not_old_stage', 'current_prebind_no_context_launch_terminal', 'current_prebind_nonce_is_sealed_active_stage', 'current_prebind_not_worker_success', 'current_prebind_original_deadline', 'current_prebind_private_actor_F9', 'current_prebind_private_actor_directory', 'current_prebind_private_actor_stable', 'current_prebind_private_request_root', 'current_prebind_publish_fresh_whole30_actor', 'current_prebind_ready_same_current', 'current_prebind_recheck_whole30', 'current_prebind_release_exact_owned_ranges_once', 'current_prebind_request_no_actor_change', 'current_prebind_request_parent_unchanged', 'current_prebind_request_path_stage', 'current_prebind_request_root_exact_ENOENT', 'current_prebind_roots_nonce_SOURCE_None', 'current_prebind_same_review', 'current_prebind_service_private_directory', 'current_prebind_shared_late_context_SOURCE_None', 'current_prebind_snapshot_context_exact', 'current_prebind_snapshot_full_source_controls', 'current_prebind_snapshot_plan_match', 'current_prebind_source_F9', 'current_prebind_warm_exact_causal_completion', 'current_prebind_warm_full_actor_originals', 'current_prebind_warm_source_not_new_authority', 'current_released_record_not_running_or_unknown', 'current_rows_unchanged_during_qualification', 'current_same_private_request_owner', 'current_same_source_SHA_and_fullF9', 'current_source_shared_gate_inflight', 'diff_id_format', 'direct_exchange_failed', 'disjoint_all_completed_and_preserved_intervals_or_exact_typed_empty_grant', 'distinct_after_stop_scope_original', 'distinct_stopped_kernel_current_clock_order', 'duplicate_JSON', 'duplicate_entry_clock_key', 'duplicate_json_key', 'duplicate_key', 'duplicate_size_conflict', 'duplicate_source_or_proof_key', 'durable_negative_completed_marker', 'durable_segment_receipt_readback', 'empty_repair_Root_explicit_all_prior_operations', 'empty_repair_Root_once_contract_publication', 'empty_repair_actual_private_parent', 'empty_repair_actual_typed_proof_not_zero_bool', 'empty_repair_all_original_failed_ancestors_still_exact', 'empty_repair_attempt_directory_stable', 'empty_repair_attempt_exact_private_tree', 'empty_repair_attempt_held_named_original', 'empty_repair_attempt_private_base', 'empty_repair_attempt_real_private_origin', 'empty_repair_complete_actor_singleleaf_cap', 'empty_repair_contract_full_readback', 'empty_repair_current_before_reserve_only', 'empty_repair_event_actor_unchanged', 'empty_repair_exact_once_attempt_not_second_work_authority', 'empty_repair_exact_prepare_action', 'empty_repair_explicit_finite_Root_contract_not_bool', 'empty_repair_full_original_event_consumer_no_clock_refresh', 'empty_repair_historical_intent_refs_not_new_permission', 'empty_repair_history_complete_intent_context', 'empty_repair_internal_owned_stage_actor', 'empty_repair_new_exact_plan_source_current', 'empty_repair_new_private_stage', 'empty_repair_no_foreign_hold', 'empty_repair_no_omitted_overlapping_used_ancestor', 'empty_repair_no_successful_or_partial_interval_overlap', 'empty_repair_no_unfinished_ancestor', 'empty_repair_one_exact_interval_all_ancestors_bound', 'empty_repair_one_grant_one_new_operation', 'empty_repair_only_idle_activated_same_Runtime', 'empty_repair_original_actor_fullF9_before_after', 'empty_repair_original_installation_history_only', 'empty_repair_original_new_plan_window_no_old_deadline_rebase', 'empty_repair_positive_missing_private_base', 'empty_repair_private_actor_directory_stability', 'empty_repair_private_actor_held_fullF9', 'empty_repair_private_actor_only_original', 'empty_repair_private_actor_origin', 'empty_repair_private_base_held_named_after', 'empty_repair_private_reply_original_cap', 'empty_repair_qualified_Root_origin', 'empty_repair_real_failed_completed_fence_not_success', 'empty_repair_same_original_reconsumed_after_fresh_current', 'empty_repair_service_private_base', 'empty_repair_stage_name', 'entry_actual_idle_resource_fields', 'entry_clock_source_literal_pending', 'entry_consumer_exact_current_epoch_and_producer', 'entry_exact_current_epoch_and_source', 'entry_exact_new_scope_schema_source', 'entry_finish_exact_current_epoch', 'entry_full_original_SHA', 'entry_origin_exact_F9', 'entry_policy_exact_SHA', 'exact_CPU_and_samples_new118', 'exact_CPU_helper_closure', 'exact_F9_group', 'exact_F9_mode', 'exact_Root_ARM_qualification', 'exact_compressed_original_bytes_SHA', 'exact_current118_source', 'exact_current_idle_clock', 'exact_dual_block_fullF9_rdev_sysfs_provenance', 'exact_failed6279_scope', 'exact_fixed_channel_echo', 'exact_held_access_mode', 'exact_hex_receipt_SHA', 'exact_historical_A_entry', 'exact_historical_r23_path_error_not_model_failure', 'exact_http_framing', 'exact_immutable_failed_A_raw_F9_rechecked', 'exact_integer_F9', 'exact_lossless_envelope_no_extra', 'exact_negative_once_identity', 'exact_new_completed', 'exact_new_request_scope', 'exact_old_A_failed_unit_source_original', 'exact_old_consumer_bytes_no_overlay', 'exact_old_private_namespace_no_start_intent', 'exact_old_registry_directory_F9', 'exact_operator_config', 'exact_original_full_F9', 'exact_owned_scope_normal_stop_original', 'exact_owner_mode_nlink', 'exact_postCAS_case_roots', 'exact_post_normal_Guard_activation_fields', 'exact_prior_private_mirror_leafset', 'exact_prior_stop_and_UID999_original', 'exact_range_offset_total_length', 'exact_raw_F9_envelope', 'exact_readonly_observation', 'exact_stop0_permit', 'exact_stopped_kernel_original', 'exact_two_ordered_generic_shutdown_originals', 'exact_typed_shutdown_classification_not_bool', 'exact_unmodified_full_receipt_SHA', 'exact_whole_AB', 'expected_original_fullSHA_F9', 'failed_A_exact_Root_mirror_original', 'failed_A_historical_source_pending', 'failed_finish_bound_original_A_context_reservation', 'failed_finish_current_source_terminal', 'failed_finish_exact_entries', 'failed_finish_original_deadline_reservation_unchanged', 'failed_finish_original_once_no_foreign_or_partial', 'failed_finish_requires_matching_actual_current_reservation', 'failed_partial_and_A_source_unchanged', 'failed_registry_exact_raw_F9_pin', 'failed_stage_positive_quiescence_not_unknown', 'failure_original_after_process_scan', 'ffc2_history_all_old_Root116_raw_F9', 'ffc2_history_complete_old_event_result_not_refreshed', 'ffc2_history_exact_old_config_not_new_authority', 'ffc2_history_exact_old_helper_order', 'ffc2_history_fixed_old_Root_and_complete_source_order', 'ffc2_history_new_source_binding_pending', 'ffc2_history_old_Root116_stable_after_consume', 'filesystem_partition_not_IO_device', 'final_core_stopped_released', 'final_noholds', 'final_wire_hash', 'finish_after_completed', 'finite_continuation_permit', 'finite_current_PC_now', 'finite_current_idle_exchange_no_retry', 'finite_exact_oldstop_newstart_no_model_success', 'finite_live_clock', 'finite_normal_old_Guard_positive_exit_no_retry', 'finite_plan_duration_and_local_publication_age', 'fixed63_range_descriptor', 'fixed_C_run_body', 'fixed_F9_leaf', 'fixed_R26_legacy_C_source_pending', 'fixed_Root_registry_command', 'fixed_Root_shared_stage_directory', 'fixed_Rootpeer_C_ARM_command', 'fixed_absolute_process_root', 'fixed_blob_stream', 'fixed_cdn_redirect', 'fixed_complete_OCI_descriptor_order', 'fixed_config_identity', 'fixed_ctr225_identity_and_deadline', 'fixed_current_Root_readonly_scope', 'fixed_current_idle_existing_transport', 'fixed_descriptor_totals', 'fixed_digest_leaf_not_external_path', 'fixed_failed_registry_source_closure', 'fixed_http_target', 'fixed_kernel_leaf_identity', 'fixed_managed_command_kernel_resources', 'fixed_manifest_for_exact_index', 'fixed_manifest_identity', 'fixed_model_image', 'fixed_new_C_run2_original_manager', 'fixed_new_epoch_and_grant', 'fixed_new_leaf_origin', 'fixed_new_run_original', 'fixed_new_summary_ref', 'fixed_old_module_path_pin', 'fixed_once_operation', 'fixed_openssl_path_certificate_deadline', 'fixed_operator_request', 'fixed_origin_budget', 'fixed_original_63_descriptor_required', 'fixed_original_leaf_policy', 'fixed_original_prior_index', 'fixed_owned_kernel_target', 'fixed_private_C_actions', 'fixed_process_root_path', 'fixed_range_target', 'fixed_reason', 'fixed_review_source', 'fixed_role_actual_qualification', 'fixed_source_worker_only', 'fixed_stage_Rootpeer_command', 'fixed_stage_clock_four_originals', 'fixed_stage_history_name', 'fixed_stage_history_namespace', 'fixed_stage_publication_nonce', 'fixed_stage_terminal_origin', 'fixed_startup_diagnostic_stage', 'fixed_terminal_clock_begin', 'fixed_worker_segment_source_binding', 'fresh_actual_managed_qualification', 'fresh_age_cap', 'fresh_current_same_after_retained_EXIT0', 'fresh_dns_route', 'fresh_guard_current_idle', 'fresh_independent_entry_scope_not_old_entry', 'fresh_positive_newsession_unclaimed_CLEAR_no_ARM_trial_start', 'fresh_shared_lock_baseline_required', 'fresh_stage_source_resource_readiness', 'fresh_token_file', 'fresh_token_supply', 'full_F9', 'full_actual_registry_records_required', 'full_immutable_clock_and_origin_chain', 'full_original_readonly_request', 'full_owned_cleanup_original_reference', 'full_raw_F9_size', 'future_source_binding_pending', 'guard_CLEAR_deadline', 'held_Root_readable_ancestor_raw_F9', 'held_full_SHA_F9', 'held_named_full_F9_drift', 'held_new_directory_exact_leaf_set', 'held_original_parent_drift', 'held_parent', 'held_secret_refused', 'held_token_stable', 'historical_AB9_source', 'historical_ABsource_Root_binding', 'historical_Guard_raw', 'historical_R4_candidate_fixed_fullraw_F9', 'historical_complete_PC_epoch', 'historical_completed_stage_not_future_current_qualification', 'historical_dependency_order_origin', 'historical_embedded_complete_original_modules', 'historical_embedded_dependency_order_origin', 'historical_embedded_full_source_SHA', 'historical_embedded_held_origin', 'historical_entry_raw_F9_pin', 'historical_exact_R9_embedded_namespace', 'historical_exact_both_AB9', 'historical_exact_fixed_source_namespace', 'historical_external_exact_module', 'historical_external_package_origin', 'historical_external_source_SHA', 'historical_external_source_pending', 'historical_failed_finish_not_image_success', 'historical_failed_terminal_full_Root_producer_consumer', 'historical_final_AB_noholds', 'historical_final_Core_stopped', 'historical_final_work_history9', 'historical_fixed_node_protocol', 'historical_full_AB9', 'historical_gen10_STOPPED_not_future_hold_release', 'historical_installation_distinct_current_PID_source', 'historical_module_exact_raw_SHA', 'historical_noholds', 'historical_real_A_entry_not_fresh_permission', 'historical_retained_failed_unit_fullraw', 'historical_transactional_record_bytes', 'historical_uncertain9_and_current_noactive', 'historical_unique_module_collision', 'historical_unique_module_replaced', 'history_changed_before_stop', 'http_reader_mode', 'immutable_history9_idle', 'immutable_original_segment_FD_named', 'immutable_original_segment_fullSHA', 'independent_current_kernel_death_emptyCG_ownedlease', 'independent_new_qualified_source_not_old_scope', 'index_readback', 'insufficient_original_window_no_reserve', 'insufficient_whole_window', 'integer_not_boolean_counters', 'invalid_json', 'journal_original_JSON_rows', 'journal_original_message', 'kernel_anchor_Root_directory', 'kernel_directory_named_identity', 'kernel_leaf_FD_named_identity', 'kernel_original_cap', 'known_empty_actual_A_observation_frame', 'known_empty_actual_zero_not_partial', 'known_empty_both_kernel_within_actual_A_frame', 'known_empty_bounded_diagnostics', 'known_empty_complete_closed_failed_source_names', 'known_empty_consumer_closed_original_failure_names', 'known_empty_exact_zero_no_receipt_no_extra_segment', 'known_empty_exactly_two_fresh_kernel_observations', 'known_empty_explicit_type_not_accepted_asset', 'known_empty_failure_kept_failure_unknown_not_NLA', 'known_empty_full_failure_original', 'known_empty_historical_worker_same_A_boot', 'known_empty_metadata_only_diagnostic', 'known_empty_no_daemon_or_import', 'known_empty_no_omitted_or_unproved_failure', 'known_empty_original_actual_started_EXIT1', 'known_empty_original_finite_plan', 'known_empty_original_same_source_failed_not_success', 'known_empty_original_terminal_bytes', 'known_empty_positive_absence', 'known_empty_same_A_boot', 'known_empty_second_full_inventory_source_receipt_unchanged', 'known_empty_single_fixed_failed_interval', 'known_empty_two_independent_ordered_kernel_observations', 'known_live_identity_drift', 'known_prefile_actual_A_frame', 'known_prefile_archive_empty', 'known_prefile_bounded_diagnostic', 'known_prefile_complete_metadata_held_named', 'known_prefile_diagnostic_only', 'known_prefile_exact_inventory_and_origins', 'known_prefile_explicit_failed_preservation_type', 'known_prefile_fresh_daemon_positive_absence', 'known_prefile_full_child_metadata', 'known_prefile_same_boot_ordered_kernel', 'known_prefile_two_actual_kernels_within_outer_frame', 'known_prior_A_origin_exact_reference', 'known_prior_PC_local_fullraw_F9', 'known_prior_PC_root_SOURCE_None', 'known_prior_PC_shared_origin', 'known_prior_ROLE_SOURCE_None', 'known_prior_Root_fixed_leaf_type', 'known_prior_Root_private_directory', 'known_prior_bounded_preserved_diagnostics', 'known_prior_bounded_stages', 'known_prior_complete_BASE_roots', 'known_prior_complete_old_A55_preserved_source', 'known_prior_current_payload_socket_positive_absence', 'known_prior_current_positive_absence', 'known_prior_diagnostic_typed_metadata', 'known_prior_directory_full_F9_stable', 'known_prior_empty_archive_no_daemon', 'known_prior_exact_A_terminal_F9', 'known_prior_exact_accepted_segments', 'known_prior_exact_complete_acquire_definition', 'known_prior_exact_completed_preservation', 'known_prior_exact_sealed_old_domain_origin', 'known_prior_exact_source_names', 'known_prior_exact_stage_namespace', 'known_prior_exact_stage_root_socket', 'known_prior_exact_version', 'known_prior_first_BASE_ENOENT', 'known_prior_first_batch_only_empty', 'known_prior_fixed_segment_path', 'known_prior_full_completion_fence_originals', 'known_prior_full_existing_terminal_success_or_failed_for_fresh_zero_only', 'known_prior_full_old_history_before_stage_snapshot', 'known_prior_full_service_reference', 'known_prior_held_named_F9', 'known_prior_large_accepted_SHA_F9_without_rehash', 'known_prior_large_asset_original_F9', 'known_prior_local_PC_full_terminal_original', 'known_prior_missing_BASE_with_prior_unknown', 'known_prior_never_current_stage', 'known_prior_no_omitted_or_foreign_inventory', 'known_prior_no_unresolved_or_partial_actor', 'known_prior_old_A55_second_full_source_read', 'known_prior_only_completed_source_leaves_no_partial_or_token', 'known_prior_original_A_origin_from_consumed_PC_clock', 'known_prior_original_receipt_expression_unique', 'known_prior_present_BASE_requires_consumed_successes', 'known_prior_preserved_full_F9_stable', 'known_prior_receipt_exact_accepted_segment', 'known_prior_receipt_fullSHA_F9', 'known_prior_receipt_full_original_binding', 'known_prior_receipt_fullraw_matches_terminal', 'known_prior_receipt_stdlib_json_only', 'known_prior_result_full_original', 'known_prior_result_no_partial', 'known_prior_result_original', 'known_prior_same_original_bytes_not_copy_bool', 'known_prior_same_source_completed_raw', 'known_prior_same_source_full_terminal_not_summary_bool', 'known_prior_sealed_old_completed_fence', 'known_prior_sealed_old_member_only', 'known_prior_source_bound_full_A_origin', 'known_prior_successful_fixed_segments_only', 'known_prior_typed_full_metadata', 'known_prior_whole30', 'late_scope_A_origin_PC_original', 'late_scope_A_origin_SOURCE_None', 'late_scope_A_origin_actual_boot', 'late_scope_A_origin_every_full_source_F9', 'late_scope_A_origin_exact_complete_source', 'late_scope_A_origin_held_after', 'late_scope_A_origin_same_static_source', 'late_scope_SOURCE_None_harddeny', 'late_scope_actor_actual_held_validator', 'late_scope_actor_current_context_and_owned_nonce', 'late_scope_actor_not_body_selected', 'late_scope_actor_source_F9_after', 'late_scope_actual_A_fullsource_SHA_F9', 'late_scope_actual_internal_current_Root_receipt', 'late_scope_actual_request_nonce', 'late_scope_derived_fixed_namespace', 'late_scope_empty_repair_internal_original_no_active_work', 'late_scope_exact_source_pin', 'late_scope_final_real_now_original_BEGIN_whole30', 'late_scope_fixed_history_no_caller_actor', 'late_scope_fixed_template_bundle', 'late_scope_full_A_prepublication_source_set', 'late_scope_full_BEGIN_original', 'late_scope_held_source_F9_after_full_consumer', 'late_scope_history_same_source_not_new_PID_authority', 'late_scope_internal_new_source_review', 'late_scope_new_packet_config_current118', 'late_scope_only_pinned_source_or_stdlib', 'late_scope_original_A_raw_F9', 'late_scope_original_qualified_not_restamped_copy', 'late_scope_owned_current_actor_only', 'late_scope_rederived_complete_PC_source_bytes', 'late_scope_same_private_grant_lock', 'late_scope_template_original_fullbytes', 'layer_algorithm', 'layer_descriptor', 'legacy_Root94_all_immutable_originals', 'legacy_Root_plan_qualification_originals', 'legacy_Root_plan_reference', 'legacy_actor_exact_operation_family', 'legacy_actor_full_F9_stable_across_Root_reads', 'legacy_actor_originals_unchanged_before_normal_release', 'legacy_full_original_actor_bytes', 'legacy_one_failed_stage_no_new_outputs', 'legacy_original_pulse_reservation_causal_binding', 'legacy_original_reserved_Runtime_source', 'legacy_original_window_never_rebased', 'legacy_stage_actual_leaf_owner_FD', 'legacy_stage_complete_original_cap', 'legacy_stage_directory_FD_named_entries_after', 'legacy_stage_fixed_directory_F9_entries', 'legacy_stage_flat_bounded_entries', 'legacy_stage_held_named_stable_after_read', 'legacy_stage_original_exact_SHA_F9', 'legacy_stage_owned_directory_exact', 'legacy_stage_policy_SOURCE_pending', 'literal_worker_identity', 'live_Guard_accepts_exact_current_CLEAR', 'live_actual_PC_source_F9', 'live_idle_shared_all_work_zero', 'live_same_physicallease_current118', 'native_duration_schema', 'negative_current_source_and_oldfacts', 'negative_hook_source_pending', 'negative_never_CPU_success_or_replay', 'new_C_ARM_once_namespace', 'new_PID_current118_config_original_physicallease', 'new_PID_source_activation_once_no_duplicate_mkdir', 'new_actual_entry_nonce', 'new_current118_source_review', 'new_finite_stage_not_replay', 'new_operation_literal', 'new_output_must_be_empty', 'new_output_named_identity_or_size_drift', 'new_output_write_progress', 'new_owned_Guard_PID_not_filesystem_CAS_claim', 'new_owned_empty_segment', 'new_ownstop0_unlink0_CAS2_start1_not_replay6279', 'new_qualified_Root_only', 'new_readonly_Root_origin', 'new_readonly_nonce', 'new_registry_source_idleattach_pending', 'new_registry_whole_factory_source_pending', 'new_run_derived_actual_producer_witness_only', 'new_scope_request_policy', 'new_shared_raw4MiB', 'new_stage_segment_directory_empty', 'new_unbound_C_run_only', 'newsource_history_original_times_sameboot_distinctPID', 'no_C24_completed_or_omitted_original', 'no_ambiguous_range_redirect_or_multipart', 'no_duplicate_or_overlapping_ranges', 'no_stage_clock_callbacks', 'no_work_entered_during_current_idle_IO', 'node_release_unconfirmed_core_hold_retained', 'nonfinite', 'nonfinite_JSON', 'nonfinite_clock', 'nonfinite_json', 'nonfinite_source_or_proof', 'not_launched_A_local_whole30', 'not_launched_MAC_mirror_distinct_origin', 'not_launched_PC_Root_shared_original', 'not_launched_PC_final_SOURCE_pending', 'not_launched_PC_history_SOURCE_pending', 'not_launched_PC_nonce_clock_chain', 'not_launched_PC_single_domain_whole30', 'not_launched_Root_SOURCE_pending', 'not_launched_Root_anchor', 'not_launched_Root_directory', 'not_launched_Root_packed_origin_table', 'not_launched_absence_parent_stable', 'not_launched_actor_exact_old_owner_source', 'not_launched_actor_fullF9', 'not_launched_actual_old_actor_unchanged', 'not_launched_actual_packed_full_F9_SHA', 'not_launched_actual_plan_context', 'not_launched_actual_service999_release', 'not_launched_clock_current_SOURCE_pending', 'not_launched_control_directory_F9', 'not_launched_control_directory_originals', 'not_launched_control_raw_F9', 'not_launched_current_SOURCE_pending', 'not_launched_current_full118_epoch', 'not_launched_current_new_source_not_history', 'not_launched_data_positive_ENOENT', 'not_launched_directory_F9', 'not_launched_directory_named_FD', 'not_launched_exact53_control18', 'not_launched_exact_entries', 'not_launched_exact_fresh_request', 'not_launched_exact_legacy_pending_not_other_work', 'not_launched_exact_original', 'not_launched_exact_qualified_type', 'not_launched_finish_actual_same_request', 'not_launched_finish_same_current', 'not_launched_full_PC_clock_originals', 'not_launched_full_control_directories', 'not_launched_full_decoded_raw_SHA_not_packed_F9', 'not_launched_full_originals_recheck30', 'not_launched_full_root_ancestry', 'not_launched_full_source_control_binding', 'not_launched_historical_absence_not_success', 'not_launched_historical_control_identity', 'not_launched_historical_current_binding', 'not_launched_history_SOURCE_pending', 'not_launched_history_before_fresh_collection', 'not_launched_is_not_EXIT0', 'not_launched_kernel_PID_role', 'not_launched_kernel_before_finished', 'not_launched_launch_intent_not_actual_launch', 'not_launched_no_extended_PC_whole30', 'not_launched_no_fabricated_worker_or_success', 'not_launched_normal_release_once', 'not_launched_old_Root97_and_dynamic_originals', 'not_launched_original_Root97_fullraw_F9', 'not_launched_original_Root_plan', 'not_launched_original_SHA_F9', 'not_launched_original_actor3', 'not_launched_original_deadline_and_pulse_causal', 'not_launched_original_dynamic_Root_fullraw_F9', 'not_launched_packed_history_SOURCE_pending', 'not_launched_packed_origins_stable_after_current', 'not_launched_parent_identity', 'not_launched_payload_present_unknown', 'not_launched_positive_current_payload_absence', 'not_launched_real_PC_clock', 'not_launched_release_SOURCE_pending', 'not_launched_review_SOURCE_pending', 'not_launched_same_protected_clock_receipt_after_current', 'not_launched_same_sole_Runtime_lease_source', 'not_launched_saved_ownedstop_originals', 'not_launched_saved_ready_EXIT0_ownedstop', 'not_launched_saved_ready_identity', 'not_launched_service_recovery_directory', 'not_launched_source_F9', 'not_launched_source_index_exact_closure', 'not_launched_static_packed_source_SHA', 'not_launched_target_executable', 'not_launched_target_process', 'not_launched_typed_current_identity', 'not_launched_typed_current_source', 'oci_config_descriptor', 'oci_manifest', 'old180_negative_only_not_current_cfg_execution', 'old_ancestor_not_NEW_source_or_PID', 'old_candidate_original_validator_no_refresh', 'old_directory_changed_at_open', 'old_directory_changed_during_read', 'old_domain_exact_spent_interval', 'old_failed_history_changed', 'old_failure_before_stop_exact', 'old_file_fullF9', 'old_original_owner_intent', 'old_private_directory', 'old_private_directory_changed', 'old_source_binding_unchanged', 'old_spec_not_rebased', 'old_stop0_changed_before_new_attempt', 'old_stop0_exact_two_entries', 'old_stop0_raw_identity', 'old_validator_operation_not_new_grant', 'once_attempt_already_exists_no_replay', 'one_bounded_request', 'one_controller_only', 'one_negative_ancestor_view', 'one_original_range_redirect', 'one_range_noRetry', 'one_redirect_location', 'one_sole_factory_no_old_reserve_resume', 'one_wire_other117_not_arbitrary_profile', 'only_fixed_new_stage_segment_path', 'only_original_Bridge_historical_block', 'operator_EOF', 'operator_command_inflight', 'operator_schema', 'operator_socket_exists_refuse', 'operator_still_alive_keep_stores_lease', 'ordered_disjoint_blob_segments', 'origin_only_bearer', 'original_C_controller_unbound', 'original_FD_extra_EOF', 'original_FD_truncation', 'original_PC_stage_plan_deadline_no_rebase', 'original_R4_validator_closure', 'original_authenticated_C_caller_not_Root_impersonation', 'original_deadline_can_only_shorten', 'original_directories_unchanged_at_share', 'original_disk_reserve100GiB', 'original_dns_host', 'original_finite_window', 'original_first_PC_journal_empty_no_specific_PC_cause', 'original_fresh_stamp', 'original_full_SHA_F9', 'original_historical_validator_source_fullSHA_F9', 'original_observation_order_no_restamp', 'original_operation_source_not_new_recovery', 'original_owner_private_socket', 'original_parent_or_grant_window_expired_no_extension', 'original_partial_exact_directory', 'original_private_status_positive', 'original_pulse_time_order_no_retime', 'original_raw_and_actual_mirror_F9_not_origin_substitution', 'original_same_physical_FD_named', 'original_source_changed', 'original_structured_raw_exact', 'original_window_expired_or_clock_invalid', 'original_window_insufficient_for_IO_cap', 'original_worker_PID_still_exists_unknown', 'owned_CG_nonempty_unknown', 'owned_CG_symlink_unknown', 'owned_CG_tree_drift', 'owned_HTTP_close_failed', 'owned_target_executable_observed', 'owned_target_process_observed', 'owner_new_activation_Rootpeer_ABI', 'owner_new_source_pending_exact_state', 'owner_new_source_qualification_stable', 'owner_original_prior_released_history_only', 'owner_pending_only_new_source_activation_no_asset_action', 'owner_prior_full_history_stable', 'owner_service_once_activation_directory', 'owner_source_activation_once_not_old_request_replay', 'packet4MiB_unchanged', 'paired_original_parent_window_bound_not_bool', 'parent_changed', 'parent_window_missing_or_expired', 'partial_assets_preserved_not_whole_blob_count', 'partial_drift_after_readonly_status', 'peer_in_current_original_dns', 'peer_proof_schema', 'permit_source_and_old_full_originals', 'phase_history_service_actual_gate_pin', 'physical_full_old_registry_consumed_not_hash_assertion', 'physical_lease_held', 'pidfd_acquire_unsupported_or_unknown', 'pidfd_poll_unknown_event', 'pidfd_poll_unsupported_no_fallback', 'pinned_actual_generic_shutdown_logger', 'positive_actual_CAS_old_to_new_exact', 'positive_current_idle_Root_reply', 'positive_fixed_CG_ENOENT', 'positive_guard_CLEAR_required', 'positive_original_PID_ENOENT', 'positive_retained_original_not_collected_guess', 'postCAS_lineage_small_ref_full_consumer_still_required', 'poststop_CG_complete_listing', 'poststop_CG_directory_identity', 'poststop_CG_full_original_nonempty', 'poststop_CG_no_listing_drift', 'poststop_CG_no_missing_child', 'poststop_absent_CG_no_fabricated_tree', 'poststop_actual_kernel_time_order', 'poststop_collected_exact_missing_not_success_alone', 'poststop_complete_CG_node', 'poststop_exact_kernel_identity', 'poststop_fixed_CG_bounded', 'poststop_kernel_anchor_schema', 'poststop_kernel_anchor_stable_identity', 'poststop_kernel_full_F9_type', 'poststop_kernel_fullraw_SHA', 'poststop_loaded_same_original_invocation', 'poststop_not_active_or_unknown', 'poststop_only_fixed_CG_tree', 'poststop_original_PID_positive_ENOENT', 'poststop_original_unit_raw_keys', 'poststop_positive_kernel_anchors', 'poststop_same_boot_originals', 'poststop_unknown_CG_state', 'prelaunch_path_exists_or_symlink', 'preserve6279_stop0_CAS2_start0', 'preserved_partial_blob_identity_only', 'prestart_actor_parent_SOURCE_pending', 'prestart_completed_history_still_original', 'prestart_exact_old_child_directory', 'prestart_history_SOURCE_pending', 'prestart_history_original_Root97', 'prestart_history_original_dynamic_Root', 'prestart_history_pending_actor_original', 'prestart_immutable_completion_not_raced', 'prestart_old_parent_held_named_stable', 'prestart_old_parent_stable_across_actor', 'prestart_only_exact_old_stage_no_unknown_sibling', 'previous_directory_changed', 'previous_failed_before_stop', 'previous_failed_directory_F9', 'previous_original_owner_intent', 'previous_raw_F9', 'previous_stop0_exact_two', 'previous_stop0_raw_changed', 'prior95aa_historical_not_current004bc', 'prior_Root77_source_fullF9_preserved', 'prior_ancestor_stable_identity', 'prior_before_source_pending', 'prior_current_actual_Code2_not_true_EXIT0', 'prior_failed_not_relabelled_success', 'prior_old_bytes_not_rebased', 'prior_private_actual_raw_fullF9', 'prior_private_exact_fullFD_named_entries', 'prior_private_mirror_raw_SHA', 'prior_private_original_exact_schema', 'prior_real_live_intent_and_consumed_stop', 'prior_scope_actual_EXIT1_preserved', 'private_CPU_activation_pending', 'private_CPU_not_attached', 'private_existing_run', 'private_operator_root_required', 'private_original_metadata', 'private_success_run', 'private_terminal_original', 'proc_churn_not_closed_within_bound', 'proc_directory_drift', 'proc_directory_identity', 'proc_identity_IO_or_permission_unknown', 'proc_leaf_not_regular', 'proc_leaf_raw_cap', 'proc_lifetime_accounting_full_identity', 'proc_lifetime_complete_bounded_events', 'proc_lifetime_current_no_target', 'proc_lifetime_current_replacements_closed', 'proc_lifetime_event_identity', 'proc_lifetime_every_event_accounted', 'proc_lifetime_exact_partial_originals', 'proc_lifetime_full_identity', 'proc_lifetime_kernel_ESRCH_required', 'proc_lifetime_live_complete', 'proc_lifetime_no_skipped_enumerated_PID', 'proc_lifetime_observed_directory_not_handle_binding', 'proc_lifetime_original_SHA_cap', 'proc_lifetime_original_base64', 'proc_lifetime_original_type', 'proc_lifetime_partial_executable', 'proc_lifetime_positive_exit_required', 'proc_lifetime_procFD_identity', 'proc_lifetime_retained_partial_keys', 'proc_lifetime_rootFD_identity', 'proc_lifetime_round_pid_set', 'proc_lifetime_round_schema', 'proc_lifetime_schema', 'proc_lifetime_stable_complete_originals', 'proc_lifetime_target_exe', 'proc_lifetime_target_original', 'proc_missing_while_handle_live_unknown', 'proc_root_identity_drift', 'proc_stat_malformed', 'proc_stat_pid_unsigned_starttime', 'process_executable_drift', 'process_identity_drift_unknown', 'proof_current_PC_source', 'protected_C_ARM_service_state', 'protected_existing_parent', 'public_ipv4_dns', 'qualified_actual_generation_not_request_selected', 'qualified_openssl_required', 'qualified_original_directory_full_provenance', 'range_HTTP206_required', 'range_authority_None', 'range_exchange_failed', 'range_failed_noRetry', 'range_metadata_deadline', 'range_origin_only_bearer', 'range_safe_token', 'range_token_safe_before_send', 'range_true_EOF_required', 'range_truncation_or_chunk', 'readonly_accepted_segment_sources_pending', 'readonly_current_source_never_model_or_installation_success', 'readonly_own_true_kernel_scope_identity', 'readonly_phase_absolute_budget', 'readonly_segments_unchanged', 'real_frozen_ancestor_qualification_pending', 'receipt_EOF_no_trailing_no_bomb', 'receipt_compressed_fixed1MiB', 'receipt_raw_exactbytes_fixed4MiB', 'receipt_zlib_CRC_or_stream', 'registry_C_gate_not_open', 'registry_actual_file_scope_terminal_not_quality', 'registry_actual_new_epoch_Core_baseline', 'registry_actual_same_owner_FD', 'registry_actual_shared_C_wrapped_calls', 'registry_attached_once', 'registry_command_alive_retain_original_runtime_lease', 'registry_current_Core_no_fake_generation', 'registry_current_nodes_noholds_noQUAR', 'registry_exact_once_entries', 'registry_grant_preparation_deadline', 'registry_held_directory_drift', 'registry_historical_finish_bound', 'registry_historical_original_terminal_not_service_owned_bool', 'registry_historical_pulses_original', 'registry_new_once_not_old_bf84', 'registry_original_999_leaf', 'registry_original_fullF9_stable', 'registry_original_negative_fence_not_released', 'registry_physical_lease_held', 'registry_private_command_inflight', 'registry_private_service_directory', 'registry_pulse_deadline', 'registry_real_typed_negative_release_required', 'registry_same_lock_all_counters', 'registry_same_sole_runtime_not_new_Bridge', 'registry_source_pending', 'registry_unknown_or_expired_hold_retained', 'registry_unresolved_hold_retain_original_runtime_lease', 'registry_unresolved_or_closing', 'released_Guard_accepts_same_record', 'released_container_inactive_known', 'released_whole_empty_GPU', 'remote_stamps_within_actual_configured30', 'renewal_complete_exact_final_source_set', 'renewal_complete_source_F9', 'renewal_threshold', 'renewal_worker_source_pending', 'request_deadline', 'request_exact_current_epoch', 'retained_stage_owned_scope_no_retry', 'retained_success_archive_then_actual_owned_stop', 'retained_true_EXIT0_exact_worker_boot_invocation', 'retained_unit_original_raw', 'reviewed_R26_source_pending', 'reviewed_failed_registry_policy_pending', 'root_operator_configuration_changed', 'safe_registry_error_action', 'same_PC_whole30_historical_interval', 'same_activation_current_witness', 'same_actual_boot_after_kernel', 'same_actual_boot_before_kernel', 'same_actual_localA_entry_source_and_order', 'same_actual_owner_not_admin_impersonation', 'same_bound_C_run', 'same_complete_new_request_no_replay_or_retime', 'same_current_C_released_core', 'same_existing_runtime', 'same_existing_stage_not_new_window', 'same_full_original_current_idle_request_reply', 'same_lock_all_work_and_lifecycle_counters', 'same_newrun_source_completed', 'same_original_Runtime_Adapter_Manager', 'same_original_body_limit', 'same_original_generic_logger_not_unknown_shutdown_pattern', 'same_original_installed_raw_and_distinct_actual_mirror_F9', 'same_original_remote_clock', 'same_original_unit_new_live_invocation', 'same_owned_scope_actual_stop0_not_bool', 'same_owner_new_nonce', 'same_private_operation_lock', 'same_runtime_Controller_scheduler_physical_lease', 'same_stopped_old_owner_invocation', 'same_worker_source_and_invocation', 'scope_same_boot_invocation_PID_source_emptyCG', 'scope_same_exact_exec', 'segment_exact_EOF', 'segment_held_named_F9', 'segment_read_progress', 'segment_readback_fullSHA', 'segment_receipt_original_fullF9', 'selected_segment_actual_SHA_F9', 'shared_complete_readback', 'shared_distinct_physical_F9_and_exact_source_origin', 'shared_lock_Core_matches_genuine_Node_baseline', 'shared_stage_clock_FD_identity', 'single_C_start_after_ARM', 'single_sole_maintenance_operation', 'small_index', 'sole_factory_before_serving_all_counters_empty', 'source_activation_cannot_release_unknown_stage_hold', 'source_bound_counts', 'source_bound_new_and_old_summary', 'source_bound_readonly_A_worker_pending', 'source_held_original_stage_plan_for_segment', 'source_history_not_fresh_admission', 'source_lease_drift_after_collect', 'source_operation_interval_bound_accepted_receipt', 'stage_actual_cleanup_aggregate_caps', 'stage_actual_context_intent_unit_identity', 'stage_actual_fixed_aggregate', 'stage_actual_owned_cleanup_not_forced', 'stage_actual_private_budget', 'stage_actual_runtime_IO_source', 'stage_cleanup_exact_supervisor', 'stage_cleanup_whole_process_tree', 'stage_clock_named_held_identity', 'stage_clock_protected_readback', 'stage_clock_write_progress', 'stage_complete_owned_CG_subtree', 'stage_directory_service_identity', 'stage_domain_controller_tree', 'stage_entry_origin_complete', 'stage_entry_real_origin', 'stage_exact_original_leaf', 'stage_exact_original_records_before_finish', 'stage_history_exact_entries', 'stage_initial_kernel_owned_bootstrap', 'stage_initial_unit_fullraw_identity', 'stage_kernel_CPU1', 'stage_kernel_actual_IO60M', 'stage_kernel_exact_IO_fields', 'stage_kernel_memory_swap_tasks', 'stage_kernel_only_owned_IO_device', 'stage_no_old_or_foreign_hold', 'stage_no_payload_left', 'stage_only_selected_outputs', 'stage_only_supervisor_before_exit', 'stage_origin_Root600_fullF9', 'stage_original_deadline', 'stage_original_deadline_reservation_not_rebased', 'stage_original_directory_identity_and_entries', 'stage_original_held_named_F9', 'stage_original_raw_F9', 'stage_original_service_fullF9', 'stage_plan_current_runtime_not_historical_permit', 'stage_prepare_consumes_original_window', 'stage_root_empty_and_limited', 'stage_root_service_identity', 'stage_scope_context_kernel_actual_time', 'stage_terminal_PC_Root_shared_origin', 'stage_terminal_SOURCE_pending', 'stage_terminal_complete_schema', 'stage_terminal_context_actual_owned_pulse', 'stage_terminal_exact_Root_plan', 'stage_terminal_exact_current_epoch', 'stage_terminal_fixed_source_not_root_bool', 'stage_terminal_quiescence_freshness', 'stage_terminal_unit_fullraw_SHA', 'stage_work_expired_sticky', 'startup_diagnostic_actual_invocation', 'startup_diagnostic_original_service_identity', 'startup_diagnostic_private_directory', 'stat_only_must_not_claim_content_SHA', 'stop_original_full_SHA', 'stop_unconfirmed_holds_retained', 'stopped_Root_type_not_fake_scheduler', 'stopped_actual_old_source_and_identity', 'stream_ordered_segments', 'stream_segment_progress', 'strict_actual_local_budget_inputs', 'strict_actual_manager_identity', 'strict_actual_process_identity', 'strict_bounded_parent_duration_no_new1800', 'strict_full_F9', 'strict_priorstop1_ownstop0', 'strict_receipt_base64', 'strict_source_or_proof_refused', 'successful_stage_normal_ownedstop', 'terminal_A_same_request_no_retime', 'terminal_PC_local_conservative_age30', 'terminal_clock_current_request', 'terminal_clock_original_send_binding', 'terminal_directory_changed', 'terminal_local_full_original_chain', 'terminal_original_PC_whole30_not_crosshost_wall', 'terminal_original_changed', 'terminal_received_PC_clock_interval', 'token_file_schema', 'token_lifetime_scope', 'token_or_window_too_short', 'token_request_state', 'token_safe_after_bounded_metadata_before_send', 'token_safe_before_first_send', 'token_shape', 'token_supply_failed', 'token_supply_limit', 'true_owned_retained_EXIT0', 'truncated_blob', 'typed_negative_callback', 'typed_new_completed', 'typed_partition_and_originating_IO_identity', 'typed_runtime_qualification', 'unaltered_stopped_unit_original', 'unambiguous_range_identity_framing', 'unclassified_exit_not_known_non_target', 'unexpected_http_tail', 'unique_actual_unit_fields', 'unique_finite_stage_operation', 'unique_stage_clock_namespace', 'unknown_old_from_import', 'unknown_old_import', 'unknown_private_import', 'whole96_history9_not_projection', 'whole_AB', 'whole_PC_current_readonly30_no_retime', 'whole_body_deadline', 'whole_compressed_descriptor_SHA', 'whole_deadline', 'whole_old_A_failure_raw_F9_not_count', 'whole_original_SHA', 'whole_original_entry_clock_not_republished', 'whole_preserved_failed_A_file_SHA_F9', 'whole_regular_bounded_raw', 'whole_rows_original', 'whole_scheduler_idle', 'whole_window_Core_and_AB_baseline_fixed', 'whole_window_Core_generation_drift', 'zero_launch_actual_held_actor3_unchanged', 'zero_launch_actual_packed_SHA_named_F9', 'zero_launch_actual_packed_origin_manifest', 'zero_launch_actual_source_pending_only', 'zero_launch_actual_still_owned_three_actor_bytes', 'zero_launch_complete_actual_publication_original', 'zero_launch_duplicate_key', 'zero_launch_exact_A_history_argument', 'zero_launch_exact_history_arguments', 'zero_launch_exact_old_current_and_interval', 'zero_launch_exact_saved_bind_before_context_namespace', 'zero_launch_exact_three_actor_originals', 'zero_launch_exact_typed_history_no_fabricated_context', 'zero_launch_existing_activation_private_lock', 'zero_launch_final_real_now_same_whole30', 'zero_launch_frozen_complete_originals_pending', 'zero_launch_full_raw_SHA_F9', 'zero_launch_full_uncompressed_original_SHA', 'zero_launch_historical_proof_event_time_not_future_authority', 'zero_launch_history_absolute_Root', 'zero_launch_immutable_completed_causal_chain', 'zero_launch_internal_Runtime_identity', 'zero_launch_no_foreign_pending_namespace', 'zero_launch_nonfinite', 'zero_launch_notfound_is_not_EXIT0', 'zero_launch_old_actor_original_F9_after', 'zero_launch_old_actor_original_F9_before', 'zero_launch_old_operation_remains_spent', 'zero_launch_original_activation_Rootpeer_ABI', 'zero_launch_original_completed_histories_stable', 'zero_launch_original_owner_plan_deadline_pulse', 'zero_launch_original_shape', 'zero_launch_packed_mirror_actual_Root_F9', 'zero_launch_parent_directory_stable', 'zero_launch_pending_no_foreign_overlap', 'zero_launch_pinned_old_actor_F9_None', 'zero_launch_previous_ffc2_history_only_not_release', 'zero_launch_private_recovery_parent', 'zero_launch_protected_history_root_pending', 'zero_launch_qualified_SOURCE_None', 'zero_launch_range_release_only_no_launch', 'zero_launch_ranges_have_one_current_owner', 'zero_launch_ready_ownedstop_success_only', 'zero_launch_real_ready_current_and_nonce', 'zero_launch_recovery_SOURCE_None', 'zero_launch_recovery_exact_four_records', 'zero_launch_release_only_via_source_activation', 'zero_launch_remove_only_current_exact_ranges', 'zero_launch_same_PC_A_Root_plan', 'zero_launch_saved_ready_ownedstop_full_originals', 'zero_launch_saved_ready_source', 'zero_launch_saved_source53_fullSHA_F9', 'zero_launch_service999_once_not_retry', 'zero_launch_single_history_policy', 'zero_launch_source_qualification_unchanged', 'zero_launch_type_not_partial_or_success', 'zero_scope_Root_raw_SHA_F9', 'zero_scope_SOURCE_None', 'zero_scope_archive_owned_stop_once', 'zero_scope_exact_fresh_type_nonce', 'zero_scope_exact_pinned_readonly_worker', 'zero_scope_fresh_poststop_kernel', 'zero_scope_full_original', 'zero_scope_inner_request_nonce', 'zero_scope_real_saved_ownedstop_not_count', 'zero_scope_reviewed_SOURCE_None')

def _record_startup_refusal(error, step, config):
    import re
    need(os.getuid() == os.geteuid() == 999 and os.getgid() == 989, 'startup_diagnostic_original_service_identity')
    inv = os.environ.get('INVOCATION_ID', '')
    need(re.fullmatch('[0-9a-f]{32}', inv), 'startup_diagnostic_actual_invocation')
    need(step in ('load_config', 'Controller', 'Bridge', 'HistoricalNegative', 'CArmGate', 'RegistryGrant', 'private_listener'), 'fixed_startup_diagnostic_stage')
    root = ROOT / ('startup-refusals-' + _STARTUP_OPERATION)
    if not root.exists():
        root.mkdir(mode=448)
    st = root.lstat()
    need(stat.S_ISDIR(st.st_mode) and (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (999, 989, 448), 'startup_diagnostic_private_directory')
    reason = str(error) if type(error).__name__ == 'Refused' and str(error) in _STARTUP_SAFE_REASONS else None
    kind = type(error).__name__
    kind = kind if kind in ('Refused', 'ValueError', 'TypeError', 'RuntimeError', 'FileNotFoundError', 'PermissionError', 'OSError', 'KeyError', 'AttributeError') else 'OtherException'
    value = {'schema': 'R10-R3-startup-first-refusal/v1', 'operation': _STARTUP_OPERATION, 'source_review_sha256': _STARTUP_REVIEW, 'config_sha256': config['_config_sha256'] if type(config) is dict and type(config.get('_config_sha256')) is str else None, 'actual_PID': os.getpid(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': inv, 'step': step, 'error_type': kind, 'source_reason': reason, 'observed_at': time.time(), 'diagnostic_only': True, 'automatic_retry': False}
    exclusive(root / (inv + '.json'), value)
