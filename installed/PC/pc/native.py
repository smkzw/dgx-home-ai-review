# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Root PC actual IO implementation. No Manager construction or model calls."""
import base64, fcntl, json, os, platform, re, socket, stat, time, types
from pathlib import Path
from contract import *
from bounded_process import capture
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read, HeldParent, metadata
APPROVED_INPUT_PINS = None
APPROVED_OLD_CONFIG_SHA = '2ff3afad2450db95f757cf44630f69fa7326128753f4308aa393998eb6554659'
APPROVED_NEW_CONFIG_SHA = 'ae1bb28271dd45609152b4d3e610a8b7b5b4c3c0529432791d74c64b36d2a24f'
APPROVED_HISTORY_IDENTITY = {'boot_id': 'redacted-2606f3e07a03', 'invocation_id': '00e0dc737d47d6039a7edd3ed288fa34', 'pid': 833356, 'start_ticks': '14311588'}
APPROVED_STOPPED_LIVE_IDLE_SHA = '90660dd9c97e7e2cc9e1de911d42765f35aae19a90925cc5dc553769bbab71ed'
APPROVED_PRESTART_PROBE_SHA = 'be531e022700e3eba74ae02d3fd9c224de1a62ce28fa5e57b86218925802cc40'
HERE = Path(__file__).resolve().parent

class RootNative:
    BOOT = BOOT

    def __init__(self, packet, *, old=True):
        need(type(old) is bool, 'exact_typed_old_phase')
        self.fixed_Root_identity()
        need(APPROVED_INPUT_PINS is not None and APPROVED_OLD_CONFIG_SHA is not None and (APPROVED_NEW_CONFIG_SHA is not None), 'native_actual_source_pending')
        self.packet = packet
        self.command_count = 0
        self.old = old
        self.stopped_mode = False
        self.after_cas = False
        self.before_cas = {}
        self.current = self.reader(old)

    def fixed_Root_identity(self):
        need(os.getuid() == os.geteuid() == 0 and platform.system() == 'Linux' and (platform.node() == 'vicky'), 'fixed_Root_PC_only')

    def module(self, name, relative):
        raw, st = protected_read(HERE / relative, limit=2097152)
        need(sha(raw) == APPROVED_INPUT_PINS[relative], 'actual_held_Native_source')
        m = types.ModuleType(name)
        m.__file__ = str(HERE / relative)
        exec(compile(raw, m.__file__, 'exec'), m.__dict__)
        return m

    def reader(self, old):
        m = self.module('registry_Root_current_reader', 'current_reader.py')
        m.APPROVED_INPUT_PINS = APPROVED_INPUT_PINS
        m.APPROVED_OLD_CONFIG_SHA = APPROVED_OLD_CONFIG_SHA
        m.APPROVED_CONFIG_SHA = APPROVED_NEW_CONFIG_SHA
        return m.CurrentReader(APPROVED_OLD_CONFIG_SHA if old else APPROVED_NEW_CONFIG_SHA)

    def wall(self):
        return time.time()

    def pid(self):
        return os.getpid()

    def record(self, name, value):
        need(re.fullmatch('[A-Za-z0-9_.-]+', name), 'fixed_record_name')
        self.current.io.fresh(STATE / (name + '.json'), encode(value))

    def namespace_absent(self):
        need(not STATE.exists() and (not STATE.is_symlink()), 'new_epoch_namespace_absent')

    def create_state(self):
        STATE.mkdir(mode=448)
        os.chmod(STATE, 448)
        self.current.io.sync(STATE.parent)

    def historical_ancestor(self, p):
        from ancestor import consume
        raw, st = protected_read(Path('/opt/dgx-v4/hx/mimo-registry-native-r26/historical/raw/old-config'))
        need(st[3:7] == [0, 989, 33056, 1] and APPROVED_HISTORY_IDENTITY is not None, 'actual_historical_config_and_identity')
        return consume(protected_read, raw, APPROVED_HISTORY_IDENTITY, self.wall())

    def capture(self, end, old=True):
        self.current = self.reader(old)
        self.old = old
        return self.current.capture(end)

    def capture_stopped(self, end):
        need(self.current.config['_config_sha256'] == (APPROVED_OLD_CONFIG_SHA if self.old else APPROVED_NEW_CONFIG_SHA), 'stopped_reader_exact_phase_config')
        return self.current.capture_stopped(end)

    def command(self, argv, seconds):
        self.command_count += 1
        return capture(argv, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/srv/dgx-home-ai/hx-service', 'PYTHONDONTWRITEBYTECODE': '1'}, deadline=time.monotonic() + seconds, cap=2097152)

    def normal_unit_policy(self):
        return self.current.helpers.unit_constraints(self.current.io)

    def current_unarmed_idle(self, end):
        if self.stopped_mode:
            return self.stopped_node_observation(end)
        action = 'status-registry-source'
        body = {'action': action, 'operation': self.packet['old_grant_operation'] if self.old else OPERATION, 'request_nonce': __import__('uuid').uuid4().hex}
        raw = encode(body)
        sent = self.wall()
        mono = time.monotonic()
        with self.current.connect(min(90, end - mono)) as conn:
            pid, uid, gid = __import__('struct').unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(uid == 999 and gid == 989 and (self.current.io.holders() == [pid]), 'same_service_socket_peer_current_FLOCK')
            conn.sendall(raw)
            reply = bytearray()
            while b'\n' not in reply:
                need(time.monotonic() < end and len(reply) <= 1048576, 'actual_private_reply_deadline_cap')
                part = conn.recv(min(65536, 1048577 - len(reply)))
                need(part, 'actual_private_reply_EOF')
                reply.extend(part)
        need(reply.count(b'\n') == 1 and reply.endswith(b'\n'), 'single_strict_original_Root_reply')
        out = strict(reply)
        need(out['ok'] is True, 'current_private_RPC_refused_not_historical_bool')
        value = out['result']
        need(value['request_nonce'] == body['request_nonce'] and sent <= value['observed_at'] <= self.wall(), 'current_private_RPC_original_clock')
        need(value['operation'] == (self.packet['old_grant_operation'] if self.old else OPERATION) and value['source118'] == self.packet['oldmap' if self.old else 'newmap'] and (value['manager_pid'] == pid), 'actual_current_source_status_not_old_PID')
        return {'request_raw_utf8': raw.decode(), 'reply_raw_utf8': bytes(reply).decode(), 'observed_at': self.wall(), 'PC_sent_at': sent, 'PC_monotonic_elapsed': time.monotonic() - mono}

    def stopped_node_observation(self, end):
        return self.live_idle_observation(end)

    def sealed_helpers(self, p):
        need(set(p['helpers']) == set(APPROVED_INPUT_PINS['service_helpers']), 'exact_new_helper_leaf_set')
        for name, pin in p['helpers'].items():
            need(name in APPROVED_INPUT_PINS['service_helpers'] and pin == APPROVED_INPUT_PINS['service_helpers'][name], 'exact_helper_source_literal')
            raw, st = protected_read(PC_ROOT / 'service' / name, limit=2097152)
            need(sha(raw) == pin and st[3:7] == [0, 989, 33056, 1], 'actual_UID999_readable_Root_helper_not_UMask700')
        d = (PC_ROOT / 'service').lstat()
        need((d.st_uid, d.st_gid, stat.S_IMODE(d.st_mode)) == (0, 989, 488), 'actual_fixed_helper_dir_UID999_traversable')

    def backup_originals(self, p, before):
        for target, name in ((WIRE, 'wire'), (CONFIG, 'config')):
            raw, s = protected_read(target)
            self.current.io.fresh(STATE / ('old-' + name + '.raw'), raw)
            self.before_cas[str(target)] = (raw, s)
        unit, st = self.current.io.read(self.current.io.UNIT_PATH)
        self.unit_before = (unit, metadata(st))
        self.record('original-unit', {'raw_utf8': unit.decode(), 'sha256': sha(unit), 'stat': metadata(st)})

    def no_other_manager(self):
        self.current.io.no_other_manager()

    def lock_F9(self):
        return metadata(self.current.io.lock_identity())

    def holders(self):
        return self.current.io.holders()

    def lease(self):
        return self.current.io.lease()

    def release(self, fd):
        self.current.io.release(fd)

    def stopped(self, before, end):
        need(time.monotonic() < end and self.holders() == [], 'stopped_budget_and_original_freelease')
        need(self.unit_original() == self.unit_before, 'same_original_unit_leaf_fullF9')
        result = self.command(['/usr/bin/systemctl', 'show', UNIT, '--property=Id,LoadState,ActiveState,SubState,MainPID,ExecMainPID,ExecMainCode,ExecMainStatus,Result,InvocationID,NRestarts,ControlGroup'], 10)
        need(result.returncode == 0 and (not result.stderr), 'normal_stopped_unit_observation')
        u = dict((line.split('=', 1) for line in result.stdout.decode().splitlines()))
        journal = self.command(['/usr/bin/journalctl', '--no-pager', '-o', 'json', '_SYSTEMD_INVOCATION_ID=' + before['manager_identity']['invocation_id']], 10)
        need(journal.returncode == 0 and (not journal.stderr), 'complete_same_invocation_journal')
        classify = self.module('actual_prelaunch_stop', 'prelaunch_stop.py')
        pins = [v for v in before['current_source118'].values() if v == classify.LOGGER_SHA]
        need(len(pins) == 1, 'actual_pinned_composition_logger_source')
        kind = classify.classify(result.stdout, journal.stdout, before['manager_identity'], classify.LOGGER_SHA)
        need(kind['actual_exit_code'] in (0, 2), 'old_owned_shutdown_classified_not_success_relabel')
        need(not Path('/proc/' + str(before['manager_identity']['pid'])).exists() and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == before['manager_identity']['boot_id'], 'old_PID_gone_sameboot_no_second_start')
        self.no_other_manager()
        kernel = self.kernel_dead(before, end)
        self.stopped_mode = True
        self.stop_kernel = kernel
        self.normal_stopped_original = {'raw_utf8': result.stdout.decode(), 'sha256': sha(result.stdout), 'unit': u, 'journal_raw_utf8': journal.stdout.decode(), 'journal_sha256': sha(journal.stdout), 'classification': kind, 'composition_sha256': classify.LOGGER_SHA, 'observed_at': self.wall()}
        return self.normal_stopped_original

    def kernel_dead(self, before, end):
        need(time.monotonic() < end and (not Path('/proc/' + str(before['manager_identity']['pid'])).exists()), 'no_live_original_Manager')
        path = Path('/sys/fs/cgroup/system.slice/' + UNIT)
        rows = []
        if path.exists():
            for file in sorted(path.rglob('cgroup.procs')):
                raw = file.read_bytes()
                need(time.monotonic() < end, 'all_owned_CG_deadline')
                rows.append({'path': str(file), 'raw_utf8': raw.decode(), 'sha256': sha(raw)})
                need(raw.strip() == b'', 'whole_original_CG_empty_no_children')
        unix = Path('/proc/net/unix').read_text()
        owners = [x for x in unix.splitlines() if x.split() and x.split()[-1] == str(SOCKET)]
        need(owners == [], 'no_old_kernel_listener_or_socket_owners')
        self.no_other_manager()
        return {'owned_cgroup_processes': [], 'cgroup_originals': rows, 'original_CG_absent': not path.exists(), 'kernel_socket_owners': [], 'proc_net_unix_sha256': sha(unix.encode()), 'old_PID_absent': True, 'observed_at': self.wall()}

    def dead_socket(self, original):
        need(original['path'] == str(SOCKET), 'fixed_private_socket_path')
        rows = Path('/proc/net/unix').read_text().splitlines()[1:]
        need(not [r for r in rows if len(r.split()) == 8 and r.split()[7] == str(SOCKET)], 'dead_socket_not_live_kernel_listener')
        with HeldParent(SOCKET, legacy=True) as chain:
            s = chain.named_leaf()
            need(metadata(s) == original['stat'] and stat.S_ISSOCK(s.st_mode) and ((s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) == (999, 989, 384, 1)), 'same_original_dead_filesystem_socket')

    def unlink_socket(self, original):
        self.dead_socket(original)
        with HeldParent(SOCKET, legacy=True) as chain:
            need(metadata(chain.named_leaf()) == original['stat'], 'late_owned_socket_CAS')
            chain.recheck()
            os.unlink(SOCKET.name, dir_fd=chain.parent_fd)
            os.fsync(chain.parent_fd)

    def verify_before_CAS(self, path, pin, before):
        need(path in (WIRE, CONFIG), 'two_fixed_CAS_leaves_only')
        raw, st = protected_read(path)
        need(sha(raw) == pin and (raw, st) == self.before_cas[str(path)], 'Root_exact_old_leaf_fullF9_CAS')

    def CAS(self, path, raw):
        need(path in (WIRE, CONFIG), 'no_body_selected_write_target')
        old = self.before_cas[str(path)]
        need(protected_read(path) == old, 'late_CAS_leaf_changed')
        temp = path.parent / ('.' + path.name + '.registry-r26.tmp')
        self.current.io.fresh(temp, raw, mode=stat.S_IMODE(old[1][5]), gid=old[1][4])
        need(protected_read(path) == old, 'late_CAS_after_temp_write')
        os.replace(temp, path)
        self.current.io.sync(path.parent)
        newer, st = protected_read(path)
        need(newer == raw and st[3:7] == old[1][3:7], 'actual_CAS_newbytes_owner_mode_preserved')

    def verify_new_stopped(self, p, before, end):
        need(time.monotonic() < end and self.holders() == [self.pid()], 'same_stopped_owned_lease_before_check')
        for path, pin in p['newmap'].items():
            need(time.monotonic() < end, 'all118_scan_same_deadline')
            raw, st = protected_read(path)
            need(sha(raw) == pin and (path == str(WIRE) or st == before['source_files'][path]['stat']), 'all118_other117_F9')
        raw, st = protected_read(CONFIG)
        need(raw == p['new_config_raw_utf8'].encode(), 'actual_new_config_after_CAS')
        need(self.unit_original() == self.unit_before, 'original_unit_unchanged')
        self.current = self.reader(False)
        self.old = False
        self.after_cas = True

    def check_config(self, expected, operation, end):
        result = self.current.helpers.check_operator_config(self.current.io, expected, operation)
        need(time.monotonic() < end, 'actual_configcheck_absolute_budget')
        return result

    def wait_current(self, before, p, end):
        while time.monotonic() < end:
            u = self.current.io.unit()
            need(u['ActiveState'] in ('activating', 'active'), 'new_original_service_terminal')
            pid = int(u['MainPID'])
            holders = self.holders()
            need(not holders or (pid > 1 and holders == [pid] and (pid != before['manager_identity']['pid'])), 'only_new_sole_FLOCK')
            if pid > 1 and u['ActiveState'] == 'active' and (u['SubState'] == 'running') and (holders == [pid]) and SOCKET.exists():
                self.current = self.reader(False)
                self.old = False
                self.stopped_mode = False
                value = self.current.capture(end)
                need(value['manager_identity']['pid'] == pid, 'current_snapshot_same_new_sole')
                self.current.helpers.listener_auth(self.current.io, pid)
                return value
            time.sleep(0.1)
        raise Refused('new_sole_listener_deadline_no_retry')

    def unit_original(self):
        raw, st = self.current.io.read(self.current.io.UNIT_PATH)
        return (raw, metadata(st))

    def live_idle_observation(self, end):
        need(APPROVED_STOPPED_LIVE_IDLE_SHA is not None and self.holders() == [self.pid()], 'owned_stopped_current_idle_source_pending')
        path = PC_ROOT / 'pc/stopped_live_idle.py'
        raw, st = protected_read(path, limit=2097152)
        need(sha(raw) == APPROVED_STOPPED_LIVE_IDLE_SHA, 'held_actual_stopped_idle_producer')
        m = types.ModuleType('fixed_normal_epoch_live_idle')
        m.__file__ = str(path)
        exec(compile(raw, m.__file__, 'exec'), m.__dict__)
        need(hasattr(self, 'original_before'), 'normal_old_exit_before_current_idle')
        result = m.collect(self, self.packet, self.original_before, end)
        need(protected_read(path, limit=2097152) == (raw, st), 'producer_original_F9_after_collect')
        return result

    def await_C9(self, p, before, end):
        need(self.holders() == [self.pid()] and time.monotonic() < end, 'C9_own_original_lease')
        path = PC_ROOT / 'c-arm-r30/before_start.py'
        raw, st = protected_read(path, limit=2097152)
        need(sha(raw) == APPROVED_INPUT_PINS['cold_stage']['c-arm-r30/before_start.py'], 'fixed_C9_closed_source')
        m = types.ModuleType('fixed_C9_normal_epoch_before_start')
        m.__file__ = str(path)
        exec(compile(raw, m.__file__, 'exec'), m.__dict__)
        result = m.prepare(self, p, before, end)
        need(type(result) is dict and self.holders() == [self.pid()] and (protected_read(path, limit=2097152) == (raw, st)) and (time.monotonic() < end), 'genuine_C9_samelease_unchangedsource')
        return result

    def prestart_helper_probe(self, p, end):
        need(APPROVED_PRESTART_PROBE_SHA is not None, 'complete_cold_SOURCE_probe_pending')
        path = PC_ROOT / 'prestart-helper-check.py'
        raw, st = protected_read(path, limit=2097152)
        need(sha(raw) == APPROVED_PRESTART_PROBE_SHA, 'complete_fixed_cold_probe')
        r = self.command(['/usr/bin/setpriv', '--reuid=999', '--regid=989', '--groups=989,1000', '/usr/bin/python3', '-I', '-B', str(path)], min(30, end - time.monotonic()))
        need(r.returncode == 0 and (not r.stderr) and (strict(r.stdout)['ok'] is True) and (protected_read(path, limit=2097152) == (raw, st)), 'actual_noambient_UID999_production_helper_closure')
        return {'stdout_raw_utf8': r.stdout.decode(), 'stderr_raw_utf8': r.stderr.decode(), 'returncode': r.returncode, 'source_sha256': sha(raw), 'source_stat': st, 'observed_at': self.wall()}

    def await_prelaunch_before(self, p, before, end):
        gate = self.module('R11_normal_prestart_gate', 'r11-gate/gate_loader.py')
        result = gate.run(self, p, before, 'before-stop', end)
        self.prelaunch_before = result
        return result

    def await_prelaunch_after_stop(self, p, before, end):
        gate = self.module('R11_normal_afterstop_gate', 'r11-gate/gate_loader.py')
        result = gate.run(self, p, before, 'after-stop', end)
        self.prelaunch_after_stop = result
        return result

    def await_AB_current_idle_source(self, p, before, end):
        m = self.module('fixed_AB_source_barrier', 'AB_source_barrier.py')
        return m.await_source(self, p, before, end)

    def preflight_normal_pending(self, p, end):
        from epoch_transaction import idle
        need(p['entry_phase'] == ENTRY_PHASE, 'normal_preflight_exact_phase')
        before = idle(self.capture(end, old=True))
        gate = self.module('R11_normal_preflight', 'r11-gate/gate_loader.py')
        mods, previous, held = gate.load('before-stop')
        try:
            current, context = mods['pc_gate'].snapshot(self, p, before, 'before-stop', end)
            need(all((protected_read(path, limit=2097152) == value for path, value in held.items())), 'normal_preflight_held_gate_sources')
            self.sealed_helpers(p)
            self.normal_unit_policy()
            return {'current_live': before, 'prelaunch_live_policy_checked': True, 'own_normal_stop_calls_planned': 1, 'prior_normal_stop_calls': 0, 'AB_source_CAS_calls': 0, 'entry_phase': p['entry_phase'], 'pending_stage_context': context}
        finally:
            gate.restore(previous)

    def inspect_actual_stopped(self, p, end):
        from epoch_transaction import idle
        prior = actual_stopped_originals(protected_read)
        spec = get_actual_stopped_spec(protected_read)
        before = prior['baseline']
        need(before['owner_state'] == 'STOPPED_POSTCAS_C24_FAILED_BEFORE_START' and before['manager_identity'] == p['old_identity'] and (before['current_source118'] == p['oldmap']) and (before['config_sha256'] == sha(p['old_config_raw_utf8'].encode())), 'exact_R11_R2_failed_current_stopped_source')
        need(time.monotonic() < end and self.holders() == [] and (self.lock_F9() == before['lease_full_F9']) and (not SOCKET.exists()) and (not SOCKET.is_symlink()) and (Path('/proc/sys/kernel/random/boot_id').read_text().strip() == before['manager_identity']['boot_id']), 'actual_failed_current_sameboot_free_original_lease_no_socket')
        for pid in (1803917, 1803579, 1789097, 1822878):
            need(not Path('/proc/' + str(pid)).exists(), 'all_current_failed_and_prior_PIDs_gone')
        self.no_other_manager()
        self.unit_before = self.unit_original()
        original = spec['originals']['epoch-private/original-unit.json']
        raw, meta = protected_read(original['path'])
        u = strict(raw)
        need(sha(raw) == original['sha256'] and meta == original['F9'] and (self.unit_before == (u['raw_utf8'].encode(), u['stat'])), 'actual_original_unit_bytes_full_F9_unchanged')
        fields = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'ExecMainPID', 'ExecMainCode', 'ExecMainStatus', 'Result', 'InvocationID', 'NRestarts', 'ControlGroup')
        result = self.command(['/usr/bin/systemctl', 'show', UNIT, '--property=' + ','.join(fields)], min(10, end - time.monotonic()))
        need(result.returncode == 0 and (not result.stderr), 'current_failed_unit_negative_only')
        now = dict((x.split('=', 1) for x in result.stdout.decode().splitlines()))
        old = prior['failed_start_unit_original']['unit']
        need(set(now) == set(fields) and all((now[k] == old[k] for k in fields if k != 'ControlGroup')) and (now['ControlGroup'] == ''), 'same_failed180_current_negative_separate_from_historical_missing_CG')
        self.stopped_mode = True
        self.after_cas = False
        self.original_before = before
        self.normal_stopped_original = prior['prior_normal_stopped_original']
        self.stop_kernel = self.kernel_dead(before, end)
        self.current_stopped_negative = {'raw_utf8': result.stdout.decode(), 'sha256': sha(result.stdout), 'unit': now, 'kernel': self.stop_kernel, 'observed_at': self.wall(), 'historical_EXIT_not_refreshed': True}
        rows = self.current.helpers.actual_rows(self.current.io)
        commands = self.current.helpers.read_command_history()
        current = dict(before, rows_original=rows, commands=commands)
        idle(current)
        need(rows['rows']['requests'] == before['rows_original']['rows']['requests'] and rows['rows']['historical_terminal_uncertain_sha256'] == before['rows_original']['rows']['historical_terminal_uncertain_sha256'] and all((commands[k] == before['commands'][k] for k in ('canonical_utf8', 'sha256', 'original_file_stat'))), 'fresh_actual_stopped_rows_history_commands_not_rebased')
        need(time.monotonic() < end and self.holders() == [] and (self.lock_F9() == before['lease_full_F9']), 'stopped_inspection_absolute_deadline_lease_still_free')
        self.actual_stopped_readonly_rows = rows
        self.actual_stopped_readonly_commands = commands
        return prior

    def preflight_actual_stopped(self, p, end):
        prior = self.inspect_actual_stopped(p, end)
        self.sealed_helpers(p)
        self.normal_unit_policy()
        return {'current_stopped_baseline': prior['baseline'], 'current_stopped_negative': self.current_stopped_negative, 'fresh_rows_original': self.actual_stopped_readonly_rows, 'fresh_commands_original': self.actual_stopped_readonly_commands, 'spec_sha256': prior['spec_sha256'], 'own_normal_stop_calls_planned': 0, 'prior_normal_stop_calls': 1, 'socket_unlink_calls_planned': 0, 'AB_source_CAS_calls': 0, 'entry_phase': p['entry_phase'], 'no_shared_originals_published': True}

    def adopt_actual_stopped(self, p, end):
        prior = self.inspect_actual_stopped(p, end)
        ref = share_actual_stopped(protected_read, self.current.io.fresh)
        complete = consume_actual_stopped_summary(protected_read, ref)
        need({k: v for k, v in complete.items() if k != 'summary_ref'} == prior and time.monotonic() < end, 'same_prior_complete_shared_before_CAS_no_retimestamp')
        return complete

    def current_failed_owner_status(self, end):
        need(not self.stopped_mode and self.old and (not self.after_cas), 'R16_failed_owner_status_live_before_only')
        action = 'status-asset-stage'
        body = {'action': action, 'operation': self.packet['old_grant_operation'], 'request_nonce': __import__('uuid').uuid4().hex, 'stage_operation': 'c64efe9f2fb5ca21eeb0ee5a107e4e9f'}
        raw = encode(body)
        sent = self.wall()
        mono = time.monotonic()
        limit = min(end, mono + 5)
        with self.current.connect(limit - mono) as conn:
            pid, uid, gid = __import__('struct').unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(uid == 999 and gid == 989 and (self.current.io.holders() == [pid]) and (pid == self.packet['old_identity']['pid']), 'R16_failed_owner_status_original_sole_peer')
            conn.sendall(raw)
            reply = bytearray()
            while b'\n' not in reply:
                need(time.monotonic() < limit and len(reply) <= 1048576, 'R16_failed_owner_status_PC5_cap')
                part = conn.recv(min(65536, 1048577 - len(reply)))
                need(part, 'R16_failed_owner_status_EOF')
                reply.extend(part)
        need(reply.count(b'\n') == 1 and reply.endswith(b'\n') and (time.monotonic() < limit), 'R16_failed_owner_status_complete_PC5')
        out = strict(reply)
        need(type(out) is dict and set(out) == {'ok', 'result'} and (out['ok'] is True) and (out['result']['stage_operation'] == body['stage_operation']), 'R16_failed_owner_status_exact_reply')
        return {'request_raw_utf8': raw.decode(), 'reply_raw_utf8': bytes(reply).decode(), 'observed_at': self.wall(), 'PC_sent_at': sent, 'PC_monotonic_elapsed': time.monotonic() - mono}
