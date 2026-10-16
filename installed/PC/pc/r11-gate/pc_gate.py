# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Root normal-epoch gate. Context comes only from the actual current reader."""
import base64, math, os, secrets, stat, time
from pathlib import Path
from plan import need, strict, encode
from root_io import sha
from receipt_codec import unpack, pack
import gate_protocol as protocol
import scope_receipt as receipt
import prelaunch_negative as negative
import pc_recovery as recovery
import prelaunch_stop as stopped
from legacy_actor import held_actor
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
APPROVED_ROOT = '/opt/dgx-v4/hx/mimo-registry-r16'
APPROVED_PHASES = {'before-stop': {'root': '/opt/dgx-v4/r16-normal-before', 'worker_sha256': 'd9aae265436252b937faf2dd762c12504bb3d14b5d8c153557884f6bc870a680', 'scope_sha256': '618ee1e457d2deb200947f0196ac674ec468e70f385e515e3365300f5b6cea12', 'history_data_root': None, 'source_review': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'}, 'after-stop': {'root': '/opt/dgx-v4/r16-normal-after', 'worker_sha256': 'e66bb858da954658af4c2f9d53d65d044e44786625e25736c6177dd4e8e1357e', 'scope_sha256': '3a93774dff0bc5bc61b44aaefcd215b30fca4c2f8ac488aea8737c2298c7eefe', 'history_data_root': None, 'source_review': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'}}
APPROVED_BASELINE = None
APPROVED_ACTOR_PARENT = None

def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()

def row(raw, f9):
    return {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': f9}

def shared_dir(path):
    need(not path.exists() and (not path.is_symlink()), 'R11_new_PC_phase_directory')
    path.mkdir(mode=488)
    os.chown(path, 0, 989)
    os.chmod(path, 488)
    z = path.lstat()
    need(stat.S_ISDIR(z.st_mode) and (z.st_uid, z.st_gid, stat.S_IMODE(z.st_mode)) == (0, 989, 488), 'R11_shared_directory_exact_not_umask')

def root(phase):
    need(APPROVED_ROOT is not None and type(APPROVED_PHASES) is dict and (phase in APPROVED_PHASES), 'R11_gate_final_SOURCE_pending')
    return Path(APPROVED_ROOT) / 'normal-prestart' / phase

def actor_parent(expected_holder):
    path = Path(recovery.ACTOR_ROOT)
    fields = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
    f = lambda z: [getattr(z, k) for k in fields]
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = f(os.fstat(fd))
        names = sorted(os.listdir(fd))
        need(before == f(path.lstat()) and before[3:6] == [999, 989, 16832] and (names == ['b7a518bbefa903b6c43c44b9a2f6f6cf', '69b0a7b8356ae276839c3cc43044096c', 'c64efe9f2fb5ca21eeb0ee5a107e4e9f', '6867e0e5c18d53bc88b7d742da7b86a8']), 'R16_normal_complete_four_actor_set')
        actors = recovery.actors(protected_read, expected_holder)
        children = {n: f(os.stat(n, dir_fd=fd, follow_symlinks=False)) for n in names}
        need(set(actors) == set(names) and f(os.fstat(fd)) == f(path.lstat()) == before and (sorted(os.listdir(fd)) == names), 'R16_normal_actor_held_after_all_history')
        return {'path': str(path), 'F9': before, 'entries': names, 'children': children, 'actor_files': {n: {k: {'sha256': v['sha256'], 'F9': v['F9']} for k, v in a['files'].items()} for n, a in actors.items()}}
    finally:
        os.close(fd)

def snapshot(native, p, before, phase, end):
    need(phase in ('before-stop', 'after-stop') and type(APPROVED_BASELINE) is dict, 'R11_normal_two_phase_only')
    original = APPROVED_BASELINE
    need(boot_id() == original['manager_identity']['boot_id'], 'R11_actual_PC_sameboot_not_history')
    need(before['manager_identity'] == original['manager_identity'] == p['old_identity'] and p['oldmap'] == original['current_source118'] and (sha(p['old_config_raw_utf8'].encode()) == original['config_sha256']), 'R11_actual174_source705_baseline_not_old171')
    if phase == 'before-stop':
        need(native.stopped_mode is False, 'R11_before_is_actual_live_reader')
        s = native.capture(end, old=True)
        need(s['manager_identity'] == original['manager_identity'] and native.holders() == [s['manager_identity']['pid']], 'R11_live_actual_owner_FLOCK')
        status = native.current_unarmed_idle(end)
        q = strict(status['request_raw_utf8'].encode())
        a = strict(status['reply_raw_utf8'].encode())
        v = a['result']
        need(a['ok'] is True and q['action'] == 'status-registry-source' and (q['request_nonce'] == v['request_nonce']) and (q['operation'] == v['operation'] == p['old_grant_operation']) and (v['manager_pid'] == s['manager_identity']['pid']) and (v['source118'] == original['current_source118']) and (v['current']['scheduler']['operator_maintenance'] is True), 'R11_exact_stage_pending_live_peer_maintenanceTrue')
        asset = native.current_failed_owner_status(end)
        av = strict(asset['reply_raw_utf8'].encode())
        need(av['ok'] is True, 'R16_actual_failed_owner_status_reply')
        pending = recovery.history_reader.owner_normal_before(protected_read, recovery.history_reader.owner_policy(), v['current'], av['result'], asset['observed_at'])
        context = {'owner_state': 'LIVE', 'snapshot': s, 'private_status_original': status, 'private_asset_status_original': asset, 'failed_owner_descriptor': {k: x for k, x in pending['failed_owner'].items() if k != 'original_terminal'}}
    else:
        need(native.stopped_mode is True and native.old is True and (native.after_cas is False) and (native.holders() == [native.pid()]), 'R11_after_actual_stopped_preCAS_ownedlease')
        native.no_other_manager()
        s = native.capture_stopped(end)
        need(s.get('manager_identity') in (None, {}), 'R11_stopped_snapshot_not_fabricated_live_owner')
        previous = native.normal_stopped_original
        need(sha(previous['raw_utf8'].encode()) == previous['sha256'] and sha(previous['journal_raw_utf8'].encode()) == previous['journal_sha256'], 'R11_unchanged_true_normalstop_raw')
        classification = stopped.classify(previous['raw_utf8'].encode(), previous['journal_raw_utf8'].encode(), original['manager_identity'], previous['composition_sha256'])
        need(classification == previous['classification'] and classification['state'] == 'OLD_OWNER_FAILED_SHUTDOWN_PRESERVED_NO_ENGINE' and (classification['actual_exit_code'] == 2), 'R16_typed_held_original_Code2_not_arbitrary_failure')
        kernel = native.kernel_dead(before, end)
        need(kernel['old_PID_absent'] is True and kernel['owned_cgroup_processes'] == kernel['kernel_socket_owners'] == [], 'R11_fresh_stopped_kernel_not_old_stop')
        context = {'owner_state': 'STOPPED', 'snapshot': s, 'prior_stopped_original': previous, 'fresh_kernel_original': kernel, 'lease_holders': [native.pid()], 'owned_installer_pid': native.pid()}
    for key in ('current_source118', 'config_sha256', 'config_stat', 'source_files', 'lease_full_F9', 'Cleaf', 'commands'):
        if key == 'commands':
            need(all((s[key][k] == original[key][k] for k in ('canonical_utf8', 'sha256', 'original_file_stat'))), 'R11_commands_exact_raw_SHA_F9_not_observedtime')
        else:
            need(s[key] == original[key], 'R11_snapshot_exact_' + key)
    rows = s['rows_original']['rows']
    need(rows['active_jobs'] == rows['active_requests'] == [] and rows['historical_terminal_uncertain_count'] == 9, 'R11_whole_Core_noactive_history9')
    for value in rows['profiles'].values():
        need(value['state'] == 'STOPPED' and value['owner'] is None and (type(value['generation']) is int) and (value['generation'] > 0), 'R11_dynamic_Core_all_STOPPED')
    for value in rows['nodes']:
        need(value['hold_profile'] is value['hold_owner'] is value['hold_generation'] is None and value['quarantine'] == 0, 'R11_noholds_noQUAR')
    need(native.current.config['_config_sha256'] == original['config_sha256'] and native.current.config['PC_source_pins'] == original['current_source118'], 'R11_reader_config_same_actual_source')
    current = {'review_sha256': negative.APPROVED_REVIEW, 'config_sha256': s['config_sha256'], 'manager_identity': original['manager_identity'], 'source118': s['current_source118']}
    holder = original['manager_identity']['pid'] if phase == 'before-stop' else native.pid()
    parent_original = actor_parent(holder)
    need(actor_parent(holder) == parent_original, 'R16_normal_four_actor_metadata_after_history')
    context['retained_actor_directory'] = parent_original
    return (current, context)

def begin(native, p, before, phase, end):
    current, context = snapshot(native, p, before, phase, end)
    target = root(phase)
    parent = target.parent
    if not parent.exists():
        shared_dir(parent)
    else:
        z = parent.lstat()
        need(not parent.is_symlink() and stat.S_ISDIR(z.st_mode) and ((z.st_uid, z.st_gid, stat.S_IMODE(z.st_mode)) == (0, 989, 488)), 'R11_PC_parent_exact')
    shared_dir(target)
    native.current.io.fresh(target / 'context.json', encode(context), mode=288, gid=989)
    desc = APPROVED_PHASES[phase]
    nonce = secrets.token_hex(16)
    raw = protocol.make(phase, current, desc['worker_sha256'], context, nonce)
    native.current.io.fresh(target / 'request.json', raw, mode=288, gid=989)
    wall = native.wall()
    mono = time.monotonic()
    need(mono < end, 'R11_original_epoch_budget')
    value = {'schema': 'R11-PC-phase-BEGIN/v1', 'phase': phase, 'request_sha256': sha(raw), 'request_nonce': nonce, 'context_sha256': sha(encode(context)), 'current': current, 'PC_sent_at': wall, 'PC_monotonic': mono, 'PC_boot_id': current['manager_identity']['boot_id']}
    native.current.io.fresh(target / 'begin.json', encode(value), mode=288, gid=989)
    native.current.io.fresh(target / 'awaiting.json', encode({'schema': 'R11-PC-awaiting-A/v1', 'request_raw_b64': base64.b64encode(raw).decode(), 'request_sha256': sha(raw), 'phase': phase, 'clock_started': True}), mode=288, gid=989)
    native.current.io.fresh(target / 'awaiting.marker', b'', mode=288, gid=989)
    return value

def finish(phase, compact, native):
    target = root(phase)
    raw, rf = protected_read(target / 'request.json', limit=262144)
    begin_raw, bf = protected_read(target / 'begin.json')
    context, cf = protected_read(target / 'context.json', limit=2097152)
    b = strict(begin_raw)
    r = strict(raw)
    need(b['schema'] == 'R11-PC-phase-BEGIN/v1' and b['request_sha256'] == sha(raw) and (b['context_sha256'] == sha(context) == r['PC_context_sha256']) and (b['request_nonce'] == r['nonce']) and (b['phase'] == phase), 'R11_full_same_protected_BEGIN_context_request')
    recv = native.wall()
    mono = time.monotonic()
    nums = (b['PC_sent_at'], b['PC_monotonic'], recv, mono)
    need(all((type(x) in (int, float) and math.isfinite(x) for x in nums)) and 0 <= mono - b['PC_monotonic'] <= 30 and (0 <= recv - b['PC_sent_at'] <= 30), 'R11_real_PC_whole30_not_crosshost_or_extended')
    decoded = unpack(compact)
    out = strict(decoded)
    packed, _ = recovery.packed_histories(protected_read, Path(APPROVED_ROOT))
    result = receipt.validate(out, raw, b['current'], APPROVED_PHASES[phase]['worker_sha256'], packed['A'], phase)
    need(boot_id() == b['PC_boot_id'], 'R11_same_actual_PC_boot_through30')
    need(mono >= b['PC_monotonic'] and b['current']['config_sha256'] == native.current.config['_config_sha256'] and (b['current']['source118'] == native.current.config['PC_source_pins']), 'R11_no_config_change_while_A_observed')
    recv = native.wall()
    mono = time.monotonic()
    need(0 <= mono - b['PC_monotonic'] <= 30 and 0 <= recv - b['PC_sent_at'] <= 30, 'R11_complete_typed_consume_within_original30')
    end = {'schema': 'R11-PC-phase-finish/v1', 'phase': phase, 'begin_sha256': sha(begin_raw), 'request_sha256': sha(raw), 'context_sha256': sha(context), 'A_compact_sha256': sha(encode(compact)), 'PC_received_at': recv, 'PC_monotonic': mono, 'current': b['current']}
    native.current.io.fresh(target / 'finish.json', encode(end), mode=288, gid=989)
    endraw, ef = protected_read(target / 'finish.json')
    value = {'schema': 'R11-PC-phase-qualified/v1', 'phase': phase, 'current': b['current'], 'begin': row(begin_raw, bf), 'finish': row(endraw, ef), 'context_ref': {'path': str(target / 'context.json'), 'sha256': sha(context), 'F9': cf}, 'A_scope': compact, 'result': {k: v for k, v in result.items() if k not in ('proof', 'request')}}
    native.current.io.fresh(target / 'qualified.json', encode(value), mode=288, gid=989)
    qualified, qf = protected_read(target / 'qualified.json', limit=2097152)
    need(qualified == encode(value), 'R11_qualified_exact_readback')
    native.current.io.fresh(target / 'published.marker', b'', mode=288, gid=989)
    return {'phase': phase, 'qualified_ref': {'path': str(target / 'qualified.json'), 'sha256': sha(qualified), 'stat': qf}, 'state': 'NOT_LAUNCHED_QUIESCENT', 'aggregate_exit_status': None}

def await_phase(native, p, before, phase, end):
    b = begin(native, p, before, phase, end)
    target = root(phase)
    limit = min(end, b['PC_monotonic'] + 30)
    while not (target / 'published.marker').exists():
        need(time.monotonic() < limit, 'R11_paired30_no_retry')
        time.sleep(0.02)
    raw, st = protected_read(target / 'qualified.json', limit=2097152)
    q = strict(raw)
    need(set(q) == {'schema', 'phase', 'current', 'begin', 'finish', 'context_ref', 'A_scope', 'result'} and q['schema'] == 'R11-PC-phase-qualified/v1' and (q['phase'] == phase) and (q['current'] == b['current']), 'R11_actual_qualified_phase')
    request_raw, _ = protected_read(target / 'request.json', limit=262144)
    packed, _ = recovery.packed_histories(protected_read, Path(APPROVED_ROOT))
    receipt.validate(strict(unpack(q['A_scope'])), request_raw, b['current'], APPROVED_PHASES[phase]['worker_sha256'], packed['A'], phase)
    f = strict(negative.original(q['finish'], (0, 989, 33056, 1)))
    need(set(f) == {'schema', 'phase', 'begin_sha256', 'request_sha256', 'context_sha256', 'A_compact_sha256', 'PC_received_at', 'PC_monotonic', 'current'} and f['schema'] == 'R11-PC-phase-finish/v1' and (f['phase'] == phase) and (f['current'] == b['current']) and (f['request_sha256'] == sha(request_raw)) and (f['A_compact_sha256'] == sha(encode(q['A_scope']))) and all((type(x) in (int, float) and math.isfinite(x) for x in (f['PC_monotonic'], f['PC_received_at']))) and (0 <= f['PC_received_at'] - b['PC_sent_at'] <= 30), 'R11_full_finite_PC_finish_original')
    need(f['begin_sha256'] == q['begin']['sha256'] and strict(negative.original(q['begin'], (0, 989, 33056, 1))) == b and (0 <= f['PC_monotonic'] - b['PC_monotonic'] <= 30) and (0 <= time.monotonic() - b['PC_monotonic'] <= 30), 'R11_final_same_origin30_no_timestamp_refresh')
    return {'phase': phase, 'state': 'NOT_LAUNCHED_QUIESCENT', 'aggregate_exit_status': None, 'qualified_ref': {'path': str(target / 'qualified.json'), 'sha256': sha(raw), 'stat': st}}
