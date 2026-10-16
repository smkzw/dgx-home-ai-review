# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure exact-history/current-clock consumer + original Runtime release seam.
Not installed and no caller bool authorizes it. All final context slots unbound.
"""
import base64, math, re, os, stat
from pathlib import Path
from plan import need, strict, encode
from root_io import sha
from contract import RELEASE_STATE
import prelaunch_negative as negative
from receipt_codec import unpack
from legacy_actor import held_actor
from B_OWNER_RECOVERY_R25_WIRING.common import exclusive
APPROVED_REVIEW = 'fb52ebe2e7c3f848322472e451fef05255dc045cd81c0aac0d0372d2000eab62'
APPROVED_ROOT = '/opt/dgx-v4/hx/mimo-registry-native-r26-cpath-r11-r3'
APPROVED_POLICY = None
APPROVED_PACKED_HISTORY = {'not-launched-A-MAC-history.compact.json': '6cd5c9ba427e0c2b20f915fb8fc079d47850531ce39a6e6105eb46ab38d50e8a', 'not-launched-PC-MAC-history.compact.json': '4493506f6873b7dbebcf9b210a22ae292c90769a3a110a10118d25043c36bc35'}
RECOVERY_ROOT = None

def history(raw):
    p = APPROVED_POLICY
    need(type(p) is dict and sha(raw) == p['PC_history_sha256'], 'not_launched_PC_history_SOURCE_pending')
    h = strict(raw)
    a = h['stage_actor']
    need({k: a[k] for k in ('path', 'directory_F9', 'entries')} == p['actor'] and a['entries'] == ['intent.json', 'pulse-1.json', 'reserved.json'] and (set(a['files']) == set(p['actor_files'])), 'not_launched_original_actor3')
    for name, row in a['files'].items():
        need({k: row[k] for k in ('sha256', 'F9')} == p['actor_files'][name], 'not_launched_actor_fullF9')
        negative.original(row, (999, 989, 33152, 1))
    i, r, u = (strict(negative.original(a['files'][n], (999, 989, 33152, 1))) for n in ('intent.json', 'reserved.json', 'pulse-1.json'))
    plan = i['plan']
    ref = i['plan_ref']
    rootplan = h['dynamic_Root_originals'][p['plan_relative']]
    need(h['Root97'] == p['PC_Root97'] and len(h['Root97']) == 97 and ({n: {k: v[k] for k in ('sha256', 'F9')} for n, v in h['dynamic_Root_originals'].items()} == p['PC_Root_originals']), 'not_launched_old_Root97_and_dynamic_originals')
    rawplan = negative.original(rootplan, (0, 989, 33056, 1))
    need(strict(rawplan) == plan and sha(rawplan) == p['plan_sha256'] == ref['sha256'] and (ref['F9'] == rootplan['F9']), 'not_launched_original_Root_plan')
    need(i['schema'] == 'fixed-image-finite-stage-intent/v1' and i['stage_operation'] == r['stage_operation'] == plan['stage_operation'] == p['stage'] and (i['operation_family'] == plan['operation_family'] == u['operation'] == p['old_operation']) and (plan['manager_identity'] == p['old_identity']) and (plan['config_sha256'] == u['config_sha256'] == p['old_config_sha256']) and (plan['source118_sha256'] == u['manager_epoch_sha256'] == sha(encode(p['old_source118']))), 'not_launched_actor_exact_old_owner_source')
    need(i['automatic_retry'] is plan['automatic_retry'] is False and i['deadline_monotonic'] == r['deadline_monotonic'] == plan['PC_plan_deadline_monotonic'] and (i['duration_seconds'] == plan['duration_seconds']) and (i['plan_ref'] == r['plan_ref']) and (type(u['ordinal']) is int) and (u['ordinal'] == 1) and (u['clear_reservation_original'] == r) and (u['clear_reservation_sha256'] == sha(encode(r))) and (u['source_release_sha256'] == i['source_release_sha256'] == plan['review_sha256']), 'not_launched_original_deadline_and_pulse_causal')
    return {'actor': a, 'plan_ref': ref, 'deadline_monotonic': i['deadline_monotonic'], 'stage_operation': p['stage']}

def consume(qualified_raw, qualified_stat, A_history_raw, PC_history_raw, current, now):
    need(APPROVED_REVIEW is not None and APPROVED_ROOT is not None, 'not_launched_PC_final_SOURCE_pending')
    need(qualified_stat[2] == len(qualified_raw) and qualified_stat[3:7] == [0, 989, 33056, 1], 'not_launched_PC_Root_shared_original')
    v = strict(qualified_raw)
    need(set(v) == {'schema', 'review_sha256', 'begin', 'finish', 'A_proof', 'current'} and v['schema'] == 'stage-not-launched-PC-qualified/v1' and (v['review_sha256'] == APPROVED_REVIEW) and (v['current'] == current), 'not_launched_current_new_source_not_history')
    p = APPROVED_POLICY
    old = history(PC_history_raw)
    proof = strict(unpack(v['A_proof']))
    a = negative.validate(proof, A_history_raw, current)
    request = negative.original(proof['request_original'])
    r = negative.checked_request(request, current)
    begin = strict(negative.original(v['begin'], (0, 989, 33056, 1)))
    finish = strict(negative.original(v['finish'], (0, 989, 33056, 1)))
    need(set(begin) == {'schema', 'request_sha256', 'request_nonce', 'current', 'PC_boot_id', 'PC_sent_at', 'PC_monotonic'} and set(finish) == {'schema', 'begin_sha256', 'request_sha256', 'A_proof_sha256', 'current', 'PC_boot_id', 'PC_received_at', 'PC_monotonic'}, 'not_launched_full_PC_clock_originals')
    need(begin['schema'] == 'stage-not-launched-PC-BEGIN/v1' and finish['schema'] == 'stage-not-launched-PC-finish/v1' and (begin['request_sha256'] == finish['request_sha256'] == sha(request)) and (begin['request_nonce'] == r['nonce']) and (finish['begin_sha256'] == v['begin']['sha256']) and (finish['A_proof_sha256'] == sha(encode(v['A_proof']))), 'not_launched_PC_nonce_clock_chain')
    need(begin['current'] == finish['current'] == r['current'] == current and current['review_sha256'] == APPROVED_REVIEW and (len(current['source118']) == 118) and (begin['PC_boot_id'] == finish['PC_boot_id'] == current['manager_identity']['boot_id']), 'not_launched_current_full118_epoch')
    nums = (begin['PC_sent_at'], begin['PC_monotonic'], finish['PC_received_at'], finish['PC_monotonic'], now)
    need(all((type(x) in (int, float) and math.isfinite(x) for x in nums)) and 0 <= finish['PC_monotonic'] - begin['PC_monotonic'] <= 30 and (0 <= finish['PC_received_at'] - begin['PC_sent_at'] <= 30) and (0 <= now - finish['PC_received_at']) and (now - begin['PC_sent_at'] <= 30), 'not_launched_PC_single_domain_whole30')
    return dict(a, state=RELEASE_STATE, proof_sha256=sha(qualified_raw), history_actor=old, original_deadline_monotonic=old['deadline_monotonic'], work_deadline_extended=False)

def packed_histories(read, root):
    need(type(APPROVED_PACKED_HISTORY) is dict and set(APPROVED_PACKED_HISTORY) == {'not-launched-A-MAC-history.compact.json', 'not-launched-PC-MAC-history.compact.json'}, 'not_launched_packed_history_SOURCE_pending')
    manifest_path = root / 'not-launched-histories-origin.json'
    raw, st = read(manifest_path, limit=2097152)
    m = strict(raw)
    need(st[2] == len(raw) and st[3:7] == [0, 989, 33056, 1] and (type(m) is dict) and (set(m) == {'schema', 'source_review_sha256', 'files'}) and (m['schema'] == 'stage-not-launched-packed-history-origin/v1') and (m['source_review_sha256'] == APPROVED_REVIEW) and (set(m['files']) == set(APPROVED_PACKED_HISTORY)), 'not_launched_Root_packed_origin_table')
    out = {}
    held = {str(manifest_path): (raw, st)}
    for name, pin in APPROVED_PACKED_HISTORY.items():
        ref = m['files'][name]
        need(set(ref) == {'packed_sha256', 'raw_sha256', 'F9'} and ref['packed_sha256'] == pin, 'not_launched_static_packed_source_SHA')
        body, f9 = read(root / name, limit=2097152)
        need(type(f9) is list and len(f9) == 9 and all((type(x) is int and x >= 0 for x in f9)) and (f9 == ref['F9']) and (f9[2] == len(body)) and (f9[3:7] == [0, 989, 33056, 1]) and (sha(body) == pin), 'not_launched_actual_packed_full_F9_SHA')
        decoded = unpack(strict(body))
        expected = APPROVED_POLICY['A_history_sha256' if name.startswith('not-launched-A-') else 'PC_history_sha256']
        need(sha(decoded) == ref['raw_sha256'] == expected, 'not_launched_full_decoded_raw_SHA_not_packed_F9')
        out['A' if name.startswith('not-launched-A-') else 'PC'] = decoded
        held[str(root / name)] = (body, f9)
    return (out, held)

def runtime_identity():
    return {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19], 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': os.environ['INVOCATION_ID']}

def release(stages, read, identity, now):
    """Future same-Runtime integration seam, not the installed finish action.
 Caller supplies the existing protected Root reader; no proof/callback input.
 It must be held-loaded by that Runtime and added to its fixed action dispatch.
 """
    need(APPROVED_ROOT is not None and RECOVERY_ROOT is not None, 'not_launched_release_SOURCE_pending')
    g = stages.g
    current = {'review_sha256': APPROVED_REVIEW, 'config_sha256': g.config['_config_sha256'], 'manager_identity': identity, 'source118': g.config['PC_source_pins']}
    need(identity == runtime_identity() == current['manager_identity'] and g.runtime.owner_recovery is g.operator and (g.runtime.server.scheduler is g.s) and g.operator.lease.held and (g.config['_config_sha256'] == current['config_sha256']) and (g.config['PC_source_pins'] == current['source118']), 'not_launched_same_sole_Runtime_lease_source')
    need(g.operator.negative_cpu_release.pending is True and stages.legacy_pending is True and (stages.closed is False) and (g.closed is False) and (stages.active is None) and (not g.active) and (g.deadline is None), 'not_launched_exact_legacy_pending_not_other_work')
    root = Path(APPROVED_ROOT)
    raw, st = read(root / 'not-launched-qualified.json', limit=2097152)
    decoded, packed_originals = packed_histories(read, root)
    ah, ph = (decoded['A'], decoded['PC'])
    result = consume(raw, st, ah, ph, current, now)
    for name, row in APPROVED_POLICY['PC_Root97'].items():
        b, f = read(Path(APPROVED_POLICY['PC_Root_root']) / name, limit=2097152)
        need(sha(b) == row['sha256'] and f == row['F9'], 'not_launched_original_Root97_fullraw_F9')
    for name, row in APPROVED_POLICY['PC_Root_originals'].items():
        b, f = read(Path(APPROVED_POLICY['PC_Root_root']) / name, limit=2097152)
        need(sha(b) == row['sha256'] and f == row['F9'], 'not_launched_original_dynamic_Root_fullraw_F9')
    recovery_root = Path(RECOVERY_ROOT)
    target = recovery_root / identity['invocation_id']
    with g.facade._lifecycle_lock:
        g.live_baseline = None
        g.current('stage-not-launched-current', fenced=True)
        with g.s._lock:
            g.counters_locked()
            g.s.continue_operator_maintenance()
            g.same()
            g.current_epoch()
            expected = dict(APPROVED_POLICY['actor'], files=APPROVED_POLICY['actor_files'])
            import_original = held_actor(Path(expected['path']), expected=expected)
            need(import_original == result['history_actor']['actor'], 'not_launched_actual_old_actor_unchanged')
            need(all((read(Path(path), limit=2097152) == value for path, value in packed_originals.items())), 'not_launched_packed_origins_stable_after_current')
            need(read(root / 'not-launched-qualified.json', limit=2097152) == (raw, st), 'not_launched_same_protected_clock_receipt_after_current')
            consume(raw, st, ah, ph, current, g.runtime.manager._now())
            need(not target.exists(), 'not_launched_normal_release_once')
            need(os.getuid() == os.geteuid() == 999, 'not_launched_actual_service999_release')
            if not recovery_root.exists():
                recovery_root.mkdir(mode=448)
                os.chmod(recovery_root, 448)
            rs = recovery_root.lstat()
            need(stat.S_ISDIR(rs.st_mode) and (rs.st_uid, rs.st_gid, stat.S_IMODE(rs.st_mode)) == (999, 989, 448), 'not_launched_service_recovery_directory')
            target.mkdir(mode=448)
            os.chmod(target, 448)
            intent_sha256 = exclusive(target / 'intent.json', {'schema': 'stage-not-launched-release-intent/v1', 'proof_sha256': sha(raw), 'current': current, 'old_stage': result['stage_operation'], 'old_deadline': result['original_deadline_monotonic'], 'work_deadline_extended': False, 'operation': negative.OPERATION, 'A_history_sha256': APPROVED_POLICY['A_history_sha256'], 'PC_history_sha256': APPROVED_POLICY['PC_history_sha256'], 'old_actor_sha256': sha(encode(result['history_actor']['actor'])), 'observed_at': g.runtime.manager._now()})
            try:
                completed = {'schema': 'stage-not-launched-release-completed/v1', 'operation': negative.OPERATION, 'intent_sha256': intent_sha256, 'observed_at': g.runtime.manager._now(), 'state': result['state'], 'stage_operation': result['stage_operation'], 'proof_sha256': sha(raw), 'current': current, 'original_deadline_monotonic': result['original_deadline_monotonic'], 'work_deadline_extended': False, 'image_imported': False, 'models_started': 0}
                exclusive(target / 'completed.json', completed)
                consume(raw, st, ah, ph, current, g.runtime.manager._now())
                g.s.finish_operator_maintenance()
                exclusive(target / 'fence-released.json', {'completed_sha256': sha(encode(completed)), 'operation': negative.OPERATION, 'observed_at': g.runtime.manager._now(), 'operator_maintenance_observed': False})
                stages.legacy_pending = False
                g.operator.negative_cpu_release.pending = False
                g.live_baseline = None
                return completed
            except BaseException:
                g.s.restore_operator_block()
                raise
