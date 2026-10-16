# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One exact failed prepayload reservation, preserved separately from new work.
No old terminal RPC, directory repair, SQL, timestamp refresh or inferred EXIT0.
"""
import base64, os, stat, time
from released_stage_history import consume as released_history
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read, metadata
from contract import need, strict, sha, encode, OPERATION, OPERATOR
APPROVED_POLICY = None
RECOVERY_ROOT = OPERATOR / ('asset-prepayload-negative-' + OPERATION)

def held_actor(path, *, expected=None):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = metadata(os.fstat(fd))
        need(before == metadata(path.lstat()) and before[3:7] == [999, 989, 16832, 2], 'legacy_stage_owned_directory_exact')
        names = sorted(os.listdir(fd))
        need(len(names) <= 32 and all(('/' not in n and n not in ('.', '..') for n in names)), 'legacy_stage_flat_bounded_entries')
        if expected is not None:
            need(before == expected['directory_F9'] and names == sorted(expected['entries']), 'legacy_stage_fixed_directory_F9_entries')
        rows = {}
        total = 0
        for name in names:
            leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                f9 = metadata(os.fstat(leaf))
                need(f9 == metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)) and f9[3:7] == [999, 989, 33152, 1] and (0 < f9[2] <= 4194304), 'legacy_stage_actual_leaf_owner_FD')
                body = bytearray()
                while len(body) <= f9[2]:
                    chunk = os.read(leaf, min(65536, f9[2] + 1 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                raw = bytes(body)
                total += len(raw)
                need(len(raw) == f9[2] and total <= 8388608, 'legacy_stage_complete_original_cap')
                need(metadata(os.fstat(leaf)) == metadata(os.stat(name, dir_fd=fd, follow_symlinks=False)) == f9, 'legacy_stage_held_named_stable_after_read')
                if expected is not None:
                    need({'sha256': sha(raw), 'F9': f9} == expected['files'][name], 'legacy_stage_original_exact_SHA_F9')
                rows[name] = {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': f9}
            finally:
                os.close(leaf)
        need(metadata(os.fstat(fd)) == metadata(path.lstat()) == before and sorted(os.listdir(fd)) == names, 'legacy_stage_directory_FD_named_entries_after')
        return {'path': str(path), 'directory_F9': before, 'entries': names, 'files': rows}
    finally:
        os.close(fd)

def validate_actor(v, p):
    need(p is not None and p['schema'] == 'R9-fixed-prepayload-failed-stage-history/v1', 'legacy_stage_policy_SOURCE_pending')
    need(v['path'] == p['directory'] and v['directory_F9'] == p['directory_F9'] and (v['entries'] == sorted(p['entries']) == ['intent.json', 'pulse-1.json', 'reserved.json']) and (set(v['files']) == set(p['files'])), 'legacy_one_failed_stage_no_new_outputs')

    def load(n):
        row = v['files'][n]
        raw = base64.b64decode(row['raw_b64'], validate=True)
        need(sha(raw) == row['sha256'] == p['files'][n]['sha256'] and row['F9'] == p['files'][n]['F9'] and (len(raw) == row['F9'][2]), 'legacy_full_original_actor_bytes')
        return strict(raw)
    i, r, u = (load(n) for n in ('intent.json', 'reserved.json', 'pulse-1.json'))
    plan = i['plan']
    ref = i['plan_ref']
    stage = p['stage_operation']
    need(i['schema'] == 'fixed-image-finite-stage-intent/v1' and i['stage_operation'] == r['stage_operation'] == stage and (i['operation_family'] == plan['operation_family'] == u['operation'] == p['old_operation_family']), 'legacy_actor_exact_operation_family')
    need(i['automatic_retry'] is plan['automatic_retry'] is False and i['deadline_monotonic'] == r['deadline_monotonic'] == plan['PC_plan_deadline_monotonic'] and (i['duration_seconds'] == plan['duration_seconds']), 'legacy_original_window_never_rebased')
    need(plan['manager_identity'] == p['old_manager_identity'] and plan['config_sha256'] == u['config_sha256'] == p['old_config_sha256'] and (plan['source118_sha256'] == u['manager_epoch_sha256'] == sha(encode(p['old_source118']))), 'legacy_original_reserved_Runtime_source')
    need(u['ordinal'] == 1 and type(u['ordinal']) is int and (u['source_release_sha256'] == i['source_release_sha256'] == plan['review_sha256']) and (u['clear_reservation_original'] == r) and (u['clear_reservation_sha256'] == sha(encode(r))), 'legacy_original_pulse_reservation_causal_binding')
    need(i['plan_ref'] == r['plan_ref'] and ref == dict(p['Root_originals'][p['root_plan']], path=p['root_plan']) and (sha(encode(plan)) == ref['sha256']), 'legacy_Root_plan_reference')
    return {'state': 'FAILED_STAGE_PREPAYLOAD_RESERVED_HISTORY', 'old_operation_family': p['old_operation_family'], 'stage_operation': stage, 'plan_ref': ref, 'original_deadline_monotonic': i['deadline_monotonic'], 'original_actor': v, 'work_deadline_extended': False, 'image_imported': False, 'CPU_success': False, 'models_started': 0}

def originals(read=protected_read):
    p = APPROVED_POLICY
    need(p is not None, 'legacy_stage_policy_SOURCE_pending')
    v = held_actor(p['directory'], expected=p)
    out = validate_actor(v, p)
    for name, row in p['Root94'].items():
        raw, f9 = read(Path(p['Root']) / name, limit=2097152)
        need(sha(raw) == row['sha256'] and f9 == row['F9'], 'legacy_Root94_all_immutable_originals')
    for name, row in p['Root_originals'].items():
        raw, f9 = read(Path(name), limit=4194304)
        need(sha(raw) == row['sha256'] and f9 == row['F9'], 'legacy_Root_plan_qualification_originals')
    need(held_actor(p['directory'], expected=p) == v, 'legacy_actor_full_F9_stable_across_Root_reads')
    return out

def prior_released(config):
    return released_history(time.time())
