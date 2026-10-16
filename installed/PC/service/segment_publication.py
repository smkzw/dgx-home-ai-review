# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact PC Root stage plan/clock/terminal publication, no direct service edit."""
import os, base64, time, re
from pathlib import Path
from contract import PC_ROOT, OPERATION, need, encode, sha, strict
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
from root_io import fresh, held
import asset_stage, segment_terminal, segment_clock

def shared(root):
    if not root.exists():
        root.mkdir(mode=488)
        os.chown(root, 0, 989)
        os.chmod(root, 488)
    z = root.lstat()
    need((z.st_uid, z.st_gid, z.st_mode) == (0, 989, 16872) and (not root.is_symlink()), 'fixed_Root_shared_stage_directory')

def publish(action, data, c, identity):
    need(os.getuid() == os.geteuid() == 0, 'Root_fixed_stage_publication')
    if action == 'publish-asset-plan':
        p = dict(data)
        need(p['manager_identity'] == identity and p['config_sha256'] == c['_config_sha256'] and (p['source118_sha256'] == sha(encode(c['PC_source_pins']))) and re.fullmatch('[0-9a-f]{32}', p['stage_operation']), 'actual_current_stage_plan_origin')
        p['created_at'] = time.time()
        p['PC_plan_monotonic'] = time.monotonic()
        p['PC_plan_deadline_monotonic'] = p['PC_plan_monotonic'] + p['duration_seconds']
        shared(asset_stage.PLAN_ROOT)
        path = asset_stage.PLAN_ROOT / (p['stage_operation'] + '.json')
        fresh(path, encode(p), mode=288)
        os.chown(path, 0, 989)
        os.chmod(path, 288)
        v, ref = asset_stage.plan(protected_read, p['stage_operation'], c, identity, time.time())
        return {'plan': v, 'plan_ref': ref}
    stage = data['stage_operation']
    need(type(stage) is str and re.fullmatch('[0-9a-f]{32}', stage), 'fixed_stage_publication_nonce')
    if action == 'begin-asset-entry-clock':
        need(set(data) == {'stage_operation'}, 'no_stage_clock_callbacks')
        return segment_clock.begin(c, identity, stage)
    if action == 'begin-asset-terminal-clock':
        need(set(data) == {'stage_operation'}, 'fixed_terminal_clock_begin')
        return segment_clock.terminal_begin(c, identity, stage)
    if action == 'publish-asset-entry-clock':
        need(set(data) == {'stage_operation', 'response_raw_b64', 'response_sha256', 'owned_stop_calls'}, 'stage_entry_origin_complete')
        raw = base64.b64decode(data['response_raw_b64'], validate=True)
        need(sha(raw) == data['response_sha256'] and data['owned_stop_calls'] == 1, 'stage_entry_real_origin')
        return segment_clock.finish(c, identity, stage, raw)
    need(action == 'publish-asset-terminal' and set(data) == {'stage_operation', 'qualified_raw_b64', 'sha256', 'stat'}, 'fixed_stage_terminal_origin')
    raw = base64.b64decode(data['qualified_raw_b64'], validate=True)
    need(sha(raw) == data['sha256'] and data['stat'][2] == len(raw) and (data['stat'][3:7] == [0, 0, 33152, 1]), 'actual_A_Root_stage_origin_fullF9')
    v = strict(raw)
    segment_terminal.validate(v, c, identity, stage, time.time())
    clockroot = segment_clock.TERMINAL_ROOT / stage
    segment_clock.terminal_finish(segment_clock.reader, segment_clock.writer(clockroot), c, identity, stage, raw, data['stat'])
    root = PC_ROOT / 'asset-terminals'
    shared(root)
    path = root / (stage + '.json')
    fresh(path, raw, mode=288)
    os.chown(path, 0, 989)
    os.chmod(path, 288)
    segment_terminal.consume(protected_read, c, identity, stage, time.time())
    return {'state': v['state'], 'sha256': sha(raw), 'image_imported': False, 'models_started': 0}
