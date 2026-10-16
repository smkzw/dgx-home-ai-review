# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Specific bind-before-start failure, exact complete immutable originals.
Historical Mac archives carry actual leaf origin metadata, never new Root time.
"""
import base64, hashlib, json
from pathlib import Path
from history_reader import read, OWNER
from receipt_codec import unpack
from ready_history import positive
HISTORY_ROOT = '/opt/dgx-v4/hx/mimo-registry-r16-data'
APPROVED_PACKED_PINS = {'pc': '0b0ca235f283257ee2376b2fafb273b0671f4a4a765f2e4e003869164a135d4d', 'a': 'd87052e5937711927ef3a1e2b1a1614294b9446279a852b2a117b168a6b0ba2c', 'sources': '087774e024094969e1d76c9f85a98fbe5406c9c5d020196b3345b10e752b0f00'}
APPROVED_PUBLICATION_OPERATION = '2b9e9b631cebc13ae6b1550ee59c13ed'
APPROVED_POLICY = None
STATE = 'FAILED_ASSET_STAGE_NOT_LAUNCHED_QUIESCENT'

class Refused(ValueError):
    pass

def need(v, r):
    if not v:
        raise Refused(r)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def strict(b):

    def pairs(xs):
        d = {}
        for k, v in xs:
            need(k not in d, 'zero_launch_duplicate_key')
            d[k] = v
        return d
    return json.loads(b, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'zero_launch_nonfinite'))

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def row(v, owner):
    need(type(v) is dict and set(v) == {'raw_b64', 'sha256', 'F9'}, 'zero_launch_original_shape')
    b = base64.b64decode(v['raw_b64'], validate=True)
    f = v['F9']
    need(type(f) is list and len(f) == 9 and all((type(x) is int and x >= 0 for x in f)) and (f[2] == len(b)) and (f[3:7] == owner) and (sha(b) == v['sha256']), 'zero_launch_full_raw_SHA_F9')
    return b

def history(pc_raw, a_raw, sources_raw):
    p = APPROVED_POLICY
    need(type(p) is dict and all((sha(raw) == p[k] for raw, k in ((pc_raw, 'PC_history_sha256'), (a_raw, 'A_history_sha256'), (sources_raw, 'A_sources_sha256')))), 'zero_launch_frozen_complete_originals_pending')
    pc, a, s = (strict(x) for x in (pc_raw, a_raw, sources_raw))
    stage = p['stage']
    need(pc['stage_operation'] == a['stage_operation'] == stage and set(pc['files']) == {'intent.json', 'reserved.json', 'pulse-1.json'}, 'zero_launch_exact_three_actor_originals')
    vals = {n: strict(row(v, [999, 989, 33152, 1])) for n, v in pc['files'].items()}
    i, r, pulse = (vals[n] for n in ('intent.json', 'reserved.json', 'pulse-1.json'))
    plan = i['plan']
    need(i['stage_operation'] == r['stage_operation'] == plan['stage_operation'] == stage and plan['operation_family'] == p['old_operation'] and (i['plan_ref'] == r['plan_ref']) and (i['deadline_monotonic'] == r['deadline_monotonic'] == plan['PC_plan_deadline_monotonic']) and (pulse['clear_reservation_original'] == r) and (pulse['clear_reservation_sha256'] == sha(encode(r))) and (pulse['ordinal'] == 1) and (i['automatic_retry'] is False), 'zero_launch_original_owner_plan_deadline_pulse')
    need(plan['manager_identity'] == p['old_identity'] and plan['config_sha256'] == p['old_config_sha256'] and (pulse['config_sha256'] == p['old_config_sha256']) and (pulse['manager_epoch_sha256'] == plan['source118_sha256']) and (plan['ranges'] == p['ranges']), 'zero_launch_exact_old_current_and_interval')
    names = {'entry-clock-request.json', 'entry-clock-response.json', 'entry-clock-start.json', 'entry-context.json', 'entry-launch-intent.json', 'entry-qualified.json', 'entry-stop-intent.json', 'entry-stop-result.json', 'plan.json'}
    need(set(a['files']) == names and set(a['entries']) == names | {'readiness'} and (a['absent'] == dict.fromkeys(('context.json', 'launch-intent.json', 'parent-proof.json', 'runtime-max-original.json'), True)) and (a['payloadBASE_absent'] is True) and (a['GET'] == a['controls'] == 0), 'zero_launch_exact_saved_bind_before_context_namespace')
    av = {n: strict(row(v, [0, 0, 33152, 1])) for n, v in a['files'].items()}
    need(row(a['files']['plan.json'], [0, 0, 33152, 1]) == encode(plan), 'zero_launch_same_PC_A_Root_plan')
    q, req, response, c = (av[n] for n in ('entry-qualified.json', 'entry-clock-request.json', 'entry-clock-response.json', 'entry-context.json'))
    unit = dict((x.split('=', 1) for x in a['never_started_unit_raw'].splitlines()))
    aggregate = 'dgx-v4-image-segment-' + stage + '.service'
    need(unit['Id'] == aggregate and unit['LoadState'] == 'not-found' and (unit['MainPID'] == unit['ExecMainPID'] == unit['ExecMainCode'] == unit['ExecMainStatus'] == '0') and (unit.get('InvocationID', '') == unit.get('ControlGroup', '') == ''), 'zero_launch_notfound_is_not_EXIT0')
    need(q['manager_identity'] == c['manager_identity'] == plan['manager_identity'] and c['PC_config_sha256'] == q['PC_config_sha256'] == plan['config_sha256'] and (sha(encode(c['current_PC_source118'])) == plan['source118_sha256']) and (req['nonce'] == response['nonce'] == stage) and (req['unit'] == q['actual_readonly_scope']['unit']['Id']), 'zero_launch_real_ready_current_and_nonce')
    need(type(s['source_files']) is dict and len(s['source_files']) == 53 and (s['source_files'] == p['sources']), 'zero_launch_saved_source53_fullSHA_F9')
    need(q['readonly_worker_sha256'] == p['sources']['segment_ready_worker.py']['sha256'] and q['producer_sha256'] == p['sources']['root_agent.py']['sha256'], 'zero_launch_saved_ready_source')
    for name in ('entry-stop-intent.json', 'entry-stop-result.json'):
        x = response['owned_stop_originals'][name]
        origin = {'raw_b64': x['raw_b64'], 'sha256': x['sha256'], 'F9': x['stat']}
        need(row(origin, [0, 0, 33152, 1]) == row(a['files'][name], [0, 0, 33152, 1]), 'zero_launch_saved_ready_ownedstop_full_originals')
    need(av['entry-stop-result.json']['rc'] == 0 and type(av['entry-stop-result.json']['rc']) is int and (av['entry-stop-result.json']['stderr_b64'] == ''), 'zero_launch_ready_ownedstop_success_only')
    positive(q['actual_readonly_scope'], req['unit'], p['sources']['segment_ready_worker.py']['sha256'], True, operation=p['old_operation'])
    return {'PC': pc, 'A': a, 'sources': s, 'actor': vals, 'plan': plan, 'ready': q, 'aggregate_unit': aggregate, 'stage_operation': stage, 'original_deadline': i['deadline_monotonic'], 'aggregate_exit_status': None, 'aggregate_context_initial_intent_cleanup': None}

def histories():
    p = APPROVED_POLICY
    need(type(p) is dict and HISTORY_ROOT is not None and (type(APPROVED_PACKED_PINS) is dict), 'zero_launch_protected_history_root_pending')
    root = Path(HISTORY_ROOT)
    need(root.is_absolute(), 'zero_launch_history_absolute_Root')
    out = []
    manifest, ms = read(root / 'zero-launch-history-origin.json', limit=2097152)
    m = strict(manifest)
    need(ms[2] == len(manifest) and ms[3:7] == OWNER and (set(m) == {'schema', 'files'}) and (m['schema'] == 'fixed-zero-launch-packed-history-origin/v1') and (set(m['files']) == set(APPROVED_PACKED_PINS) == {'pc', 'a', 'sources'}), 'zero_launch_actual_packed_origin_manifest')
    receipt, rf = read(root / 'zero-launch-publication.json', limit=2097152)
    pub = strict(receipt)
    need(rf[2] == len(receipt) and rf[3:7] == OWNER and (type(pub) is dict) and (set(pub) == {'schema', 'operation', 'origin_sha256', 'origin_F9', 'files', 'automatic_retry'}) and (pub['schema'] == 'fixed-zero-launch-data-publication/v1') and (APPROVED_PUBLICATION_OPERATION is not None) and (pub['operation'] == APPROVED_PUBLICATION_OPERATION) and (pub['origin_sha256'] == sha(manifest)) and (pub['origin_F9'] == ms) and (pub['files'] == m['files']) and (pub['automatic_retry'] is False), 'zero_launch_complete_actual_publication_original')
    for name, key in (('pc', 'PC_history_sha256'), ('a', 'A_history_sha256'), ('sources', 'A_sources_sha256')):
        packed, f = read(root / ('zero-launch-' + name + '.compact.json'), limit=2097152)
        need(f[3:7] == OWNER and f[2] == len(packed), 'zero_launch_packed_mirror_actual_Root_F9')
        ref = m['files'][name]
        need(set(ref) == {'packed_sha256', 'raw_sha256', 'F9'} and f == ref['F9'] and (sha(packed) == ref['packed_sha256'] == APPROVED_PACKED_PINS[name]), 'zero_launch_actual_packed_SHA_named_F9')
        raw = unpack(strict(packed))
        need(sha(raw) == ref['raw_sha256'] == p[key], 'zero_launch_full_uncompressed_original_SHA')
        out.append(raw)
    return tuple(out)

def actor_match(t, plan, rows):
    """Terminal callback must already consume fresh full Root scope/clock proof."""
    p = APPROVED_POLICY
    need(type(p) is dict and t['state'] == STATE and (t['schema'] == 'fixed-image-not-launched-stage-terminal/v1') and (t['stage_operation'] == plan['stage_operation'] == p['stage']) and (t['plan_sha256'] == sha(encode(plan))) and (t['history_refs'] == {k: p[k] for k in ('PC_history_sha256', 'A_history_sha256', 'A_sources_sha256')}) and (t['aggregate_exit_status'] is None) and (t['context_initial_intent_cleanup'] is None) and (t['image_imported'] is False) and (type(t['models_started']) is int) and (t['models_started'] == 0), 'zero_launch_exact_typed_history_no_fabricated_context')
    pc_raw, a_raw, s_raw = histories()
    pc = history(pc_raw, a_raw, s_raw)['PC']
    need(set(rows) == set(pc['files']) == {'intent.json', 'reserved.json', 'pulse-1.json'} and all((rows[n] == row(v, [999, 989, 33152, 1]) for n, v in pc['files'].items())), 'zero_launch_actual_still_owned_three_actor_bytes')
    return True

def remaining_protected(used, ranges, t):
    """Only exactly validated zero-launch active intervals may be retired."""
    need(t['state'] == STATE, 'zero_launch_type_not_partial_or_success')
    need(type(used) is list and type(ranges) is list and all((used.count(r) == 1 for r in ranges)), 'zero_launch_ranges_have_one_current_owner')
    out = [r for r in used if r not in ranges]
    need(len(out) + len(ranges) == len(used), 'zero_launch_remove_only_current_exact_ranges')
    return out
