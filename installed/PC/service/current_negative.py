# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Future current-owned prebind proof. Every SOURCE slot defaults closed.
No old-1d297 history substitution, aggregate launch, model or network operation.
"""
import base64, math, os, re, stat, time
from pathlib import Path
from plan import need, strict, encode
from root_io import held, sha
import zero_negative as primitives
import known_prior_assets
from ready_history import positive
from stage_naming import unit as readiness_unit
import old_failed_kernel as kernel
from proc_lifetime import scan
APPROVED_POLICY = None
APPROVED_REVIEW = None
ROOT = None
OPERATION = None
OLD_STAGE = 'd8d0f06cc54a807f320d03813daf3b4b'
STATE = 'NOT_LAUNCHED_CURRENT_STAGE_QUIESCENT'
CONTROLS = frozenset(('plan.json', 'entry-context.json', 'entry-clock-request.json', 'entry-clock-start.json', 'entry-launch-intent.json', 'entry-qualified.json', 'entry-stop-intent.json', 'entry-stop-result.json', 'entry-clock-response.json'))

def original(row, owner=(0, 0, 33152, 1)):
    return primitives.original(row, owner)

def policy():
    p = APPROVED_POLICY
    need(type(p) is dict and set(p) == {'source_root', 'data_root', 'sources', 'index_sha256', 'ready_worker_sha256', 'boot_id'} and (ROOT is not None) and (APPROVED_REVIEW is not None) and (OPERATION is not None), 'current_prebind_SOURCE_None')
    need(all((type(p[k]) is str and p[k].startswith('/') for k in ('source_root', 'data_root'))) and type(p['sources']) is dict and p['sources'], 'current_prebind_fixed_namespaces')
    return p

def _base_actor(raw, current):
    policy()
    need(type(raw) is bytes and len(raw) <= 2097152, 'current_prebind_actor_cap2MiB')
    v = strict(raw)
    need(type(v) is dict and set(v) == {'schema', 'stage_operation', 'current', 'plan_original', 'records', 'ordinal', 'original_deadline_monotonic'} and (v['schema'] == 'current-stage-prebind-actor/v1') and (v['current'] == current) and (current['review_sha256'] == APPROVED_REVIEW) and (len(current['source118']) == 118), 'current_prebind_actor_current')
    stage = v['stage_operation']
    need(type(stage) is str and re.fullmatch('[0-9a-f]{32}', stage) and (stage not in (OLD_STAGE, OPERATION)), 'current_prebind_new_active_not_old_stage')
    need(type(v['ordinal']) is int and 1 <= v['ordinal'] <= 9999, 'current_prebind_full_ordinal_count')
    rows = v['records']
    names = {'intent.json', 'reserved.json'} | {'pulse-' + str(i) + '.json' for i in range(1, v['ordinal'] + 1)}
    need(type(rows) is dict and set(rows) == names, 'current_prebind_exact_actor_no_terminal_partial')
    values = {n: strict(original(r, (999, 989, 33152, 1))) for n, r in rows.items()}
    i = values['intent.json']
    r = values['reserved.json']
    p = strict(original(v['plan_original'], (0, 989, 33056, 1)))
    need(i['plan'] == p and i['plan_ref']['sha256'] == v['plan_original']['sha256'] and (i['plan_ref']['F9'] == v['plan_original']['F9']) and (i['plan_ref'] == r['plan_ref']) and (i['stage_operation'] == r['stage_operation'] == p['stage_operation'] == stage) and (i['operation_family'] == p['operation_family'] == OPERATION) and (i['source_release_sha256'] == p['review_sha256'] == APPROVED_REVIEW), 'current_prebind_full_original_plan_actor')
    need(p['manager_identity'] == current['manager_identity'] and p['config_sha256'] == current['config_sha256'] and (p['source118_sha256'] == sha(encode(current['source118']))) and (p['automatic_retry'] is False), 'current_prebind_full118_plan')
    deadline = v['original_deadline_monotonic']
    need(type(deadline) in (int, float) and math.isfinite(deadline) and (i['deadline_monotonic'] == r['deadline_monotonic'] == p['PC_plan_deadline_monotonic'] == deadline), 'current_prebind_original_deadline')
    prior = r['observed_at']
    for k in range(1, v['ordinal'] + 1):
        q = values['pulse-' + str(k) + '.json']
        need(q['schema'] == 'sole-Manager-private-CPU-reservation-pulse/v1' and q['operation'] == OPERATION and (q['source_release_sha256'] == APPROVED_REVIEW) and (q['config_sha256'] == current['config_sha256']) and (q['manager_epoch_sha256'] == sha(encode(current['source118']))) and (q['ordinal'] == k) and (q['clear_reservation_original'] == r) and (q['clear_reservation_sha256'] == sha(encode(r))) and (type(q['remaining_seconds']) in (int, float)) and (0 < q['remaining_seconds'] <= p['duration_seconds']) and (prior <= q['observed_at']), 'current_prebind_all_original_pulses')
        src = q['manager_source']
        need(type(src) is dict and set(src) == {'PC_source_files', 'boot_id', 'lease_dev_inode', 'manager_pid', 'manager_start_ticks'} and (src['boot_id'] == current['manager_identity']['boot_id']) and (src['manager_pid'] == current['manager_identity']['pid']) and (src['manager_start_ticks'] == current['manager_identity']['start_ticks']) and (src['lease_dev_inode'] == [2096, 69257]) and (set(src['PC_source_files']) == set(current['source118'])), 'current_prebind_each_pulse_same_physical_source118')
        for name, row in src['PC_source_files'].items():
            need(set(row) == {'sha256', 'stat'} and row['sha256'] == current['source118'][name] and (len(row['stat']) == 9) and all((type(x) is int and x >= 0 for x in row['stat'])) and (row['stat'][3] == 0) and (row['stat'][4] in (0, 989)) and stat.S_ISREG(row['stat'][5]) and (not row['stat'][5] & 18) and (row['stat'][6] == 1), 'current_prebind_each_pulse_full_source_F9')
        prior = q['observed_at']
    need(i['issued_at'] <= r['observed_at'], 'current_prebind_actor_causal_order')
    return v

def checked_request(raw, current):
    policy()
    r = strict(raw)
    need(type(r) is dict and set(r) == {'schema', 'operation', 'nonce', 'current', 'actor_sha256', 'stage_operation'} and (r['schema'] == 'current-stage-prebind-request/v1') and (r['operation'] == OPERATION) and (r['current'] == current) and (current['review_sha256'] == APPROVED_REVIEW) and (type(r['nonce']) is str) and re.fullmatch('[0-9a-f]{32}', r['nonce']) and (type(r['actor_sha256']) is str) and re.fullmatch('[0-9a-f]{64}', r['actor_sha256']), 'current_prebind_exact_request')
    need(r['nonce'] == r['stage_operation'], 'current_prebind_nonce_is_sealed_active_stage')
    ident = current['manager_identity']
    need(set(current) == {'review_sha256', 'config_sha256', 'manager_identity', 'source118'} and type(ident) is dict and (set(ident) == {'pid', 'start_ticks', 'boot_id', 'invocation_id'}) and (type(ident['pid']) is int) and (ident['pid'] > 1) and (type(ident['start_ticks']) is str) and re.fullmatch('[1-9][0-9]*', ident['start_ticks']) and re.fullmatch('[0-9a-f]{32}', ident['invocation_id']) and all((re.fullmatch('[0-9a-f]{64}', current[k]) for k in ('review_sha256', 'config_sha256'))) and (len(current['source118']) == 118) and all((type(k) is str and k.startswith('/') and (type(x) is str) and re.fullmatch('[0-9a-f]{64}', x) for k, x in current['source118'].items())), 'current_prebind_exact_live_identity118')
    return r

def snapshot(a, current):
    p = policy()
    stage = a['stage_operation']
    root = Path(p['source_root'])
    control = root / 'stages' / stage
    files = {}
    sources = {}
    for name, row in p['sources'].items():
        need(type(name) is str and (not name.startswith('/')) and all((x not in ('', '.', '..') for x in name.split('/'))), 'current_prebind_fixed_source_leaf')
        raw, s = held(root / name, row['sha256'], cap=2097152, mode=384)
        need(s == row['F9'], 'current_prebind_source_F9')
        sources[name] = {'sha256': sha(raw), 'F9': s}
    ix = strict(held(root / 'source-index.json', p['index_sha256'], mode=384)[0])
    need(ix['operation'] == OPERATION and ix['review_sha256'] == APPROVED_REVIEW and all((sources[n]['sha256'] == pin for n, pin in ix['files'].items())), 'current_prebind_exact_source_index')
    d = primitives.directory(control, CONTROLS | {'readiness'})
    for name in CONTROLS:
        raw, s = held(control / name, mode=384)
        files[name] = {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': s}
    need(sha(original(files['plan.json'])) == a['plan_original']['sha256'], 'current_prebind_A_PC_same_plan')
    c = strict(original(files['entry-context.json']))
    need(c['manager_identity'] == current['manager_identity'] and c['PC_config_sha256'] == current['config_sha256'] and (c['current_PC_source118'] == current['source118']), 'current_prebind_A_exact_current')
    q = strict(original(files['entry-qualified.json']))
    ready = q['actual_readonly_scope']
    positive(ready, readiness_unit(stage), p['ready_worker_sha256'], True, operation=OPERATION)
    need(q['manager_identity'] == current['manager_identity'] and q['PC_config_sha256'] == current['config_sha256'] and (q['current_PC_source118'] == current['source118']), 'current_prebind_ready_same_current')
    return {'sources': sources, 'controls': files, 'directory': d, 'ready_pid': int(ready['unit']['ExecMainPID'])}

def check_snapshot(s, a, current):
    p = policy()
    need(set(s) == {'sources', 'controls', 'directory', 'ready_pid'} and s['sources'] == p['sources'] and (set(s['controls']) == CONTROLS), 'current_prebind_snapshot_full_source_controls')
    for v in s['controls'].values():
        original(v)
    need(sha(original(s['controls']['plan.json'])) == a['plan_original']['sha256'], 'current_prebind_snapshot_plan_match')
    d = s['directory']
    need(d['path'] == p['source_root'] + '/stages/' + a['stage_operation'] and d['entries'] == sorted(CONTROLS | {'readiness'}), 'current_prebind_no_context_launch_terminal')
    q = strict(original(s['controls']['entry-qualified.json']))
    scope = q['actual_readonly_scope']
    positive(scope, readiness_unit(a['stage_operation']), p['ready_worker_sha256'], True, operation=OPERATION)
    need(s['ready_pid'] == int(scope['unit']['ExecMainPID']) and scope['boot_id'] == p['boot_id'] and (q['manager_identity'] == current['manager_identity']) and (q['current_PC_source118'] == current['source118']) and (q['PC_config_sha256'] == current['config_sha256']) and (q['schema'] == 'registry-R26-A-entry-qualified/v1') and (q['operation'] == OPERATION) and (q['source_index_sha256'] == p['index_sha256']) and (scope['worker_source']['path'] == p['source_root'] + '/segment_ready_worker.py'), 'current_prebind_actual_saved_ready_PID')
    c = strict(original(s['controls']['entry-context.json']))
    need(c['manager_identity'] == current['manager_identity'] and c['PC_config_sha256'] == current['config_sha256'] and (c['current_PC_source118'] == current['source118']), 'current_prebind_snapshot_context_exact')
    validate_directory(s['directory'], p['source_root'] + '/stages/' + a['stage_operation'])
    return s

def validate_directory(d, path):
    need(type(d) is dict and set(d) == {'path', 'F9', 'entries', 'anchors'} and (d['path'] == path) and (type(d['entries']) is list) and (d['entries'] == sorted(set(d['entries']))) and all((type(x) is str and x not in ('', '.', '..') and ('/' not in x) for x in d['entries'])), 'current_prebind_exact_directory_record')

    def good(f):
        return type(f) is list and len(f) == 9 and all((type(x) is int and x >= 0 for x in f)) and (f[0] > 0) and (f[1] > 0) and (f[3] == 0) and stat.S_ISDIR(f[5]) and (not f[5] & 18)
    expected = ['/'] + ['/' + '/'.join(Path(path).parts[1:i]) for i in range(2, len(Path(path).parts) + 1)]
    need(good(d['F9']) and [x['path'] for x in d['anchors']] == expected and all((set(x) == {'path', 'F9'} and good(x['F9']) for x in d['anchors'])) and (d['anchors'][-1]['F9'] == d['F9']), 'current_prebind_all_Root_anchors')
    return d

def collect():
    p = policy()
    need(os.getuid() == os.geteuid() == 0, 'current_prebind_actual_Root')
    start = time.time()
    mono = time.monotonic()
    end = mono + 30
    request, rs = held(Path(ROOT) / 'request.json', mode=384)
    current = strict(held(Path(ROOT) / 'current-context.json', mode=384)[0])
    r = checked_request(request, current)
    ar, afs = held(Path(ROOT) / 'actor.json', r['actor_sha256'], mode=384)
    a = actor(ar, current)
    need(a['stage_operation'] == r['stage_operation'], 'current_prebind_actor_request_same_stage')
    s = snapshot(a, current)
    absence = known_prior_assets.collect(p, a, current, end)
    unit = 'dgx-v4-image-segment-' + a['stage_operation'] + '.service'
    kernel.ALLOWED_UNIT = unit
    k = kernel.kernel_after_stop(unit, s['ready_pid'], p['boot_id'], end)
    processes = primitives.no_target(scan(Path(p['source_root'])), dict(p, aggregate_unit=unit))
    need(snapshot(a, current) == s and known_prior_assets.recheck(absence, known_prior_assets.collect(p, a, current, end)) and (time.monotonic() < end), 'current_prebind_recheck_whole30')
    return {'schema': 'current-stage-prebind-quiescent/v1', 'state': STATE, 'stage_operation': a['stage_operation'], 'request_original': {'raw_b64': base64.b64encode(request).decode(), 'sha256': sha(request), 'F9': rs}, 'actor_original': {'raw_b64': base64.b64encode(ar).decode(), 'sha256': sha(ar), 'F9': afs}, 'snapshot': s, 'data_absence': absence, 'kernel_original': k, 'process_scan': processes, 'aggregate_exit_status': None, 'context_initial_intent_cleanup': None, 'GET': 0, 'models_started': 0, 'image_imported': False, 'started_at': start, 'finished_at': time.time(), 'monotonic_elapsed': time.monotonic() - mono}

def validate(v, history_raw, current):
    p = policy()
    a = actor(history_raw, current)
    r = checked_request(original(v['request_original']), current)
    need(set(v) == {'schema', 'state', 'stage_operation', 'request_original', 'actor_original', 'snapshot', 'data_absence', 'kernel_original', 'process_scan', 'aggregate_exit_status', 'context_initial_intent_cleanup', 'GET', 'models_started', 'image_imported', 'started_at', 'finished_at', 'monotonic_elapsed'} and v['schema'] == 'current-stage-prebind-quiescent/v1' and (v['state'] == STATE) and (v['stage_operation'] == r['stage_operation'] == a['stage_operation']) and (original(v['actor_original']) == history_raw) and (r['actor_sha256'] == sha(history_raw)), 'current_prebind_exact_typed_origin')
    need(v['aggregate_exit_status'] is v['context_initial_intent_cleanup'] is None and v['image_imported'] is False and (type(v['GET']) is int) and (v['GET'] == 0) and (type(v['models_started']) is int) and (v['models_started'] == 0), 'current_prebind_not_worker_success')
    need(all((type(v[k]) in (int, float) and math.isfinite(v[k]) for k in ('started_at', 'finished_at', 'monotonic_elapsed'))) and v['started_at'] <= v['finished_at'] and (0 <= v['monotonic_elapsed'] <= 30), 'current_prebind_A_whole30')
    check_snapshot(v['snapshot'], a, current)
    known_prior_assets.validate(v['data_absence'], p, a, current, (v['started_at'], v['finished_at']))
    kernel.validate_failed_kernel(v['kernel_original'], 'dgx-v4-image-segment-' + a['stage_operation'] + '.service', v['snapshot']['ready_pid'], p['boot_id'], v['started_at'])
    primitives.no_target(v['process_scan'], dict(p, aggregate_unit='dgx-v4-image-segment-' + a['stage_operation'] + '.service'))
    need(v['kernel_original']['finished_at'] <= v['finished_at'], 'current_prebind_kernel_time')
    return {'schema': 'fixed-image-current-not-launched-terminal/v2', 'component_version': known_prior_assets.VERSION, 'state': STATE, 'stage_operation': a['stage_operation'], 'actor_sha256': sha(history_raw), 'plan_sha256': a['plan_original']['sha256'], 'original_deadline_monotonic': a['original_deadline_monotonic'], 'work_deadline_extended': False, 'aggregate_exit_status': None, 'context_initial_intent_cleanup': None, 'GET': 0, 'models_started': 0, 'image_imported': False}

def actor(raw, current):
    need(type(raw) is bytes and len(raw) <= 2097152, 'current_prebind_actor_cap2MiB')
    v = strict(raw)
    need(type(v) is dict and v.get('schema') == 'current-stage-prebind-actor/v2' and ('known_prior_assets' in v), 'current_prebind_known_prior_version')
    core = dict(v)
    prior = core.pop('known_prior_assets')
    core['schema'] = 'current-stage-prebind-actor/v1'
    _base_actor(encode(core), current)
    known_prior_assets.shape(prior, v['stage_operation'])
    return v
