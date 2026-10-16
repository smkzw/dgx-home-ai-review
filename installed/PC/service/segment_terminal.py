# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Typed stage terminals from complete real scope/Root originals."""
import base64, math, re, time
from pathlib import Path
from contract import PC_ROOT, OPERATION, need, strict, sha, encode
from old_failed_kernel import validate_failed_kernel
from observer import positive, duration
from segment_clock import consume as readiness, terminal_consume
from asset_segments import exact_ranges
APPROVED_SOURCE_INDEX = '6bd34702b74fd9cf6af1764da5a75e520b63fd7c924be424257cc59e1691ca32'
APPROVED_WORKER_SHA = 'e976ddc881c539de2984319cf96abc0e6410108e8d37a28c925e4b6526ae8b49'
APPROVED_PRODUCER_SHA = '58b4538613e4c19278f50fa9cfdcce66ce59dcfef76ea1aaa86c9b406fb0c508'
APPROVED_A_STAGE = '/opt/dgx-v4/mimo-registry-r16'
APPROVED_DATA = '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14'

def original(v):
    need(type(v) is dict and set(v) == {'raw_b64', 'sha256', 'stat'}, 'stage_original_raw_F9')
    raw = base64.b64decode(v['raw_b64'], validate=True)
    s = v['stat']
    need(sha(raw) == v['sha256'] and len(s) == 9 and all((type(x) is int for x in s)) and (s[2] == len(raw)) and (s[3:7] == [0, 0, 33152, 1]), 'stage_origin_Root600_fullF9')
    return raw

def kernel_budget(row, cg):
    need(row['cgroup'] == cg, 'stage_actual_fixed_aggregate')
    q = row['cpu.max'].split()
    need(len(q) == 2 and all((x.isascii() and x.isdigit() for x in q)) and (0 < int(q[0]) <= int(q[1])), 'stage_kernel_CPU1')
    need(row['memory.max'].isdigit() and 0 < int(row['memory.max']) <= 4294967296 and (row['memory.swap.max'] == '0') and row['pids.max'].isdigit() and (0 < int(row['pids.max']) <= 256), 'stage_kernel_memory_swap_tasks')
    lines = row['io.max'].splitlines()
    need(len(lines) == 1, 'stage_kernel_only_owned_IO_device')
    fields = lines[0].split()
    need(len(fields) in (3, 5) and fields[0] == '259:0' and (len({x.split('=')[0] for x in fields[1:]}) == len(fields) - 1), 'stage_kernel_exact_IO_fields')
    limits = dict((x.split('=', 1) for x in fields[1:]))
    need({'rbps', 'wbps'} <= set(limits) <= {'rbps', 'wbps', 'riops', 'wiops'} and all((limits[k].isascii() and limits[k].isdigit() and (0 < int(limits[k]) <= 62914560) for k in ('rbps', 'wbps'))) and all((limits[k] == 'max' for k in set(limits) - {'rbps', 'wbps'})), 'stage_kernel_actual_IO60M')

def topology(initial, clean, u, intent, stage):
    unit = u['Id']
    cg = '/system.slice/' + unit
    required = {'cpu', 'io', 'memory', 'pids'}
    iu = initial['unit']
    raw = initial['unit_raw_utf8'].encode()
    need(dict((x.split('=', 1) for x in raw.decode().splitlines())) == iu and iu['Id'] == unit and (iu['MainPID'] == u['ExecMainPID']) and (iu['InvocationID'] == u['InvocationID']) and (iu['LoadState'] == 'loaded') and (iu['ActiveState'] == 'active') and (iu['SubState'] == 'running'), 'stage_initial_unit_fullraw_identity')
    top = initial['topology']
    before = top['before']
    kernel_budget(before, cg)
    need(before['cgroup.type'] == 'domain' and before['cgroup.procs'] == u['ExecMainPID'] and (before['cgroup.subtree_control'] == '') and (required <= set(before['cgroup.controllers'].split())) and (top['ancestor_or_aggregate_writes'] == 0) and (top['self_starttick'] == intent['worker_start_ticks']), 'stage_initial_kernel_owned_bootstrap')
    cleanup = clean['kernel_after_cleanup']
    processes = cleanup['processes']
    need(len(processes) == 1, 'stage_cleanup_whole_process_tree')
    process = processes[0]
    need(process['pid'] == int(u['ExecMainPID']) and process['argv'] == ['/usr/bin/python3', '-I', '-B', str(Path(APPROVED_A_STAGE) / 'segment_worker.py'), stage] and (process['cgroup'] == cg + '/supervisor') and (process['starttick'] == intent['worker_start_ticks']), 'stage_cleanup_exact_supervisor')
    for rows in (top['after'], cleanup['rows']):
        need(type(rows) is list and len(rows) == 3 and ({r['cgroup'] for r in rows} == {cg, cg + '/supervisor', cg + '/containers'}), 'stage_complete_owned_CG_subtree')
        for r in rows:
            need(r['cgroup.type'] == 'domain' and required <= set(r['cgroup.controllers'].split()), 'stage_domain_controller_tree')
            if r['cgroup'] == cg:
                kernel_budget(r, cg)
                need(r['cgroup.procs'] == '' and required <= set(r['cgroup.subtree_control'].split()), 'stage_root_empty_and_limited')
            elif r['cgroup'] == cg + '/supervisor':
                need(r['cgroup.procs'] == u['ExecMainPID'] and r['cgroup.subtree_control'] == '', 'stage_only_supervisor_before_exit')
            else:
                need(r['cgroup.procs'] == '' and required <= set(r['cgroup.subtree_control'].split()), 'stage_no_payload_left')
    need(cleanup['only_domain'] is True and cleanup['effective_aggregate_caps'] in cleanup['rows'], 'stage_actual_cleanup_aggregate_caps')

def validate(v, config, identity, stage, now, *, historical=False):
    need(all((x is not None for x in (APPROVED_SOURCE_INDEX, APPROVED_WORKER_SHA, APPROVED_PRODUCER_SHA, APPROVED_A_STAGE, APPROVED_DATA))), 'stage_terminal_SOURCE_pending')
    need(type(v) is dict and set(v) == {'schema', 'stage_operation', 'operation_family', 'review_sha256', 'manager_identity', 'config_sha256', 'source118', 'plan_sha256', 'plan_original', 'source_index_sha256', 'worker_sha256', 'producer_sha256', 'scope', 'runtime_original', 'initial_kernel_original', 'context_original', 'intent_original', 'result_original', 'cleanup_original', 'kernel_original', 'owned_stop_originals', 'terminal_request_original', 'state', 'image_imported', 'models_started', 'observed_at'}, 'stage_terminal_complete_schema')
    need(v['schema'] == 'fixed-image-owned-stage-terminal/v1' and v['operation_family'] == OPERATION and (v['stage_operation'] == stage) and (v['review_sha256'] == config['review_sha256']) and (v['source_index_sha256'] == APPROVED_SOURCE_INDEX) and (v['worker_sha256'] == APPROVED_WORKER_SHA) and (v['producer_sha256'] == APPROVED_PRODUCER_SHA), 'stage_terminal_fixed_source_not_root_bool')
    need(v['manager_identity'] == identity and v['source118'] == config['PC_source_pins'] and (v['config_sha256'] == config['_config_sha256']) and (v['image_imported'] is False) and (type(v['models_started']) is int) and (v['models_started'] == 0), 'stage_terminal_exact_current_epoch')
    need(type(now) in (int, float) and math.isfinite(now) and (type(v['observed_at']) in (int, float)) and math.isfinite(v['observed_at']), 'stage_terminal_quiescence_freshness')
    planraw = original(v['plan_original'])
    p = strict(planraw)
    need(sha(planraw) == v['plan_sha256'] and p['stage_operation'] == stage and (p['operation_family'] == OPERATION), 'stage_terminal_exact_Root_plan')
    c, i, result, clean = (strict(original(v[k])) for k in ('context_original', 'intent_original', 'result_original', 'cleanup_original'))
    runtime = strict(original(v['runtime_original']))
    initial = strict(original(v['initial_kernel_original']))
    scope = v['scope']
    u = scope['unit']
    rawunit = scope['unit_raw_utf8'].encode()
    need(sha(rawunit) == scope['unit_raw_sha256'] and dict((x.split('=', 1) for x in rawunit.decode().splitlines())) == u, 'stage_terminal_unit_fullraw_SHA')
    unit = 'dgx-v4-image-segment-' + stage + '.service'
    need(c['operation'] == OPERATION and c['source_release_sha256'] == config['review_sha256'] and (c['manager_identity'] == identity) and (c['current_PC_source118'] == config['PC_source_pins']) and (c['PC_config_sha256'] == config['_config_sha256']) and (c['owned_aggregate_unit'] == unit) and (c['owned_aggregate_cgroup'] == '/system.slice/' + unit) and (i['unit'] == unit) and (c['stage_operation'] == i['stage_operation'] == stage) and (i['plan_sha256'] == sha(planraw)) and (i['worker_sha256'] == APPROVED_WORKER_SHA) and (i['source_index_sha256'] == APPROVED_SOURCE_INDEX) and (i['context_sha256'] == sha(original(v['context_original']))) and (i['worker_pid'] == int(u['ExecMainPID'])) and (i['invocation_id'] == u['InvocationID']) and (i['boot_id'] == scope['boot_id']), 'stage_actual_context_intent_unit_identity')
    need(scope['cgroup_procs'] == [] and u['LoadState'] == 'loaded' and (u['Id'] == unit) and (u['Type'] == 'exec') and (u['User'] == u['Group'] == 'root') and (u['MainPID'] == '0') and (u['NRestarts'] == '0') and (u['Restart'] == 'no') and (u['RemainAfterExit'] == 'yes') and (u['SendSIGKILL'] == 'no') and (u['KillMode'] == 'control-group'), 'retained_stage_owned_scope_no_retry')
    need(duration(u['CPUQuotaPerSecUSec']) == 1 and u['MemoryMax'] == '4294967296' and (u['MemorySwapMax'] == '0') and (u['TasksMax'] == '256') and (u['Nice'] == '10') and (u['IOSchedulingClass'] == '3') and (0 < duration(u['RuntimeMaxUSec']) <= p['duration_seconds'] <= 1800), 'stage_actual_private_budget')
    need(type(runtime['runtime_max_seconds']) is int and 1 <= runtime['runtime_max_seconds'] <= p['duration_seconds'] and (runtime['context_sha256'] == sha(original(v['context_original']))) and (duration(u['RuntimeMaxUSec']) == runtime['runtime_max_seconds']) and (u['Delegate'] == 'yes') and (set(u['DelegateControllers'].split()) == {'cpu', 'io', 'memory', 'pids'}) and (u['IOReadBandwidthMax'] == u['IOWriteBandwidthMax'] == '/dev/nvme0n1 62914560') and ('path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B ' + APPROVED_A_STAGE + '/segment_worker.py ' + stage + ' ;' in u['ExecStart']), 'stage_actual_runtime_IO_source')
    topology(initial, clean, u, i, stage)
    need(clean['all_owned_children_exited'] is True and clean['force_kill'] == clean['global_signals'] == 0, 'stage_actual_owned_cleanup_not_forced')
    k = validate_failed_kernel(v['kernel_original'], unit, i['worker_pid'], scope['boot_id'], v['observed_at'])
    need(c['A_boot_id'] == scope['boot_id'] and k['started_at'] <= k['finished_at'], 'stage_scope_context_kernel_actual_time')
    if v['state'] == 'ASSET_STAGE_COMPLETED':
        need(u['ExecMainCode'] == '1' and u['ExecMainStatus'] == '0' and (u['Result'] == 'success') and (u['ActiveState'] == 'active') and (u['SubState'] == 'exited') and (result['schema'] == 'fixed-image-selected-segments-returned/v1') and (result['stage_operation'] == stage) and (result['operation_family'] == OPERATION) and (result['image_imported'] is result['daemon_started'] is False) and (result['models_started'] == result['retry'] == 0) and (result['logical_range_requests'] == len(p['ranges'])), 'actual_stage_EXIT0_partial_success_not_import')
        stops = v['owned_stop_originals']
        need(type(stops) is dict and set(stops) == {'stage-stop-intent.json', 'stage-stop-result.json'}, 'actual_success_stage_archive_then_stop')
        si, sr = (strict(original(stops[n])) for n in ('stage-stop-intent.json', 'stage-stop-result.json'))
        need(si['unit'] == unit and si['invocation_id'] == u['InvocationID'] and (sr['rc'] == 0) and (base64.b64decode(sr['stderr_b64'], validate=True) == b'') and (si['observed_at'] <= sr['observed_at'] <= v['observed_at']), 'successful_stage_normal_ownedstop')
        exact_ranges(p['ranges'])
        items = result['segments']
        need(type(items) is list and len(items) == len(p['ranges']), 'all_selected_segments_complete')
        for r, a in zip(p['ranges'], items):
            need(set(a) == {'digest', 'start', 'count', 'path', 'sha256', 'F9', 'receipt_ref'} and a['path'] == str(Path(APPROVED_DATA) / 'stages' / stage / 'range/segments' / (r['digest'] + '.' + str(r['start']) + '-' + str(r['start'] + r['count'] - 1) + '.segment')) and (a['receipt_ref']['path'] == a['path'] + '.json') and re.fullmatch('[0-9a-f]{64}', a['receipt_ref']['sha256']) and (a['receipt_ref']['F9'][3:7] == [0, 0, 33152, 1]) and all((a[k] == r[k] for k in ('digest', 'start', 'count'))) and (type(a['sha256']) is str) and re.fullmatch('[0-9a-f]{64}', a['sha256']) and (a['F9'][2] == r['count']) and (a['F9'][3:7] == [0, 0, 33152, 1]), 'selected_segment_actual_SHA_F9')
    else:
        need(v['owned_stop_originals'] is None and v['state'] == 'FAILED_REGISTRY_QUIESCENT' and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '1') and (u['Result'] == 'exit-code') and (u['ActiveState'] == 'failed') and (result['schema'] == 'fixed-image-stage-failed/v1') and (result['stage_operation'] == stage) and (result['partial_preserved'] is True) and (result['error_type'] in ('Refused', 'OSError', 'FileNotFoundError', 'PermissionError', 'TimeoutError', 'ValueError')) and (result['automatic_retry'] is False), 'failed_stage_positive_quiescence_not_unknown')
    return v

def consume(read, config, identity, stage, now, *, historical=False, readiness=False):
    if readiness:
        value = globals()['readiness'](config, identity, stage, now)
        raw, st = read(PC_ROOT / 'asset-plans' / (stage + '.json'))
        return {'state': 'ASSET_STAGE_READY', 'stage_operation': stage, 'plan_sha256': sha(raw), 'entry': value}
    raw, st = read(PC_ROOT / 'asset-terminals' / (stage + '.json'), limit=4194304)
    need(st[3:7] == [0, 989, 33056, 1], 'stage_terminal_PC_Root_shared_origin')
    v = strict(raw)
    owner = v['manager_identity'] if historical else identity
    terminal_consume(read, config, owner, stage, raw, now, historical=historical)
    return validate(v, config, owner, stage, now, historical=historical)
