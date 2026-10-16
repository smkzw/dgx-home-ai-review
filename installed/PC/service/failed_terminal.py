# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual retained failed-owned terminal; never an import success receipt."""
import base64, math, re, time
from pathlib import Path
import plan
from root_io import held, sha, fresh
from old_failed_kernel import kernel_after_stop, validate_failed_kernel
APPROVED_FAILURE_PRODUCER_SHA = '5cf4d64d0d9b6e83f461c76babe84faa9128d4972f78d34f16eb8c3d7921eaf8'
APPROVED_FETCH_WORKER_SHA = 'c31ec3088783e274c8d4a12a5234d702a5058e2a2ff315c4c7d292ebfff9a05c'
APPROVED_FETCH_INDEX_SHA = '6bd34702b74fd9cf6af1764da5a75e520b63fd7c924be424257cc59e1691ca32'
PATH = Path(plan.PC_STAGE) / 'failed-registry-terminal.json'

def envelope(raw, st):
    return {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'stat': st}

def original(row):
    plan.need(type(row) is dict and set(row) == {'raw_b64', 'sha256', 'stat'}, 'failed_terminal_original_schema')
    raw = base64.b64decode(row['raw_b64'], validate=True)
    s = row['stat']
    plan.need(base64.b64encode(raw).decode() == row['raw_b64'] and sha(raw) == row['sha256'] and (type(s) is list) and (len(s) == 9) and all((type(x) is int for x in s)) and (s[2] == len(raw)) and (s[3:7] == [0, 0, 33152, 1]), 'failed_terminal_original_fullSHA_F9')
    return raw

def validate(v, c, identity, now, *, worker_sha, producer_sha, index_sha):
    plan.need(type(v) is dict and set(v) == {'schema', 'operation', 'producer_sha256', 'worker_sha256', 'source_index_sha256', 'source_release_sha256', 'manager_identity', 'current_PC_source118', 'config_sha256', 'context_original', 'runtime_original', 'initial_kernel_original', 'failed_original', 'cleanup_original', 'intent_original', 'unit_original', 'worker_original', 'kernel_original', 'observed_at', 'CPU_success', 'image_imported', 'models_started'}, 'fixed_failed_terminal_fullschema')
    plan.need(v['schema'] == 'registry-R26-failed-owned-quiescent-qualified/v1' and v['operation'] == plan.OPERATION and (v['producer_sha256'] == producer_sha) and (v['worker_sha256'] == worker_sha) and (v['source_release_sha256'] == c['review_sha256']) and (v['manager_identity'] == identity) and (v['current_PC_source118'] == c['PC_source_pins']) and (v['config_sha256'] == c['_config_sha256']), 'failed_terminal_current_source_epoch')
    plan.need(v['CPU_success'] is v['image_imported'] is False and type(v['models_started']) is int and (v['models_started'] == 0) and (type(now) in (int, float)) and math.isfinite(now) and (type(v['observed_at']) in (int, float)) and math.isfinite(v['observed_at']) and (0 <= now - v['observed_at'] <= 30), 'failed_terminal_fresh_quiescence_not_success')
    ctx = plan.strict(original(v['context_original']))
    runtime = plan.strict(original(v['runtime_original']))
    failed = plan.strict(original(v['failed_original']))
    clean = plan.strict(original(v['cleanup_original']))
    intent = plan.strict(original(v['intent_original']))
    worker = original(v['worker_original'])
    plan.need(sha(worker) == worker_sha, 'failed_terminal_exact_reviewed_worker')
    plan.need(v['source_index_sha256'] == index_sha, 'failed_terminal_exact_current_index')
    plan.need(ctx['operation'] == plan.OPERATION and ctx['source_release_sha256'] == c['review_sha256'] and (ctx['manager_identity'] == identity) and (ctx['current_PC_source118'] == c['PC_source_pins']) and (ctx['PC_config_sha256'] == c['_config_sha256']) and (ctx['owned_aggregate_unit'] == plan.UNIT) and (ctx['owned_aggregate_cgroup'] == plan.CG), 'failed_terminal_actual_bound_context')
    plan.need(failed['schema'] == 'registry-R26-A-owned-phase-failed-preserved/v1' and failed['operation'] == plan.OPERATION and (failed['error_type'] in ('Refused', 'ValueError', 'FileNotFoundError', 'TimeoutError', 'TimeoutExpired', 'PermissionError', 'OSError', 'KeyError', 'TypeError')) and (failed['automatic_retry'] is False) and (failed['partial_preserved'] is True) and (failed['phase'] in ('registry.preflight', 'registry.download', 'registry.download_terminal', 'registry.config_raw', 'registry.config_CLI', 'registry.config_merged', 'registry.daemon_start', 'registry.import', 'registry.content_verify')), 'known_failed_owned_phase_not_unknown')
    plan.need(intent['operation'] == plan.OPERATION and intent['source_review_sha256'] == c['review_sha256'] and (type(intent['retry']) is int) and (intent['retry'] == 0) and (intent['original_grant'] == ctx['initial_pulse_original']), 'failed_terminal_original_owned_intent')
    uo = v['unit_original']
    plan.need(type(uo) is dict and set(uo) == {'raw_utf8', 'sha256', 'boot_id', 'cgroup_procs'}, 'failed_unit_exact_schema')
    raw = uo['raw_utf8'].encode()
    lines = raw.decode().splitlines()
    plan.need(sha(raw) == uo['sha256'] and len(lines) == len(set((x.split('=', 1)[0] for x in lines))), 'failed_unit_original_fullraw')
    u = dict((x.split('=', 1) for x in lines))
    plan.need(u['Id'] == plan.UNIT and u['LoadState'] == 'loaded' and (u['ActiveState'] == 'failed') and (u['MainPID'] == '0') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '1') and (u['Result'] == 'exit-code') and (u['NRestarts'] == '0') and (int(u['ExecMainPID']) > 1) and re.fullmatch('[0-9a-f]{32}', u['InvocationID']) and (uo['cgroup_procs'] == []), 'actual_retained_EXIT1_not_missing_or_live')
    plan.need(u['Type'] == 'exec' and u['User'] == u['Group'] == 'root' and (u['Restart'] == 'no') and (u['RemainAfterExit'] == 'yes') and (u['SendSIGKILL'] == 'no') and (u['KillMode'] == 'control-group') and (u['MemoryMax'] == '4294967296') and (u['MemorySwapMax'] == '0') and (u['TasksMax'] == '256') and (u['Nice'] == '10') and (u['IOSchedulingClass'] == '3') and (u['CPUQuotaPerSecUSec'] == '1s') and ('path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B ' + plan.STAGE + '/root_worker.py ;' in u['ExecStart']), 'failed_terminal_actual_owned_unit_caps_source')
    from observer import duration
    plan.need(type(runtime['runtime_max_seconds']) is int and 1 <= runtime['runtime_max_seconds'] <= 1800 and (runtime['context_sha256'] == v['context_original']['sha256']) and (duration(u['RuntimeMaxUSec']) == runtime['runtime_max_seconds']) and (u['Delegate'] == 'yes') and (set(u['DelegateControllers'].split()) == {'cpu', 'io', 'memory', 'pids'}) and (u['IOReadBandwidthMax'] == u['IOWriteBandwidthMax'] == '/dev/nvme0n1 62914560'), 'failed_terminal_original_kernel_RuntimeMax_IO')
    plan.need(clean['all_owned_children_exited'] is True and clean['force_kill'] == clean['global_signals'] == 0 and (len(clean['kernel_after_cleanup']['processes']) == 1), 'failed_owned_cleanup_complete_no_force')
    plan.need(intent['source_index_sha256'] == index_sha and intent['context_sha256'] == v['context_original']['sha256'] and (intent['worker_sha256'] == worker_sha) and (intent['worker_pid'] == int(u['ExecMainPID'])) and (intent['invocation_id'] == u['InvocationID']) and (intent['boot_id'] == uo['boot_id']) and (intent['unit'] == plan.UNIT), 'failed_terminal_intent_same_unit_inv_boot_worker_context')
    process = clean['kernel_after_cleanup']['processes'][0]
    plan.need(process['pid'] == int(u['ExecMainPID']) and process['argv'] == ['/usr/bin/python3', '-I', '-B', plan.STAGE + '/root_worker.py'] and (process['cgroup'] == plan.CG + '/supervisor') and (process['starttick'] == intent['worker_start_ticks']), 'failed_cleanup_same_original_supervisor')
    initial = plan.strict(original(v['initial_kernel_original']))
    iraw = initial['unit_raw_utf8'].encode()
    iu = initial['unit']
    plan.need(dict((x.split('=', 1) for x in iraw.decode().splitlines())) == iu and iu['Id'] == plan.UNIT and (iu['MainPID'] == u['ExecMainPID']) and (iu['InvocationID'] == u['InvocationID']) and (iu['LoadState'] == 'loaded') and (iu['ActiveState'] == 'active') and (iu['SubState'] == 'running'), 'failed_initial_actual_unit_identity')
    top = initial['topology']
    required = {'cpu', 'io', 'memory', 'pids'}
    before = top['before']
    plan.kernel(before)
    plan.need(before['cgroup'] == plan.CG and before['cgroup.type'] == 'domain' and (before['cgroup.procs'] == u['ExecMainPID']) and (before['cgroup.subtree_control'] == '') and (required <= set(before['cgroup.controllers'].split())) and (top['ancestor_or_aggregate_writes'] == 0) and (top['self_starttick'] == intent['worker_start_ticks']), 'failed_initial_positive_kernel_no_unknown_or_unsafe_bootstrap')
    for rows in (top['after'], clean['kernel_after_cleanup']['rows']):
        plan.need(type(rows) is list and {r['cgroup'] for r in rows} == {plan.CG, plan.CG + '/supervisor', plan.CG + '/containers'} and (len(rows) == 3), 'failed_quiescent_only_fixed_domain_tree')
        for r in rows:
            plan.need(r['cgroup.type'] == 'domain' and required <= set(r['cgroup.controllers'].split()), 'failed_quiescent_no_threaded_or_missing_controller')
            if r['cgroup'] == plan.CG:
                plan.kernel(r)
                plan.need(r['cgroup.procs'] == '' and required <= set(r['cgroup.subtree_control'].split()), 'failed_aggregate_empty_and_limited')
            elif r['cgroup'] == plan.CG + '/supervisor':
                plan.need(r['cgroup.procs'] == u['ExecMainPID'] and r['cgroup.subtree_control'] == '', 'failed_only_owned_supervisor_before_exit')
            else:
                plan.need(r['cgroup.procs'] == '' and required <= set(r['cgroup.subtree_control'].split()), 'failed_empty_owned_payload')
    plan.need(clean['kernel_after_cleanup']['only_domain'] is True and clean['kernel_after_cleanup']['effective_aggregate_caps'] in clean['kernel_after_cleanup']['rows'], 'failed_cleanup_whole_kernel_effective_caps')
    k = validate_failed_kernel(v['kernel_original'], plan.UNIT, int(u['ExecMainPID']), uo['boot_id'], v['observed_at'])
    plan.need(ctx['A_boot_id'] == uo['boot_id'] and v['observed_at'] <= k['started_at'] <= k['finished_at'] <= now, 'failed_actual_scope_context_kernel_time_order')
    return v

def produce(read, unit_raw, context, index_sha, worker_sha, now):
    u = dict((x.split('=', 1) for x in unit_raw.decode().splitlines()))
    pid = int(u['ExecMainPID'])
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    start = time.time()
    rows = {n: envelope(*read(Path(plan.ROOT) / n, mode=384)) for n in ('failed.json', 'owned-cleanup.json', 'intent.json')}
    ctx = envelope(*read(Path(plan.STAGE) / 'context.json', mode=384))
    worker = envelope(*read(Path(plan.STAGE) / 'root_worker.py', worker_sha, mode=384))
    index, ix = read(Path(plan.STAGE) / 'source-index.json', index_sha, mode=384)
    plan.need(plan.strict(index)['review_sha256'] == context['source_release_sha256'], 'failed_current_source_index')
    for n, pin in plan.strict(index)['files'].items():
        read(Path(plan.STAGE) / n, pin, cap=2097152)
    kernel = kernel_after_stop(plan.UNIT, pid, boot, time.monotonic() + 15)
    v = {'schema': 'registry-R26-failed-owned-quiescent-qualified/v1', 'operation': plan.OPERATION, 'producer_sha256': sha(Path(__file__).read_bytes()), 'worker_sha256': worker_sha, 'source_index_sha256': index_sha, 'source_release_sha256': context['source_release_sha256'], 'manager_identity': context['manager_identity'], 'current_PC_source118': context['current_PC_source118'], 'config_sha256': context['PC_config_sha256'], 'context_original': ctx, 'runtime_original': envelope(*read(Path(plan.STAGE) / 'runtime-max-original.json', mode=384)), 'initial_kernel_original': envelope(*read(Path(plan.ROOT) / 'initial-kernel-unit.json', mode=384)), 'failed_original': rows['failed.json'], 'cleanup_original': rows['owned-cleanup.json'], 'intent_original': rows['intent.json'], 'unit_original': {'raw_utf8': unit_raw.decode(), 'sha256': sha(unit_raw), 'boot_id': boot, 'cgroup_procs': []}, 'worker_original': worker, 'kernel_original': kernel, 'observed_at': start, 'CPU_success': False, 'image_imported': False, 'models_started': 0}
    cfg = {'review_sha256': context['source_release_sha256'], 'PC_source_pins': context['current_PC_source118'], '_config_sha256': context['PC_config_sha256']}
    validate(v, cfg, context['manager_identity'], time.time(), worker_sha=worker_sha, producer_sha=sha(Path(__file__).read_bytes()), index_sha=index_sha)
    return v

def consume(read, config, identity, now, *, historical=False):
    plan.need(APPROVED_FAILURE_PRODUCER_SHA is not None and APPROVED_FETCH_WORKER_SHA is not None and (APPROVED_FETCH_INDEX_SHA is not None), 'failed_terminal_SOURCE_pending')
    raw, st = read(PATH, limit=4194304)
    plan.need(st[2] == len(raw) and st[3:7] == [0, 989, 33056, 1], 'failed_terminal_actual_Root_mirror')
    v = plan.strict(raw)
    if historical:
        identity = v['manager_identity']
        now = v['kernel_original']['finished_at']
    validate(v, config, identity, now, worker_sha=APPROVED_FETCH_WORKER_SHA, producer_sha=APPROVED_FAILURE_PRODUCER_SHA, index_sha=APPROVED_FETCH_INDEX_SHA)
    return dict(v, receipt_sha256=sha(raw), receipt_F9=st)
