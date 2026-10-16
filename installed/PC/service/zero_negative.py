# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One fixed NOT_LAUNCHED stage; historical Mac evidence never becomes Root origin."""
import base64, math, os, re, stat, time
import not_launched_history as zero_history
from pathlib import Path
from plan import need, strict, encode
from root_io import held, f9, sha
from ready_history import positive
import old_failed_kernel as kernel
from proc_lifetime import scan, validate as validate_processes
APPROVED_POLICY = None
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
ROOT = None
UNIT = None
OPERATION = '2b9e9b631cebc13ae6b1550ee59c13ed'

def original(row, owner=(0, 0, 33152, 1)):
    need(type(row) is dict and set(row) == {'raw_b64', 'sha256', 'F9'}, 'not_launched_exact_original')
    raw = base64.b64decode(row['raw_b64'], validate=True)
    s = row['F9']
    need(type(s) is list and len(s) == 9 and all((type(x) is int and x >= 0 for x in s)) and (s[2] == len(raw) <= 2097152) and (s[3:7] == list(owner)) and (sha(raw) == row['sha256']), 'not_launched_original_SHA_F9')
    return raw

def history(raw):
    pc_raw, a_raw, s_raw = zero_history.histories()
    need(raw == a_raw, 'zero_launch_exact_A_history_argument')
    v = zero_history.history(pc_raw, a_raw, s_raw)
    a = v['A']
    q = v['ready']
    p = APPROVED_POLICY
    need(p == zero_history.APPROVED_POLICY, 'zero_launch_single_history_policy')
    return dict(a, control_originals=a['files'], control_directories={'.': a['directory_F9']}, boot_id=q['actual_readonly_scope']['boot_id'])

def checked_request(raw, current):
    r = strict(raw)
    c = current
    need(APPROVED_REVIEW is not None, 'not_launched_review_SOURCE_pending')
    need(type(c) is dict and set(c) == {'review_sha256', 'config_sha256', 'manager_identity', 'source118'} and (len(c['source118']) == 118), 'not_launched_current_SOURCE_pending')
    i = c['manager_identity']
    need(type(i) is dict and set(i) == {'pid', 'start_ticks', 'boot_id', 'invocation_id'} and (type(i['pid']) is int) and (i['pid'] > 1) and (type(i['start_ticks']) is str) and re.fullmatch('[1-9][0-9]*', i['start_ticks']) and (type(i['invocation_id']) is str) and re.fullmatch('[0-9a-f]{32}', i['invocation_id']) and (type(i['boot_id']) is str) and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}', i['boot_id']), 'not_launched_typed_current_identity')
    need(all((type(c[k]) is str and re.fullmatch('[0-9a-f]{64}', c[k]) for k in ('review_sha256', 'config_sha256'))) and all((type(k) is str and k.startswith('/') and (type(v) is str) and re.fullmatch('[0-9a-f]{64}', v) for k, v in c['source118'].items())), 'not_launched_typed_current_source')
    need(type(r) is dict and set(r) == {'schema', 'operation', 'nonce', 'current', 'history_sha256'} and (r['schema'] == 'stage-not-launched-request/v1') and (r['operation'] == OPERATION) and (type(r['nonce']) is str) and re.fullmatch('[0-9a-f]{32}', r['nonce']) and (r['current'] == c) and (c['review_sha256'] == APPROVED_REVIEW) and (r['history_sha256'] == APPROVED_POLICY['A_history_sha256']), 'not_launched_exact_fresh_request')
    return r

def directory(path, entries=None):
    path = Path(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fds = [(fd, '/', f9(os.fstat(fd)), None, None)]
    try:
        current = Path('/')
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            current = current / part
            z = os.fstat(child)
            need(z.st_uid == 0 and stat.S_ISDIR(z.st_mode) and (not z.st_mode & 18), 'not_launched_Root_directory')
            fds.append((child, str(current), f9(z), fd, part))
            fd = child
        names = sorted(os.listdir(fd))
        need(entries is None or names == sorted(entries), 'not_launched_exact_entries')
        a = f9(os.fstat(fd))
        need(a == f9(path.lstat()), 'not_launched_directory_named_FD')
        for child, _, before, parent, name in fds:
            z = f9(os.fstat(child))
            n = f9(os.stat(name, dir_fd=parent, follow_symlinks=False)) if parent is not None else f9(Path('/').lstat())
            need(all((z[i] == n[i] == before[i] for i in (0, 1, 3, 4, 5))), 'not_launched_parent_identity')
        return {'path': str(path), 'F9': a, 'entries': names, 'anchors': [{'path': name, 'F9': s} for _, name, s, _, _ in fds]}
    finally:
        for fd, *_ in reversed(fds):
            os.close(fd)

def data_absence(p):
    path = Path(p['data_root'])
    parent = directory(path.parent)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError as e:
            need(e.errno == 2, 'not_launched_data_positive_ENOENT')
        else:
            need(False, 'not_launched_payload_present_unknown')
        need(f9(os.fstat(fd)) == parent['F9'] == f9(path.parent.lstat()), 'not_launched_absence_parent_stable')
    finally:
        os.close(fd)
    return {'path': str(path), 'errno': 2, 'parent': parent}

def source_and_controls(p, h):
    out = {}
    root = Path(p['source_root'])
    for name, row in p['sources'].items():
        raw, s = held(root / name, row['sha256'], cap=2097152, mode=384)
        need(s == row['F9'], 'not_launched_source_F9')
        out[name] = {'sha256': sha(raw), 'F9': s}
    index = strict(held(root / 'source-index.json', p['sources']['source-index.json']['sha256'], mode=384)[0])
    need(index['operation'] == p['old_operation'] and len(index['files']) == 47 and all((out[n]['sha256'] == pin for n, pin in index['files'].items())), 'not_launched_source_index_exact_closure')
    control = root / 'stages' / p['stage']
    files = {}
    for name, row in h['control_originals'].items():
        raw, s = held(control / name, row['sha256'], mode=384)
        need(raw == original(row) and s == row['F9'], 'not_launched_control_raw_F9')
        files[name] = {'sha256': sha(raw), 'F9': s}
    d = directory(control, sorted(files) + ['readiness'])
    need(d['F9'] == h['control_directories']['.'], 'not_launched_control_directory_F9')
    return {'sources': out, 'controls': files, 'directories': [d]}

def no_target(processes, p):
    validate_processes(processes, Path(p['source_root']))
    markers = (p['data_root'], p['aggregate_unit'])
    for event in processes['events']:
        for rawset in [event['partial']] + ([event['row']['originals']] if event['complete_identity'] else []):
            for name, row in rawset.items():
                if name.startswith(('cmdline_', 'cgroup_')):
                    need(not any((x.encode() in base64.b64decode(row['raw_b64'], validate=True) for x in markers)), 'not_launched_target_process')
        for exe in event['partial_executable'] + ([event['row']['exe']] if event['complete_identity'] else []):
            need(exe is None or not any((x in exe for x in markers)), 'not_launched_target_executable')
    return processes

def collect():
    p = APPROVED_POLICY
    need(type(p) is dict and os.getuid() == os.geteuid() == 0, 'not_launched_Root_SOURCE_pending')
    start = time.time()
    mono = time.monotonic()
    end = mono + 30
    request, rs = held(ROOT / 'request.json', mode=384)
    current = strict(held(ROOT / 'current-context.json', mode=384)[0])
    r = checked_request(request, current)
    hist, hs = held(ROOT / 'historical-MAC-original.json', p['A_history_sha256'], cap=2097152, mode=384)
    h = history(hist)
    need(h['observed_at'] <= start, 'not_launched_history_before_fresh_collection')
    snapshot = source_and_controls(p, h)
    absence = data_absence(p)
    kernel.ALLOWED_UNIT = p['aggregate_unit']
    k = kernel.kernel_after_stop(p['aggregate_unit'], p['ready_pid'], p['boot_id'], end)
    processes = no_target(scan(Path(p['source_root'])), p)
    need(source_and_controls(p, h) == snapshot and data_absence(p) == absence and (time.monotonic() < end), 'not_launched_full_originals_recheck30')
    return {'schema': 'stage-not-launched-quiescent/v1', 'state': 'NOT_LAUNCHED_QUIESCENT', 'operation': OPERATION, 'stage_operation': p['stage'], 'request_original': {'raw_b64': base64.b64encode(request).decode(), 'sha256': sha(request), 'F9': rs}, 'history_mirror': {'path': str(ROOT / 'historical-MAC-original.json'), 'sha256': sha(hist), 'F9': hs, 'original_MAC_sha256': p['A_history_sha256']}, 'snapshot': snapshot, 'data_absence': absence, 'kernel_original': k, 'kernel_PID_role': 'saved_ready_worker_not_aggregate_worker', 'process_scan': processes, 'aggregate_launched': False, 'aggregate_exit_status': None, 'worker_initial_intent_cleanup': None, 'old_unit_queries': 0, 'old_finalize_calls': 0, 'GET': 0, 'models_started': 0, 'image_imported': False, 'started_at': start, 'finished_at': time.time(), 'monotonic_elapsed': time.monotonic() - mono}

def validate(v, history_raw, current):
    p = APPROVED_POLICY
    h = history(history_raw)
    checked_request(original(v['request_original']), current)
    need(set(v) == {'schema', 'state', 'operation', 'stage_operation', 'request_original', 'history_mirror', 'snapshot', 'data_absence', 'kernel_original', 'kernel_PID_role', 'process_scan', 'aggregate_launched', 'aggregate_exit_status', 'worker_initial_intent_cleanup', 'old_unit_queries', 'old_finalize_calls', 'GET', 'models_started', 'image_imported', 'started_at', 'finished_at', 'monotonic_elapsed'} and v['schema'] == 'stage-not-launched-quiescent/v1' and (v['state'] == 'NOT_LAUNCHED_QUIESCENT') and (v['operation'] == OPERATION) and (v['stage_operation'] == p['stage']), 'not_launched_exact_qualified_type')
    need(v['aggregate_launched'] is False and v['aggregate_exit_status'] is v['worker_initial_intent_cleanup'] is None and (v['image_imported'] is False) and all((type(v[k]) is int and v[k] == 0 for k in ('old_unit_queries', 'old_finalize_calls', 'GET', 'models_started'))), 'not_launched_no_fabricated_worker_or_success')
    need(all((type(v[k]) in (int, float) and math.isfinite(v[k]) for k in ('started_at', 'finished_at', 'monotonic_elapsed'))) and h['observed_at'] <= v['started_at'] <= v['finished_at'] and (0 <= v['monotonic_elapsed'] <= 30), 'not_launched_A_local_whole30')
    need(v['history_mirror']['path'] == str(ROOT / 'historical-MAC-original.json') and v['history_mirror']['sha256'] == v['history_mirror']['original_MAC_sha256'] == p['A_history_sha256'] and (v['history_mirror']['F9'][2] == len(history_raw)) and (v['history_mirror']['F9'][3:7] == [0, 0, 33152, 1]), 'not_launched_MAC_mirror_distinct_origin')
    s = v['snapshot']
    need(s['sources'] == p['sources'] and s['controls'] == {n: {'sha256': x['sha256'], 'F9': x['F9']} for n, x in h['control_originals'].items()}, 'not_launched_full_source_control_binding')
    control = p['source_root'] + '/stages/' + p['stage']
    need(len(s['directories']) == 1, 'not_launched_full_control_directories')
    for prefix, d in zip(('',), s['directories']):
        need(d['path'] == control + ('/readiness' if prefix else '') and d['F9'] == h['control_directories']['readiness' if prefix else '.'] and (d['entries'] == sorted(set(h['control_originals']) | {'readiness'})), 'not_launched_control_directory_originals')
    a = v['data_absence']
    need(a['path'] == p['data_root'] and a['errno'] == 2 and (a['parent']['path'] == str(Path(p['data_root']).parent)) and (Path(p['data_root']).name not in a['parent']['entries']), 'not_launched_positive_current_payload_absence')
    for d in s['directories'] + [a['parent']]:
        need(type(d['F9']) is list and len(d['F9']) == 9 and (d['F9'][3] == 0) and stat.S_ISDIR(d['F9'][5]) and (not d['F9'][5] & 18), 'not_launched_directory_F9')
        expected = ['/'] + ['/' + '/'.join(Path(d['path']).parts[1:i]) for i in range(2, len(Path(d['path']).parts) + 1)]
        need([x['path'] for x in d['anchors']] == expected, 'not_launched_full_root_ancestry')
        for anchor in d['anchors']:
            need(len(anchor['F9']) == 9 and anchor['F9'][3] == 0 and stat.S_ISDIR(anchor['F9'][5]) and (not anchor['F9'][5] & 18), 'not_launched_Root_anchor')
    need(v['kernel_PID_role'] == 'saved_ready_worker_not_aggregate_worker', 'not_launched_kernel_PID_role')
    kernel.validate_failed_kernel(v['kernel_original'], p['aggregate_unit'], p['ready_pid'], p['boot_id'], v['started_at'])
    no_target(v['process_scan'], p)
    need(v['kernel_original']['finished_at'] <= v['finished_at'], 'not_launched_kernel_before_finished')
    return {'state': 'NOT_LAUNCHED_QUIESCENT', 'stage_operation': p['stage'], 'work_may_resume': False, 'aggregate_exit_status': None, 'image_imported': False, 'models_started': 0}
