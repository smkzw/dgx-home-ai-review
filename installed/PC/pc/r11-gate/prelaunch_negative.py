# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Typed failed-owner normal update. All retained bytes stay historical."""
import base64, math, os, re, stat, time
from pathlib import Path
from plan import need, strict, encode
from root_io import held, f9, sha
import old_failed_kernel as kernel
from proc_lifetime import scan, validate as validate_processes
APPROVED_POLICY = None
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
OPERATION = '2b9e9b631cebc13ae6b1550ee59c13ed'
ROOT = None

def original(row, owner=(0, 0, 33152, 1)):
    need(type(row) is dict and set(row) == {'raw_b64', 'sha256', 'F9'}, 'R15_normal_exact_original')
    b = base64.b64decode(row['raw_b64'], validate=True)
    s = row['F9']
    need(type(s) is list and len(s) == 9 and all((type(x) is int and x >= 0 for x in s)) and (s[2] == len(b) <= 2097152) and (s[3:7] == list(owner)) and (sha(b) == row['sha256']), 'R15_normal_original_SHA_fullF9')
    return b

def directory_tree(roots):
    """Root metadata only; bounded held directory set, no leaf body/hash reads."""
    need(type(roots) is list and len(roots) == 2 and (len(set(roots)) == 2), 'R15_normal_two_fixed_Root_trees')
    fds = []
    out = {}
    count = 0

    def walk(fd, path):
        nonlocal count
        before = f9(os.fstat(fd))
        need(stat.S_ISDIR(before[5]) and before[3:5] == [0, 0] and (not before[5] & 18), 'R15_normal_Root_directory')
        names = sorted(os.listdir(fd))
        need(len(names) == len(set(names)) and all((type(n) is str and n not in ('', '.', '..') and ('/' not in n) for n in names)), 'R15_normal_closed_names')
        children = {}
        for n in names:
            count += 1
            need(count <= 256, 'R15_normal_all_metadata_256_cap')
            s = f9(os.stat(n, dir_fd=fd, follow_symlinks=False))
            need(s[3:5] == [0, 0] and (not s[5] & 18) and (stat.S_ISDIR(s[5]) or stat.S_ISREG(s[5]) or stat.S_ISSOCK(s[5])), 'R15_normal_no_foreign_symlink_or_device')
            children[n] = s
        out[path] = {'path': path, 'F9': before, 'entries': names, 'children': children}
        for n, s in children.items():
            if stat.S_ISDIR(s[5]):
                child = os.open(n, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                fds.append(child)
                need(f9(os.fstat(child)) == s, 'R15_normal_child_FD_named')
                walk(child, path + '/' + n)
        need(f9(os.fstat(fd)) == before and sorted(os.listdir(fd)) == names and all((f9(os.stat(n, dir_fd=fd, follow_symlinks=False)) == s for n, s in children.items())), 'R15_normal_full_metadata_after_stable')
    try:
        for path in roots:
            p = Path(path)
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            fds.append(fd)
            anchors = []
            for part in p.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                fds.append(child)
                z = f9(os.fstat(child))
                need(z[3:5] == [0, 0] and stat.S_ISDIR(z[5]) and (not z[5] & 18) and (z == f9(os.stat(part, dir_fd=fd, follow_symlinks=False))), 'R15_normal_complete_Root_ancestry')
                anchors.append((fd, part, z))
                fd = child
            walk(fd, path)
            for parent, name, z in anchors:
                need(f9(os.stat(name, dir_fd=parent, follow_symlinks=False)) == z, 'R15_normal_ancestor_after')
        return out
    finally:
        for fd in reversed(fds):
            os.close(fd)

def settings():
    p = APPROVED_POLICY
    need(type(p) is dict and set(p) == {'schema', 'history_sha256', 'new_source_root'} and (p['schema'] == 'R16-held-failed-owner-normal-policy/v1') and re.fullmatch('[0-9a-f]{64}', p['history_sha256']) and (p['new_source_root'] == '/opt/dgx-v4/mimo-registry-r16'), 'R16_normal_complete_source_pending')
    return p

def policy(raw):
    p = settings()
    need(sha(raw) == p['history_sha256'], 'R16_normal_exact_Root_history_SHA')
    v = strict(raw)
    keys = {'schema', 'old_domain', 'metadata', 'current_A_source', 'current_A_root', 'shared_BASE', 'owner_workers', 'pending_stage', 'old_terminal', 'old_plan', 'old_records', 'old_completed', 'source_metadata_capture_sha256'}
    need(type(v) is dict and set(v) == keys and (v['schema'] == 'R16-failed-owner-normal-history/v1'), 'R16_normal_closed_data_shape')
    h = v['old_domain']
    need(h['schema'] == 'R14B-sealed-old-domain/v1' and h['operation'] == 'ed7021db9df4c839d02f3271361924de' and (set(h['actors']) == {'b7a518bbefa903b6c43c44b9a2f6f6cf', '69b0a7b8356ae276839c3cc43044096c'}) and all((x['state'] == 'FAILED_REGISTRY_QUIESCENT' for x in h['actors'].values())), 'R16_normal_exact_original_bridge_domain')
    need(v['current_A_root'] == '/opt/dgx-v4/mimo-registry-r15' and v['shared_BASE'] == h['A_source']['data_root'] == '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14' and (len(v['current_A_source']) == 55) and (set(v['owner_workers']) == {'c64efe9f2fb5ca21eeb0ee5a107e4e9f', '6867e0e5c18d53bc88b7d742da7b86a8'}) and (v['pending_stage'] == 'c64efe9f2fb5ca21eeb0ee5a107e4e9f'), 'R16_exact_pending_and_completed_old_workers')
    return dict(p, **v)

def checked_request(raw, current):
    p = settings()
    r = strict(raw)
    need(APPROVED_REVIEW is not None and type(current) is dict and (set(current) == {'review_sha256', 'config_sha256', 'manager_identity', 'source118'}) and (current['review_sha256'] == APPROVED_REVIEW) and (len(current['source118']) == 118), 'R15_normal_independent_current_source')
    need(type(r) is dict and set(r) == {'schema', 'operation', 'nonce', 'current', 'history_sha256'} and (r['schema'] == 'stage-not-launched-request/v1') and (r['operation'] == OPERATION) and re.fullmatch('[0-9a-f]{32}', r['nonce']) and (r['current'] == current) and (r['history_sha256'] == p['history_sha256']), 'R15_normal_phase_actual_request')
    return r

def history(raw):
    return policy(raw)['old_domain']

def source_and_metadata(p):
    files = {}
    for path, row in expected_sources(p).items():
        b, f = held(Path(path), row['sha256'], cap=2097152, mode=384)
        need(f == row['F9'], 'R16_normal_both_old_A_source_sets_fullF9')
        files[path] = {'sha256': sha(b), 'F9': f}
    for root in (p['old_domain']['A_source']['source_root'], p['current_A_root']):
        index = strict(held(Path(root) / 'source-index.json', files[root + '/source-index.json']['sha256'], mode=384)[0])
        need(index['operation'] == p['old_domain']['operation'] and all((files[root + '/' + n]['sha256'] == pin for n, pin in index['files'].items())), 'R16_normal_two_exact_original_A_indexes')
    tree = directory_tree([p['current_A_root'], p['shared_BASE']])
    need(tree == p['metadata'], 'R16_normal_complete_201_metadata_no_unknown_entry')
    return {'source_files': files, 'metadata': tree}

def no_target(events, p):
    h = p['old_domain']
    validate_processes(events, Path(h['A_source']['source_root']))
    markers = [h['A_source']['source_root'], p['current_A_root'], h['A_source']['data_root'], p['new_source_root']] + [v['unit'] for v in workers(p).values()]
    for event in events['events']:
        for rows in [event['partial']] + ([event['row']['originals']] if event['complete_identity'] else []):
            for name, row in rows.items():
                if name.startswith(('cmdline_', 'cgroup_')):
                    need(not any((m.encode() in base64.b64decode(row['raw_b64'], validate=True) for m in markers)), 'R15_normal_no_old_or_new_target_process')
        for exe in event['partial_executable'] + ([event['row']['exe']] if event['complete_identity'] else []):
            need(exe is None or not any((m in exe for m in markers)), 'R15_normal_no_target_executable')
    return events

def collect():
    configured = settings()
    need(ROOT is not None and OPERATION is not None and (os.getuid() == os.geteuid() == 0), 'R15_normal_Root_scope_only')
    start = time.time()
    mono = time.monotonic()
    end = mono + 30
    raw, rf = held(ROOT / 'request.json', mode=384)
    current = strict(held(ROOT / 'current-context.json', mode=384)[0])
    checked_request(raw, current)
    hist, hf = held(ROOT / 'historical-MAC-original.json', configured['history_sha256'], cap=2097152, mode=384)
    p = policy(hist)
    h = p['old_domain']
    first = source_and_metadata(p)
    kernels = {}
    saved = kernel.ALLOWED_UNIT
    try:
        for stage, a in sorted(workers(p).items()):
            kernel.ALLOWED_UNIT = a['unit']
            kernels[stage] = kernel.kernel_after_stop(a['unit'], a['failed_pid'], a['A_boot_id'], end)
    finally:
        kernel.ALLOWED_UNIT = saved
    events = no_target(scan(Path(h['A_source']['source_root'])), p)
    need(source_and_metadata(p) == first and time.monotonic() < end, 'R15_normal_complete_second_source_metadata_scan30')
    return {'schema': 'R15-complete-old-family-quiescent-normal/v1', 'state': 'COMPLETE_FAILED_EPOCH_PRESERVED_NO_WORK', 'operation': OPERATION, 'request_original': {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': rf}, 'history_mirror': {'path': str(ROOT / 'historical-MAC-original.json'), 'sha256': sha(hist), 'F9': hf}, 'snapshot': first, 'kernels': kernels, 'process_scan': events, 'old_unit_queries': 0, 'old_finalize_calls': 0, 'GET': 0, 'models_started': 0, 'image_imported': False, 'started_at': start, 'finished_at': time.time(), 'monotonic_elapsed': time.monotonic() - mono}

def validate(v, history_raw, current):
    p = policy(history_raw)
    h = p['old_domain']
    checked_request(original(v['request_original']), current)
    need(set(v) == {'schema', 'state', 'operation', 'request_original', 'history_mirror', 'snapshot', 'kernels', 'process_scan', 'old_unit_queries', 'old_finalize_calls', 'GET', 'models_started', 'image_imported', 'started_at', 'finished_at', 'monotonic_elapsed'} and v['schema'] == 'R15-complete-old-family-quiescent-normal/v1' and (v['state'] == 'COMPLETE_FAILED_EPOCH_PRESERVED_NO_WORK') and (v['operation'] == OPERATION), 'R15_normal_full_typed_no_asset_permission')
    need(all((type(v[k]) is int and v[k] == 0 for k in ('old_unit_queries', 'old_finalize_calls', 'GET', 'models_started'))) and v['image_imported'] is False, 'R15_normal_no_old_phase_or_asset_replay')
    need(all((type(v[k]) in (int, float) and math.isfinite(v[k]) for k in ('started_at', 'finished_at', 'monotonic_elapsed'))) and v['started_at'] <= v['finished_at'] and (0 <= v['monotonic_elapsed'] <= 30), 'R15_normal_A_local_full30')
    need(v['snapshot'] == {'source_files': expected_sources(p), 'metadata': p['metadata']}, 'R15_normal_all_preserved_metadata_sources')
    m = v['history_mirror']
    need(m['path'] == str(ROOT / 'historical-MAC-original.json') and m['sha256'] == p['history_sha256'] and (m['F9'][2] == len(history_raw)) and (m['F9'][3:7] == [0, 0, 33152, 1]), 'R15_normal_history_original_mirror_domains')
    need(set(v['kernels']) == set(workers(p)), 'R15_normal_all_old_PID_kernel_originals')
    for stage, a in workers(p).items():
        k = v['kernels'][stage]
        kernel.validate_failed_kernel(k, a['unit'], a['failed_pid'], a['A_boot_id'], v['started_at'])
        need(k['finished_at'] <= v['finished_at'], 'R15_normal_kernel_within_outer_observation')
    no_target(v['process_scan'], p)
    return {'state': 'NOT_LAUNCHED_QUIESCENT', 'stage_operation': None, 'aggregate_exit_status': None, 'old_failures_preserved': True, 'old_stages': sorted(workers(p)), 'work_may_resume': False, 'image_imported': False, 'models_started': 0}

def workers(p):
    out = {n: {'unit': a['unit'], 'failed_pid': a['failed_pid'], 'A_boot_id': a['A_boot_id']} for n, a in p['old_domain']['actors'].items()}
    for n, a in p['owner_workers'].items():
        out[n] = {'unit': a['unit'], 'failed_pid': a['pid'], 'A_boot_id': a['boot_id']}
    need(len({a['A_boot_id'] for a in out.values()}) == 1, 'R16_all_retained_workers_same_A_boot')
    return out

def expected_sources(p):
    a = p['old_domain']['A_source']
    out = {a['source_root'] + '/' + n: dict(ref) for n, ref in a['sources'].items()}
    for n, ref in p['current_A_source'].items():
        need(ref['path'] == p['current_A_root'] + '/' + n, 'R16_current_A55_fixed_source_path')
        out[ref['path']] = {k: ref[k] for k in ('sha256', 'F9')}
    return out
