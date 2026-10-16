# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Typed retained A no-engine originals; historical times never become freshness."""
from pathlib import Path
from proc_lifetime import validate as validate_proc_lifetime
import base64, math, stat
from contract import need, sha, strict, OPERATION
from managed_scope import positive
from prelaunch_history import original, partial, historical_entry, encode, failed_A, failed_A_originals, consume_failed_A_history
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
from prelaunch_stop import stopped
import prelaunch_legacy
APPROVED_A_WORKER_SHA = '93902c66a9607efc03b8abbc66321d942a8b5bcd0b54c1f3f03a46e0f1b21791'

def validate_owned_stop(proof, body, so):
    unit = proof['actual_scope']['unit']['Id']
    old = proof['actual_scope']['unit']
    u = so['unit']
    raw = so['unit_raw_utf8'].encode()
    lines = raw.decode().splitlines()
    need(len(lines) == len({x.split('=', 1)[0] for x in lines}) and sha(raw) == so['unit_sha256'] and (u == dict((x.split('=', 1) for x in lines))), 'poststop_original_unit_raw_keys')
    need(old['LoadState'] == 'loaded' and old['MainPID'] == '0' and (old['ExecMainCode'] == '1') and (old['ExecMainStatus'] == '0') and (old['Result'] == 'success') and (old['InvocationID'] == body['invocation_id']) and (old['ExecMainPID'] == str(body['pid'])) and (proof['actual_scope']['boot_id'] == so['boot_id'] == body['boot_id']), 'positive_retained_original_not_collected_guess')
    need(u['Id'] == unit and u['MainPID'] == '0' and (u['ActiveState'] == 'inactive') and (u['SubState'] == 'dead') and (u['NRestarts'] == '0') and (u['ControlGroup'] in ('', '/system.slice/' + unit)) and (so['cgroup_procs'] == []), 'poststop_not_active_or_unknown')
    if u['LoadState'] == 'loaded':
        need(u['InvocationID'] == old['InvocationID'] and u['ExecMainPID'] == old['ExecMainPID'] and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['Result'] == 'success') and (so['poststop_unit_branch'] == 'loaded-same-invocation'), 'poststop_loaded_same_original_invocation')
    else:
        need(u['LoadState'] == 'not-found' and u['InvocationID'] == u['ControlGroup'] == u['Type'] == u['User'] == u['Group'] == '' and (u['ExecMainPID'] == u['ExecMainCode'] == u['ExecMainStatus'] == '0') and (u['Result'] == 'success') and (so['poststop_unit_branch'] == 'collected-with-independent-kernel-proof'), 'poststop_collected_exact_missing_not_success_alone')
    k = so['poststop_kernel_original']
    need(type(k) is dict and set(k) == {'schema', 'unit', 'original_worker_pid', 'boot_before', 'boot_after', 'PID_absence', 'fixed_cgroup', 'cgroup_state', 'cgroup_nodes', 'directory_anchors', 'started_at', 'finished_at'} and (k['schema'] == 'owned-readonly-poststop-kernel/v1') and (k['unit'] == unit) and (type(k['original_worker_pid']) is int) and (k['original_worker_pid'] == body['pid']), 'poststop_exact_kernel_identity')
    need(all((type(x) in (int, float) and math.isfinite(x) for x in (k['started_at'], k['finished_at'], so['observed_at']))) and so['observed_at'] <= k['started_at'] <= k['finished_at'], 'poststop_actual_kernel_time_order')

    def metadata(s, directory=False):
        need(type(s) is list and len(s) == 9 and all((type(x) is int and x >= 0 for x in s)) and (s[0] > 0) and (s[1] > 0) and (s[3] == 0) and (s[6] >= 1) and (not s[5] & 18) and (stat.S_ISDIR(s[5]) if directory else stat.S_ISREG(s[5])), 'poststop_kernel_full_F9_type')

    def original(row, path):
        need(type(row) is dict and set(row) == {'path', 'raw_utf8', 'sha256', 'stat'} and (row['path'] == path) and (type(row['raw_utf8']) is str) and (len(row['raw_utf8'].encode()) <= 65536) and (sha(row['raw_utf8'].encode()) == row['sha256']), 'poststop_kernel_fullraw_SHA')
        metadata(row['stat'])
        return row['raw_utf8']
    bootpath = '/proc/sys/kernel/random/boot_id'
    b = original(k['boot_before'], bootpath)
    need(b == original(k['boot_after'], bootpath) and b.strip() == body['boot_id'], 'poststop_same_boot_originals')
    need(k['PID_absence'] == {'path': '/proc/' + str(body['pid']), 'errno': 2}, 'poststop_original_PID_positive_ENOENT')
    fixed = '/sys/fs/cgroup/system.slice/' + unit
    need(k['fixed_cgroup'] == fixed and type(k['cgroup_nodes']) is list and (len(k['cgroup_nodes']) <= 128), 'poststop_fixed_CG_bounded')
    nodes = k['cgroup_nodes']
    paths = []
    edges = []
    if k['cgroup_state'] == 'absent':
        need(nodes == [], 'poststop_absent_CG_no_fabricated_tree')
    else:
        need(k['cgroup_state'] == 'present-empty' and nodes, 'poststop_unknown_CG_state')
        for node in nodes:
            need(type(node) is dict and set(node) == {'path', 'before_stat', 'after_stat', 'entries_before', 'entries_after', 'children', 'procs_original'}, 'poststop_complete_CG_node')
            path = node['path']
            need(type(path) is str and (path == fixed or path.startswith(fixed + '/')) and all((x not in ('', '.', '..') for x in path[len(fixed):].split('/')[1:])), 'poststop_only_fixed_CG_tree')
            paths.append(path)
            for key in ('entries_before', 'entries_after', 'children'):
                a = node[key]
                need(type(a) is list and all((type(x) is str and x not in ('', '.', '..') and ('/' not in x) for x in a)) and (a == sorted(set(a))), 'poststop_CG_complete_listing')
            need(node['entries_before'] == node['entries_after'] and set(node['children']) <= set(node['entries_before']) and ('cgroup.procs' in node['entries_before']), 'poststop_CG_no_listing_drift')
            metadata(node['before_stat'], True)
            metadata(node['after_stat'], True)
            need(all((node['before_stat'][i] == node['after_stat'][i] for i in (0, 1, 3, 4, 5))), 'poststop_CG_directory_identity')
            need(not original(node['procs_original'], path + '/cgroup.procs').strip(), 'poststop_CG_full_original_nonempty')
            edges.extend((path + '/' + name for name in node['children']))
        need(paths[0] == fixed and len(paths) == len(set(paths)) and (set(paths) == {fixed} | set(edges)), 'poststop_CG_no_missing_child')
    anchors = k['directory_anchors']
    expected = ['/proc/sys/kernel/random', '/proc', '/sys/fs/cgroup/system.slice'] + paths + ['/proc/sys/kernel/random']
    need(type(anchors) is list and len(anchors) == len(expected) and ([x['path'] for x in anchors] == expected), 'poststop_positive_kernel_anchors')
    for a in anchors:
        need(type(a) is dict and set(a) == {'path', 'before_stat', 'after_stat', 'named_stat'}, 'poststop_kernel_anchor_schema')
        for key in ('before_stat', 'after_stat', 'named_stat'):
            metadata(a[key], True)
        need(all((a['before_stat'][i] == a['after_stat'][i] == a['named_stat'][i] for i in (0, 1, 3, 4, 5))), 'poststop_kernel_anchor_stable_identity')
    return k

def A_original(proof, p):
    need(APPROVED_A_WORKER_SHA is not None and proof['phase'] in ('before-stop', 'after-stop'), 'source_bound_readonly_A_worker_pending')
    request = proof['request']
    nonce = request['request_nonce']
    unit = 'dgx-v4-prelaunch-' + proof['phase'] + '-' + nonce + '.service'
    need(request['operation'] == OPERATION and request['policy_sha256'] == p['_policy_sha256'] and (request['A_worker_sha256'] == APPROVED_A_WORKER_SHA) and (proof['request_sha256'] == sha(encode(request))), 'full_original_readonly_request')
    positive(proof['actual_scope'], proof['returned_original'], APPROVED_A_WORKER_SHA, unit=unit, operation=OPERATION, runtime_seconds=120)
    body = original(proof['body_original'], uid=0, gid=0, mode=384)
    need(body['schema'] == 'registry-prelaunch-readonly-A-body/v1' and body['request'] == request and (body['policy_sha256'] == p['_policy_sha256']) and (body['worker_sha256'] == APPROVED_A_WORKER_SHA) and (proof['returned_original']['result']['body_sha256'] == proof['body_original']['sha256']), 'body_fullraw_F9_scope_return_binding')
    need(body['kernel'] == {'cpu.max': '100000 100000', 'memory.max': '201326592', 'memory.swap.max': '0', 'pids.max': '32', 'cgroup.procs': str(body['pid'])} and body['pid'] == proof['returned_original']['worker_pid'] and (body['boot_id'] == proof['actual_scope']['boot_id']) and (body['invocation_id'] == proof['actual_scope']['unit']['InvocationID']), 'readonly_own_true_kernel_scope_identity')
    stops = proof['owned_stop_originals']
    need(set(stops) == {'owned-stop-intent.json', 'owned-stop-result.json', 'owned-stop-observed.json'}, 'complete_actual_new_scope_owned_stop_originals')
    si = original(stops['owned-stop-intent.json'], uid=0, gid=0, mode=384)
    sr = original(stops['owned-stop-result.json'], uid=0, gid=0, mode=384)
    so = original(stops['owned-stop-observed.json'], uid=0, gid=0, mode=384)
    need(si['unit'] == unit and si['invocation_id'] == proof['returned_original']['invocation_id'] and (type(si['owned_scope_stop_calls']) is int) and (si['owned_scope_stop_calls'] == 1) and (type(sr['rc']) is int) and (sr['rc'] == 0) and (base64.b64decode(sr['stderr_b64'], validate=True) == b''), 'exact_owned_scope_normal_stop_original')
    validate_owned_stop(proof, body, so)
    need(body['observed_at'] <= si['issued_at'] <= sr['observed_at'] <= so['observed_at'], 'retained_success_archive_then_actual_owned_stop')
    a = body['A']
    historical_entry(a['records'], p, prelaunch_legacy.load(p))
    validate_proc_lifetime(a['process_scan'], Path(p['A_root']))
    need(a['A34'] == p['A34'], 'complete_current_A34_no_owned_engine')
    consume_failed_A_history(protected_read, p)
    failed_A(a, p)
    start, end, elapsed = (proof[k] for k in ('PC_started_at', 'PC_finished_at', 'PC_monotonic_elapsed'))
    need(all((type(x) in (int, float) and math.isfinite(x) for x in (start, end, elapsed))) and 0 <= end - start <= 30 and (0 <= elapsed <= 30) and (abs(end - start - elapsed) <= 30), 'same_PC_whole30_historical_interval')
    need(start - 30 <= a['started_at'] <= a['observed_at'] <= body['observed_at'] <= end + 30, 'A_remote_clock_audit_not_future_freshness')
    return a

def stopped_original(after, p, actual_records=None):
    need(after['phase'] == 'after-stop', 'distinct_after_stop_scope_original')
    a = A_original(after, p)
    checked = partial(actual_records, p)
    need(after['PC_records'] == checked, 'after_stop_actual_registry_fullread')
    proof = strict(after['PC_idle_original']['raw_utf8'].encode())
    need(sha(after['PC_idle_original']['raw_utf8'].encode()) == after['PC_idle_original']['sha256'], 'complete_PC_stopped_idle_raw')
    stopped(proof)
    need(proof['old_identity'] == p.get('live_current', p)['manager_identity'] and proof['PC_source_files'] == after['PC_snapshot']['source_files'], 'stopped_actual_old_source_and_identity')
    need({k: v['sha256'] for k, v in proof['PC_source_files'].items()} == p.get('live_current', p)['current_source118'] and after['PC_snapshot']['lease_full_F9'] == p.get('live_current', p)['lease_full_F9'] and (after['PC_snapshot']['Cleaf'] == p.get('live_current', p)['Cleaf']), 'all118_Cleaf_original_physicallease_after_stop')
    return proof
