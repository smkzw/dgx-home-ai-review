# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Exact saved EXIT0 predicate with explicit immutable old operation domain.
Never mutates the live plan.OPERATION shared by the new Runtime.
"""
import re, plan
from root_io import sha
from observer import duration

def positive(v, unit, worker_sha, readonly=False, *, operation):
    u = v['unit']
    raw = v['unit_raw_utf8'].encode()
    r = v['returned_original']
    b = plan.strict(r['raw_utf8'])
    plan.need(sha(raw) == v['unit_raw_sha256'] and dict((s.split('=', 1) for s in raw.decode().splitlines())) == u, 'unit_raw_dictionary_binding')
    plan.need(u['Id'] == unit and u['Type'] == 'exec' and (u['User'] == u['Group'] == 'root') and (u['LoadState'] == 'loaded') and (u['ActiveState'] == 'active') and (u['SubState'] == 'exited') and (u['MainPID'] == '0') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['Result'] == 'success') and (u['NRestarts'] == '0') and (u['Restart'] == 'no') and (u['RemainAfterExit'] == 'yes') and (u['SendSIGKILL'] == 'no') and (v['cgroup_procs'] == []), 'actual_retained_owned_EXIT0_emptyCG_not_transport')
    plan.need(r['sha256'] == sha(r['raw_utf8'].encode()) and r['stat'][2] == len(r['raw_utf8'].encode()) and (r['stat'][3:7] == [0, 0, 33152, 1]) and (v['worker_source']['sha256'] == worker_sha), 'actual_returned_and_worker_Root_source_F9')
    plan.need(b['operation'] == operation and b['worker_sha256'] == worker_sha and (b['boot_id'] == v['boot_id']) and (b['invocation_id'] == u['InvocationID']) and re.fullmatch('[0-9a-f]{32}', u['InvocationID']) and (u['ExecMainPID'] == str(b['worker_pid'])) and (b['child_rc'] == b['stderr_bytes'] == 0), 'actual_same_boot_inv_PID_original_return')
    plan.need('path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B ' + v['worker_source']['path'] + ' ;' in u['ExecStart'], 'exact_actual_source_exec')
    plan.need(duration(u['CPUQuotaPerSecUSec']) == 1 and u['MemorySwapMax'] == '0' and (u['Nice'] == '10') and (u['IOSchedulingClass'] == '3') and (u['MemoryMax'] == str(192 * 1024 ** 2 if readonly else plan.MEMORY)) and (u['TasksMax'] == ('32' if readonly else '256')) and (duration(u['RuntimeMaxUSec']) == (90 if readonly else b['runtime_max_seconds'])) and (readonly or (type(b['runtime_max_seconds']) is int and 30 < b['runtime_max_seconds'] <= 1800)), 'actual_unit_kernel_policy')
    plan.need(b['observed_at'] <= v['observed_at'], 'keep_return_before_actual_collect')
    return b
