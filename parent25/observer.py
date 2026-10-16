# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual owned retained unit/raw/F9/kernel consumer. Never starts/stops itself."""
import os, re, time
from pathlib import Path
import plan
from root_io import held, sha, fresh
from bounded_process import capture
FIELDS = ('Id', 'Type', 'User', 'Group', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'ExecMainPID', 'ExecMainCode', 'ExecMainStatus', 'Result', 'NRestarts', 'Restart', 'RemainAfterExit', 'SendSIGKILL', 'KillMode', 'InvocationID', 'ExecStart', 'ControlGroup', 'CPUQuotaPerSecUSec', 'MemoryMax', 'MemorySwapMax', 'TasksMax', 'Nice', 'IOSchedulingClass', 'RuntimeMaxUSec', 'TimeoutStopUSec', 'Delegate', 'DelegateControllers')

def collect(unit, returned, worker, worker_sha, deadline):
    plan.need(unit in (plan.UNIT, plan.ENTRY_UNIT), 'only_two_owned_source_units')
    r = capture(['/usr/bin/systemctl', 'show', unit, *['--property=' + n for n in FIELDS]], env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=min(deadline, time.monotonic() + 5), cap=262144)
    plan.need(r.returncode == 0 and (not r.stderr), 'actual_unit_collect_nonzero_or_stderr')
    u = dict((s.split('=', 1) for s in r.stdout.decode().splitlines()))
    raw, st = held(returned, mode=384)
    v = plan.strict(raw)
    source, ss = held(worker, worker_sha, mode=384)
    cg = u['ControlGroup']
    plan.need(cg in ('', '/system.slice/' + unit), 'actual_scope_owned_CG')
    procs = []
    if cg:
        top = Path('/sys/fs/cgroup' + cg)
        if top.exists():
            todo = [top]
            while todo:
                p = todo.pop()
                procs.extend((int(x) for x in (p / 'cgroup.procs').read_text().split()))
                todo.extend((x for x in p.iterdir() if x.is_dir()))
    return {'unit': u, 'unit_raw_utf8': r.stdout.decode(), 'unit_raw_sha256': sha(r.stdout), 'returned_original': {'raw_utf8': raw.decode(), 'sha256': sha(raw), 'stat': st}, 'worker_source': {'path': str(worker), 'sha256': sha(source), 'stat': ss}, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'cgroup_procs': sorted(set(procs)), 'observed_at': time.time()}

def duration(raw):
    parts = re.findall('([0-9.]+)(us|ms|min|s)', raw)
    factor = {'us': 1e-06, 'ms': 0.001, 's': 1, 'min': 60}
    plan.need(parts and ''.join((x + y for x, y in parts)) == raw.replace(' ', ''), 'strict_actual_duration')
    return sum((float(x) * factor[y] for x, y in parts))

def positive(v, unit, worker_sha, readonly=False):
    u = v['unit']
    raw = v['unit_raw_utf8'].encode()
    r = v['returned_original']
    b = plan.strict(r['raw_utf8'])
    plan.need(sha(raw) == v['unit_raw_sha256'] and dict((s.split('=', 1) for s in raw.decode().splitlines())) == u, 'unit_raw_dictionary_binding')
    plan.need(u['Id'] == unit and u['Type'] == 'exec' and (u['User'] == u['Group'] == 'root') and (u['LoadState'] == 'loaded') and (u['ActiveState'] == 'active') and (u['SubState'] == 'exited') and (u['MainPID'] == '0') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['Result'] == 'success') and (u['NRestarts'] == '0') and (u['Restart'] == 'no') and (u['RemainAfterExit'] == 'yes') and (u['SendSIGKILL'] == 'no') and (v['cgroup_procs'] == []), 'actual_retained_owned_EXIT0_emptyCG_not_transport')
    plan.need(r['sha256'] == sha(r['raw_utf8'].encode()) and r['stat'][2] == len(r['raw_utf8'].encode()) and (r['stat'][3:7] == [0, 0, 33152, 1]) and (v['worker_source']['sha256'] == worker_sha), 'actual_returned_and_worker_Root_source_F9')
    plan.need(b['operation'] == plan.OPERATION and b['worker_sha256'] == worker_sha and (b['boot_id'] == v['boot_id']) and (b['invocation_id'] == u['InvocationID']) and re.fullmatch('[0-9a-f]{32}', u['InvocationID']) and (u['ExecMainPID'] == str(b['worker_pid'])) and (b['child_rc'] == b['stderr_bytes'] == 0), 'actual_same_boot_inv_PID_original_return')
    plan.need('path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B ' + v['worker_source']['path'] + ' ;' in u['ExecStart'], 'exact_actual_source_exec')
    plan.need(duration(u['CPUQuotaPerSecUSec']) == 1 and u['MemorySwapMax'] == '0' and (u['Nice'] == '10') and (u['IOSchedulingClass'] == '3') and (u['MemoryMax'] == str(192 * 1024 ** 2 if readonly else plan.MEMORY)) and (u['TasksMax'] == ('32' if readonly else '256')) and (duration(u['RuntimeMaxUSec']) == (90 if readonly else b['runtime_max_seconds'])) and (readonly or (type(b['runtime_max_seconds']) is int and 30 < b['runtime_max_seconds'] <= 1800)), 'actual_unit_kernel_policy')
    plan.need(b['observed_at'] <= v['observed_at'], 'keep_return_before_actual_collect')
    return b
