# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite independent new-PID readonly qualification. No lifecycle installation."""
import os, re, sys, time, types
from pathlib import Path
ROOT = Path('/opt/dgx-v4/hx/mimo-registry-r16')
APPROVED_INDEX_SHA = '5edd00d1c71f46a2c1abf9fb97f08860a636bbe1436dcdb5f2ed68970a3c4ee3'
APPROVED_REVIEW = '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'
MODE = 'finalize-stop'
PROPS = 'Id,LoadState,ActiveState,SubState,MainPID,ExecMainPID,ExecStart,Type,User,Group,ExecMainCode,ExecMainStatus,Result,NRestarts,InvocationID,ControlGroup,RemainAfterExit,Restart,KillMode,SendSIGKILL,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,Nice,IOSchedulingClass,RuntimeMaxUSec,TimeoutStopUSec'

def main():
    if APPROVED_INDEX_SHA is None or APPROVED_REVIEW is None or MODE not in ('launch', 'finalize-stop'):
        raise RuntimeError('current_PID_renewal_default_None')
    if os.getuid() != os.geteuid() or os.geteuid() != 0 or sys.platform != 'linux':
        raise RuntimeError('Root_current_source_only')
    sys.path.insert(0, '/opt/dgx-v4/hx/runtime')
    from B_OWNER_RECOVERY_R25_WIRING.common import protected_read, need, sha, strict, encode
    raw, st = protected_read(ROOT / 'epoch-index.json')
    need(sha(raw) == APPROVED_INDEX_SHA, 'exact_source_index')
    index = strict(raw)
    need(index['review_sha256'] == APPROVED_REVIEW, 'same_finite_newcurrent_source')
    for n, pin in index['files'].items():
        need(sha(protected_read(ROOT / n, limit=2097152)[0]) == pin, 'complete_final_byte_DAG_before_renewal')

    def load(name):
        raw, st = protected_read(ROOT / name, limit=2097152)
        need(sha(raw) == index['files'][name], 'indexed_actual_entry_source')
        m = types.ModuleType('held_R6_' + name.replace('/', '_'))
        m.__file__ = str(ROOT / name)
        exec(compile(raw, m.__file__, 'exec'), m.__dict__)
        return m
    loader = load('renewal-loader.py')
    current = loader.main('inspect-current')
    identity = current['manager_identity']
    inv = identity['invocation_id']
    need(re.fullmatch('[0-9a-f]{32}', inv), 'current_real_manager_invocation')
    parent = ROOT / 'runtime-qualifications' / inv
    unit = 'dgx-v4-mimo-source-renewal-entryclock-r1-' + inv + '.service'
    worker = str(ROOT / 'renewal-worker.py')
    cp = load('pc/bounded_process.py')
    io = load('pc/inputs/io_utils.py')

    def capture(argv, seconds=10, cap=262144):
        return cp.capture(argv, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, deadline=time.monotonic() + seconds, cap=cap)

    def observe():
        r = capture(['/usr/bin/systemctl', 'show', unit, '--property=' + PROPS])
        need(r.returncode == 0 and (not r.stderr), 'current_renewal_actual_unit')
        u = dict((line.split('=', 1) for line in r.stdout.decode().splitlines()))
        cg = u['ControlGroup']
        need(cg in ('', '/system.slice/' + unit), 'owned_renewal_cgroup')
        procs = []
        if cg:
            p = Path('/sys/fs/cgroup' + cg + '/cgroup.procs')
            if p.parent.exists():
                procs = p.read_text().splitlines()
            else:
                need(not p.parent.is_symlink(), 'no_wrong_cgroup')
        return {'unit': u, 'unit_raw_utf8': r.stdout.decode(), 'unit_sha256': sha(r.stdout), 'cgroup_procs': procs, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'observed_at': time.time()}
    if MODE == 'launch':
        need(not parent.exists() and (not parent.is_symlink()), 'readonly_newPID_once_no_failed_retry')
        before = observe()['unit']
        need(before['LoadState'] == 'not-found' and before['MainPID'] == '0', 'renewal_unit_unused_not_false_EXIT0')
        io.fresh(ROOT / ('renewal-' + inv + '-launch-intent.json'), encode({'manager_identity': identity, 'unit': unit, 'index_sha256': APPROVED_INDEX_SHA, 'observed_at': time.time(), 'automatic_retry': False}), mode=288, gid=989)
        argv = ['/usr/bin/systemd-run', '--quiet', '--unit=' + unit, '--service-type=exec', '-p', 'User=root', '-p', 'Group=root', '-p', 'CPUQuota=100%', '-p', 'MemoryMax=192M', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=32', '-p', 'Nice=10', '-p', 'IOSchedulingClass=idle', '-p', 'UMask=0077', '-p', 'RuntimeMaxSec=120', '-p', 'RemainAfterExit=yes', '-p', 'Restart=no', '-p', 'KillMode=process', '-p', 'SendSIGKILL=no', '-p', 'TimeoutStopSec=30', '/usr/bin/python3', '-I', '-B', worker, '--worker']
        result = capture(argv, 30, 65536)
        io.fresh(ROOT / ('renewal-' + inv + '-launch-result.json'), encode({'argv': argv, 'returncode': result.returncode, 'stdout_raw_utf8': result.stdout.decode(), 'stderr_raw_utf8': result.stderr.decode(), 'observed_at': time.time()}), mode=288, gid=989)
        need(result.returncode == 0 and (not result.stderr), 'renewal_launch_once_refused')
        return {'unit': unit, 'manager_identity': identity, 'launch_calls': 1}
    proof = observe()
    returnedraw, rs = protected_read(parent / 'returned-zero.json')
    returned = strict(returnedraw)
    result = loader.main('finalize', scope=proof, returned=returned)
    io.fresh(parent / 'archived-qualified.json', encode({'scope': proof, 'returned_raw_utf8': returnedraw.decode(), 'returned_F9': rs, 'qualified_sha256': sha(encode(result)), 'observed_at': time.time()}), mode=288, gid=989)
    second = observe()
    need(second['unit'] == proof['unit'] and second['cgroup_procs'] == [], 'same_actual_retainedscope_before_owned_stop')
    io.fresh(parent / 'owned-stop-intent.json', encode({'unit': unit, 'invocation_id': proof['unit']['InvocationID'], 'calls': 1, 'observed_at': time.time()}), mode=288, gid=989)
    stop = capture(['/usr/bin/systemctl', 'stop', unit], 30, 65536)
    io.fresh(parent / 'owned-stop-result.json', encode({'rc': stop.returncode, 'stdout_raw_utf8': stop.stdout.decode(), 'stderr_raw_utf8': stop.stderr.decode(), 'observed_at': time.time()}), mode=288, gid=989)
    need(stop.returncode == 0 and (not stop.stderr), 'owned_stop_no_retry')
    return {'qualified_sha256': sha(encode(result)), 'actual_readonly_EXIT0': True, 'owned_stop_calls': 1, 'models_started': 0}
if __name__ == '__main__':
    raise SystemExit(main())
