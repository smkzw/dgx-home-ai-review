# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual retained unit/raw/empty cgroup, bounded commands; never creates units."""
import os, time
from pathlib import Path
from contract import *
from bounded_process import capture
PROPS = 'Id,LoadState,ActiveState,SubState,MainPID,ExecMainPID,ExecStart,Type,User,Group,ExecMainCode,ExecMainStatus,Result,NRestarts,InvocationID,ControlGroup,RemainAfterExit,Restart,KillMode,SendSIGKILL,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,Nice,IOSchedulingClass,RuntimeMaxUSec,TimeoutStopUSec'

def observe(role):
    need(role in ('history', 'epoch') and os.getuid() == os.geteuid() == 0, 'fixed_Root_scope_observer')
    unit = HISTORY_UNIT if role == 'history' else SCOPE_UNIT
    r = capture(['/usr/bin/systemctl', 'show', unit, '--property=' + PROPS], env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, deadline=time.monotonic() + 10, cap=262144)
    need(r.returncode == 0 and (not r.stderr), 'actual_retained_observation_not_ssh_status')
    u = dict((x.split('=', 1) for x in r.stdout.decode().splitlines()))
    need(u['Id'] == unit, 'fixed_unit_identity')
    cg = u['ControlGroup']
    procs = []
    if cg:
        need(cg == '/system.slice/' + unit, 'owned_scope_cgroup_only')
        f = Path('/sys/fs/cgroup' + cg + '/cgroup.procs')
        if f.parent.exists():
            procs = f.read_text().splitlines()
        else:
            need(not f.parent.is_symlink(), 'no_cgroup_symlink')
    return {'unit': u, 'unit_raw_utf8': r.stdout.decode(), 'unit_sha256': sha(r.stdout), 'cgroup_procs': procs, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'observed_at': time.time()}
