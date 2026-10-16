# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual already-stopped Root frame producer using the original lease + UID999 SSH."""
import os, time, types
from pathlib import Path
from contract import *
import prelaunch_stop
from B_OWNER_RECOVERY_R25_WIRING.common import protected_read
APPROVED_LIVE_IDLE_SHA = '0e9b31ca5cc387bfb60200d8a676b720d16b052645945c75892661838388d19f'

def failed_child_original(native, name, stdout, stderr, returncode):
    need(name in ('pc-nodes-readonly.py', 'pc-nodes-readonly-new.py') and type(stdout) is bytes and (type(stderr) is bytes) and (len(stdout) + len(stderr) <= 2097152), 'bounded_readonly_failure_original')
    prefix = 'node-readonly-' + ('new' if name.endswith('-new.py') else 'old') + '-failed'
    for suffix, raw in (('stdout.raw', stdout), ('stderr.raw', stderr)):
        native.current.io.fresh(PC_ROOT / (prefix + '-' + suffix), raw)
    value = {'schema': 'PC-current-idle-child-failed-original/v1', 'producer': name, 'producer_sha256': native.packet['input_pins'][name], 'returncode': returncode, 'stdout_path': str(PC_ROOT / (prefix + '-stdout.raw')), 'stderr_path': str(PC_ROOT / (prefix + '-stderr.raw')), 'stdout_bytes': len(stdout), 'stderr_bytes': len(stderr), 'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr), 'observed_at': native.wall()}
    native.current.io.fresh(PC_ROOT / (prefix + '.json'), encode(value))

def module():
    need(APPROVED_LIVE_IDLE_SHA is not None, 'stopped_current_idle_source_pending')
    raw, st = protected_read(PC_ROOT / 'service/live_idle.py', limit=2097152)
    need(sha(raw) == APPROVED_LIVE_IDLE_SHA and st[3:7] == [0, 989, 33056, 1], 'Root_live_idle_source')
    m = types.ModuleType('Root_fixed_stopped_live_idle')
    m.__file__ = str(PC_ROOT / 'service/live_idle.py')
    exec(compile(raw, m.__file__, 'exec'), m.__dict__)
    return m

def collect(native, p, before, end):
    need(native.holders() == [native.pid()] and time.monotonic() < end, 'actual_installer_original_lease')
    kernel = native.kernel_dead(before, end)
    current = native.capture_stopped(end)
    rows = current['rows_original']['rows']
    m = module()
    name = 'pc-nodes-readonly-new.py' if native.after_cas else 'pc-nodes-readonly.py'
    raw, st = protected_read(PC_ROOT / name, limit=2097152)
    need(sha(raw) == p['input_pins'][name], 'new_stopped_exact_producer')
    try:
        r = native.command(['/usr/bin/setpriv', '--reuid=999', '--regid=989', '--groups=989,1000', '/usr/bin/python3', '-I', '-B', str(PC_ROOT / name), '--generation', str(rows['profiles']['glm-ab']['generation'])], min(50, end - time.monotonic()))
    except BaseException as error:
        failed_child_original(native, name, getattr(error, 'partial_stdout', b''), getattr(error, 'partial_stderr', b''), None)
        raise
    if r.returncode != 0 or r.stderr:
        failed_child_original(native, name, r.stdout, r.stderr, r.returncode)
    need(r.returncode == 0 and (not r.stderr), 'actual_current_idle_no_retry')
    nodes = strict(r.stdout)
    need(protected_read(PC_ROOT / name, limit=2097152) == (raw, st), 'actual_stopped_producer_stable')
    proof = {**kernel, 'schema': 'PC-stopped-current-idle-R26-R6/v1', 'root_uid': os.geteuid(), 'Core_profiles': {k: rows['profiles'][k] for k in m.PROFILES}, 'nodes': nodes, 'core_nodes': [{**x, 'node': x['name'], 'quarantined': bool(x['quarantine'])} for x in rows['nodes']], 'rows': rows, 'PC_source_files': current['source_files'], 'lease_dev_inode': current['lease_dev_inode'], 'observed_at': current['observed_at'], 'finished_at': native.wall(), 'stopped_unit_original': native.normal_stopped_original, 'old_identity': before.get('prior_normal_identity', before['manager_identity']), 'owned_installer_pid': native.pid(), 'lease_holders': native.holders(), 'kernel_original': kernel, 'prior_kernel_original': dict(native.stop_kernel), 'old_PID_absent': not Path('/proc/' + str(before.get('prior_normal_identity', before['manager_identity'])['pid'])).exists(), 'other_Manager_PIDs': []}
    native.no_other_manager()
    cfg = dict(native.current.config, node_source_pins=strict(p['new_config_raw_utf8'])['node_source_pins'])
    m.validate_stopped_idle(proof, cfg, native.wall(), fenced=True)
    return {'raw_utf8': encode(proof).decode(), 'sha256': sha(encode(proof)), 'observed_at': native.wall()}
