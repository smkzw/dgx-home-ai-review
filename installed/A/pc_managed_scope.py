# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed finite Root worker/source identity and retained terminal validator."""
import math, re
from pc_contract import need, sha, strict, SCOPE_UNIT, PC_ROOT, EPOCH_OPERATION, HISTORY_ROOT
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
MEMORY = 192 * 1024 ** 2
RUNTIME = 900
WORKER_SECONDS = 840

def seconds(raw):
    if re.fullmatch('[0-9]+', raw):
        return int(raw) / 1000000
    units = {'us': 1e-06, 'ms': 0.001, 's': 1, 'min': 60, 'h': 3600}
    parts = re.findall('([0-9]+(?:\\.[0-9]+)?)(us|ms|min|s|h)', raw)
    need(parts and ''.join((a + b for a, b in parts)) == raw.replace(' ', ''), 'native_duration_schema')
    return sum((float(a) * units[b] for a, b in parts))

def positive(proof, returned, worker_pin, unit=SCOPE_UNIT, operation=EPOCH_OPERATION, runtime_seconds=RUNTIME):
    need(type(worker_pin) is str and re.fullmatch('[0-9a-f]{64}', worker_pin), 'literal_worker_identity')
    raw = proof['unit_raw_utf8'].encode()
    u = proof['unit']
    need(sha(raw) == proof['unit_sha256'] and dict((x.split('=', 1) for x in raw.decode().splitlines())) == u, 'retained_unit_original_raw')
    need(u['Id'] == unit and u['Type'] == 'exec' and (u['User'] == u['Group'] == 'root') and (u['LoadState'] == 'loaded') and (u['ActiveState'] == 'active') and (u['SubState'] == 'exited') and (u['MainPID'] == '0') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['Result'] == 'success') and (u['NRestarts'] == '0') and (u['Restart'] == 'no') and (u['RemainAfterExit'] == 'yes') and (u['SendSIGKILL'] == 'no') and (u['KillMode'] == 'process'), 'true_owned_retained_EXIT0')
    need(seconds(u['CPUQuotaPerSecUSec']) == 1 and u['MemoryMax'] == str(MEMORY) and (u['MemorySwapMax'] == '0') and (u['TasksMax'] == '32') and (u['Nice'] == '10') and (u['IOSchedulingClass'] == '3') and (seconds(u['RuntimeMaxUSec']) == runtime_seconds) and (seconds(u['TimeoutStopUSec']) == 30), 'actual_scope_resource_caps')
    need(u['ExecMainPID'] == str(returned['worker_pid']) and u['InvocationID'] == returned['invocation_id'] and re.fullmatch('[0-9a-f]{32}', u['InvocationID']) and (proof['boot_id'] == returned['boot_id']) and (proof['cgroup_procs'] == []) and (returned['worker_sha256'] == worker_pin) and (returned['loader_returned_zero'] is True) and (returned['operation'] == operation), 'scope_same_boot_invocation_PID_source_emptyCG')
    need('path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -I -B ' + returned['worker_path'] + ' --worker ;' in u['ExecStart'], 'scope_same_exact_exec')
    need(returned['observed_at'] <= returned['finished_at'] <= proof['observed_at'], 'actual_native_after_original_return')
    return True

def argv(worker_path, unit=SCOPE_UNIT):
    need(worker_path in (str(PC_ROOT / 'epoch-scope/worker.py'), str(HISTORY_ROOT / 'history-scope/worker.py')), 'fixed_source_worker_only')
    return ['/usr/bin/systemd-run', '--quiet', '--unit=' + unit, '--service-type=exec', '-p', 'User=root', '-p', 'Group=root', '-p', 'CPUQuota=100%', '-p', 'MemoryMax=192M', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=32', '-p', 'Nice=10', '-p', 'IOSchedulingClass=idle', '-p', 'UMask=0077', '-p', 'RuntimeMaxSec=900', '-p', 'RemainAfterExit=yes', '-p', 'Restart=no', '-p', 'KillMode=process', '-p', 'SendSIGKILL=no', '-p', 'TimeoutStopSec=30', '/usr/bin/python3', '-I', '-B', worker_path, '--worker']
