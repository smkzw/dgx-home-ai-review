# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure consumer for a future fresh sole-owner grant and actual kernel collector.

No producer, lease acquisition, source activation, or Root entry is synthesized.
The source-reviewed operation/source literals remain None until integration review.
"""
import hashlib
import json
import math
import os
import re
import resource
import stat
import time
from contract import Refused, need
from fetch import write_all
EXPECTED_OPERATION = None
EXPECTED_SOURCE_RELEASE = None
UNIT = 'dgx-v4-mimo-registry-native-asset-protocol-r12.service'
CG = '/system.slice/' + UNIT
CAP = 1024 ** 2
AS = 192 * 1024 ** 2

def limit_address_space():
    """Future worker-local bound, never a shared daemon or host policy change."""
    resource.setrlimit(resource.RLIMIT_AS, (AS, AS))
    need(resource.getrlimit(resource.RLIMIT_AS) == (AS, AS), 'actual_worker_RLIMIT_AS')

def collect_kernel(NVMe_major_minor):
    """Bounded native readonly supplier; not invoked by this source task or entry."""

    def read(path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            raw = os.read(fd, 16385)
            need(len(raw) <= 16384, 'bounded_kernel_read')
            return raw.decode().strip()
        finally:
            os.close(fd)
    cgroups = [s[3:] for s in read('/proc/self/cgroup').splitlines() if s.startswith('0::')]
    need(len(cgroups) == 1 and cgroups[0].startswith(CG + '/') and ('..' not in cgroups[0].split('/')), 'actual_owned_kernel_cgroup')
    need(type(NVMe_major_minor) is str and re.fullmatch('[0-9]+:[0-9]+', NVMe_major_minor), 'review_bound_NVMe')
    base = '/sys/fs/cgroup' + CG
    result = {k: read(base + '/' + k) for k in ('cpu.max', 'memory.max', 'memory.swap.max', 'pids.max', 'io.max')}
    process_stat = read('/proc/self/stat').rsplit(')', 1)[1].split()
    ticks = process_stat[19]
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    return {**result, 'boot_id': read('/proc/sys/kernel/random/boot_id'), 'invocation_id': os.environ.get('INVOCATION_ID'), 'pid': os.getpid(), 'start_ticks': int(ticks), 'nice': int(process_stat[16]), 'cgroup': cgroups[0], 'top_cgroup': CG, 'NVMe_major_minor': NVMe_major_minor, 'RSS_bytes': int(read('/proc/self/statm').split()[1]) * os.sysconf('SC_PAGE_SIZE'), 'address_space_soft_bytes': soft, 'address_space_hard_bytes': hard, 'observed_at': time.time()}

def consume_pulse(raw, expected_operation, expected_source, identity, now):
    from contract import parse
    need(type(expected_operation) is str and re.fullmatch('[0-9a-f]{32}', expected_operation) and (type(expected_source) is str) and re.fullmatch('[0-9a-f]{64}', expected_source), 'unbound_future_owner_grant')
    need(type(raw) is bytes and 0 < len(raw) <= 4 * 1024 ** 2, 'bounded_pulse_raw')
    p = parse(raw)
    need(set(p) == {'schema', 'operation', 'source_release_sha256', 'config_sha256', 'ordinal', 'request_nonce', 'manager_epoch_sha256', 'budget', 'remaining_seconds', 'manager_source', 'clear_reservation_original', 'clear_reservation_sha256', 'observed_at'}, 'original_pulse_ABI')
    need(p['schema'] == 'sole-Manager-private-CPU-reservation-pulse/v1' and p['operation'] == expected_operation and (p['source_release_sha256'] == expected_source) and (type(p['ordinal']) is int) and (p['ordinal'] > 0) and re.fullmatch('[0-9a-f]{32}', p['request_nonce']), 'same_fixed_source_operation_pulse')
    need(type(p['observed_at']) in (int, float) and math.isfinite(p['observed_at']) and (0 <= now - p['observed_at'] <= 10) and (type(p['remaining_seconds']) in (int, float)) and math.isfinite(p['remaining_seconds']) and (0 < p['remaining_seconds'] <= 1800), 'fresh_unexpired_original_pulse')
    need(set(p['budget']) == {'CPU', 'memory_bytes', 'swap_bytes', 'tasks', 'io_read_bytes_per_second', 'io_write_bytes_per_second', 'runtime_seconds'} and {k: v for k, v in p['budget'].items() if k != 'runtime_seconds'} == {'CPU': 1, 'memory_bytes': 4 * 1024 ** 3, 'swap_bytes': 0, 'tasks': 256, 'io_read_bytes_per_second': 62914560, 'io_write_bytes_per_second': 62914560} and (type(p['budget']['runtime_seconds']) is int) and (0 < p['budget']['runtime_seconds'] <= 1800), 'same_finite_parent_budget_resources')
    need(type(identity) is dict and p['manager_source'] == identity['manager_source'] and (p['manager_epoch_sha256'] == identity['manager_epoch_sha256']) and (p['config_sha256'] == identity['config_sha256']) and (p['clear_reservation_sha256'] == identity['clear_reservation_sha256']), 'actual_same_epoch_physical_lease_origin')
    need(p['clear_reservation_original'] == identity['clear_reservation_original'], 'original_reservation_not_replaced')
    return p

def kernel(row, boot, invocation, pid):
    need(set(row) == {'boot_id', 'invocation_id', 'pid', 'start_ticks', 'nice', 'cgroup', 'top_cgroup', 'cpu.max', 'memory.max', 'memory.swap.max', 'pids.max', 'io.max', 'NVMe_major_minor', 'RSS_bytes', 'address_space_soft_bytes', 'address_space_hard_bytes', 'observed_at'}, 'complete_actual_kernel_snapshot')
    need(row['boot_id'] == boot and row['invocation_id'] == invocation and (row['pid'] == pid) and (type(row['start_ticks']) is int) and (row['start_ticks'] > 0) and (type(row['nice']) is int) and (row['nice'] == 10) and (row['top_cgroup'] == CG) and row['cgroup'].startswith(CG + '/'), 'owned_actual_process_subtree')
    cpu = row['cpu.max'].split()
    need(len(cpu) == 2 and cpu[0].isdigit() and cpu[1].isdigit() and (0 < int(cpu[0]) <= int(cpu[1])), 'actual_CPU1')
    need(row['memory.max'].isdigit() and 0 < int(row['memory.max']) <= 4 * 1024 ** 3 and (row['memory.swap.max'] == '0') and row['pids.max'].isdigit() and (0 < int(row['pids.max']) <= 256), 'actual_aggregate_memory_swap_tasks')
    need(re.fullmatch('[0-9]+:[0-9]+', row['NVMe_major_minor']), 'actual_NVMe_identity')
    lines = [s.split() for s in row['io.max'].splitlines()]
    matches = [s for s in lines if s and s[0] == row['NVMe_major_minor']]
    need(len(matches) == 1, 'actual_IO_device_cap')
    items = dict((item.split('=', 1) for item in matches[0][1:]))
    need(set(items) <= {'rbps', 'wbps', 'riops', 'wiops'} and all((k in items and items[k].isdigit() and (0 < int(items[k]) <= 60 * 1024 ** 2) for k in ('rbps', 'wbps'))), 'actual_IO60MiB')
    need(type(row['RSS_bytes']) is int and 0 < row['RSS_bytes'] <= 192 * 1024 ** 2, 'sampled_worker_RSS_budget')
    need(row['address_space_soft_bytes'] == row['address_space_hard_bytes'] == AS, 'actual_worker_AS_bound')
    return row

class Supervisor:

    def __init__(self, trace_fd, pulse, snapshot, identity, budget, wall, boot, invocation, operation=EXPECTED_OPERATION, source=EXPECTED_SOURCE_RELEASE, pulse_wall=None):
        s = os.fstat(trace_fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and (stat.S_IMODE(s.st_mode) == 384) and (s.st_nlink == 1) and (s.st_size == 0), 'new_private_empty_trace')
        self.fd, self.pulse, self.snapshot, self.identity, self.budget, self.wall = (trace_fd, pulse, snapshot, identity, budget, wall)
        self.boot, self.invocation, self.operation, self.source = (boot, invocation, operation, source)
        self.pulse_wall = pulse_wall or wall
        self.last, self.ordinal, self.bytes, self.failed, self.start_ticks = (None, 0, 0, False, None)

    def sample(self, force=False):
        need(not self.failed, 'supervision_sticky_failure')
        if not force and self.last is not None and (self.budget.clock() - self.last < 5):
            return
        try:
            raw = self.pulse()
            p = consume_pulse(raw, self.operation, self.source, self.identity, self.pulse_wall())
            need(p['ordinal'] > self.ordinal, 'pulse_monotonic_not_replayed')
            row = kernel(self.snapshot(), self.boot, self.invocation, os.getpid())
            need(type(row['observed_at']) in (int, float) and math.isfinite(row['observed_at']) and (0 <= self.wall() - row['observed_at'] <= 2), 'fresh_actual_kernel_read')
            if self.start_ticks is None:
                self.start_ticks = row['start_ticks']
            need(row['start_ticks'] == self.start_ticks, 'same_actual_PID_start_ticks')
            now = self.budget.clock()
            record = {'observed_at': self.wall(), 'monotonic': now, 'sample_gap': None if self.last is None else now - self.last, 'kernel': row, 'pulse_sha256': hashlib.sha256(raw).hexdigest(), 'pulse_ordinal': p['ordinal'], 'pulse_original_observed_at': p['observed_at'], 'remaining_seconds': p['remaining_seconds'], 'sampled_RSS_only': True, 'source_authorization': False}
            data = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
            need(self.bytes + len(data) <= CAP and os.fstat(self.fd).st_size == self.bytes, 'bounded_trace_no_foreign_writer')
            write_all(self.fd, data)
            os.fsync(self.fd)
            self.bytes += len(data)
            self.last, self.ordinal = (now, p['ordinal'])
            self.budget.deadline = min(self.budget.deadline, now + p['remaining_seconds'])
            need(self.budget.deadline > now, 'unexpired_same_owner_grant')
        except Exception:
            self.failed = True
            raise Refused('supervision_failed_sticky') from None
