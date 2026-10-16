# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Finite source-only A readiness in a NEW readonly unit. Default literal None."""
import os, sys, time, platform, stat, re, base64
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import plan
from root_io import held, fresh, sha, f9
from bounded_process import capture
APPROVED_ENTRY = {'index_sha256': '6bd34702b74fd9cf6af1764da5a75e520b63fd7c924be424257cc59e1691ca32', 'review_sha256': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'}
APPROVED_NVME = {'sysfs': {'259:0': {'dev': '259:0\n', 'parent_dev': '235:0\n', 'partition_exists': False, 'queue_exists': True, 'realpath': '/sys/devices/pci0004:00/0004:00:00.0/0004:01:00.0/nvme/nvme0/nvme0n1'}, '259:2': {'dev': '259:2\n', 'parent_dev': '259:0\n', 'partition': '2\n', 'partition_exists': True, 'queue_exists': False, 'realpath': '/sys/devices/pci0004:00/0004:00:00.0/0004:01:00.0/nvme/nvme0/nvme0n1/nvme0n1p2'}}, 'filesystem': {'path': '/dev/nvme0n1p2', 'stat': [7, 227, 0, 0, 6, 25008, 1, 1791712401913318136, 1791712401913318136], 'major_minor': '259:2', 'rdev': 66306}, 'originating_io': {'path': '/dev/nvme0n1', 'stat': [7, 224, 0, 0, 6, 25008, 1, 1791712401901297875, 1791712401901297875], 'major_minor': '259:0', 'rdev': 66304}}
_ENTRY_PHASE = 'source_admission'
ENTRY_PHASES = frozenset(('source_admission', 'source_context', 'source_closure', 'payload_absence', 'resource_floor', 'NVMe_identity', 'kernel_readonly', 'tools', 'route', 'config_raw', 'config_CLI', 'config_merged', 'returned'))

def phase(name):
    global _ENTRY_PHASE
    plan.need(name in ENTRY_PHASES, 'fixed_entry_failure_phase')
    _ENTRY_PHASE = name

def command_original(name, args, result):
    fresh(Path(plan.ENTRY_STATE) / name, plan.encode({'schema': 'entry-config-readonly-command-original/v1', 'argv': args, 'returncode': result.returncode, 'stdout_b64': base64.b64encode(result.stdout).decode(), 'stderr_b64': base64.b64encode(result.stderr).decode(), 'observed_at': time.time()}))

def failure(error):
    import diagnostics
    body = dict(diagnostics.details(error, _ENTRY_PHASE), schema='registry-R26-A-entry-failed-preserved/v1', operation=plan.OPERATION, reason_code='entry_readonly_failed', retry=False, worker_pid=os.getpid(), worker_sha256=sha(Path(__file__).read_bytes()), observed_at=time.time())
    fresh(Path(plan.ENTRY_STATE) / 'failed.json', plan.encode(body))
    return 1

def readonly_kernel():
    rows = [s[3:] for s in Path('/proc/self/cgroup').read_text().splitlines() if s.startswith('0::')]
    plan.need(rows == ['/system.slice/' + plan.ENTRY_UNIT], 'actual_entry_current_cgroup')
    root = Path('/sys/fs/cgroup' + rows[0])
    v = {n: (root / n).read_text().strip() for n in ('cpu.max', 'memory.max', 'memory.swap.max', 'pids.max', 'cgroup.procs')}
    q = v['cpu.max'].split()
    plan.need(len(q) == 2 and q[0].isdigit() and q[1].isdigit() and (0 < int(q[0]) <= int(q[1])) and (v['memory.max'] == '201326592') and (v['memory.swap.max'] == '0') and (v['pids.max'] == '32') and (v['cgroup.procs'].split() == [str(os.getpid())]), 'actual_entry_CPU1_192M_swap0_tasks32_ownedPID')
    return dict(v, cgroup=rows[0], worker_pid=os.getpid(), observed_at=time.time())

def sysfs_original(expected):
    out = {}
    for device, pin in expected['sysfs'].items():
        real = Path('/sys/dev/block') / device
        real = real.resolve(strict=True)
        plan.need(str(real) == pin['realpath'], 'exact_actual_sysfs_device_realpath')
        row = {'dev': (real / 'dev').read_text(), 'parent_dev': (real.parent / 'dev').read_text(), 'partition_exists': (real / 'partition').exists(), 'queue_exists': (real / 'queue').exists(), 'realpath': str(real)}
        if row['partition_exists']:
            row['partition'] = (real / 'partition').read_text()
        plan.need(row == pin, 'exact_partition_parent_queue_raw_provenance')
        out[device] = row
    plan.need(out['259:2']['parent_dev'] == out['259:0']['dev'] == '259:0\n' and Path(out['259:2']['realpath']).parent == Path(out['259:0']['realpath']) and (out['259:2']['partition'] == '2\n') and (out['259:2']['queue_exists'] is False) and (out['259:0']['partition_exists'] is False) and (out['259:0']['queue_exists'] is True), 'systemd255_whole_disk_IO_mapping_actual_sysfs')
    return out

def nvme_identity(c):
    plan.need(APPROVED_NVME is not None, 'actual_NVMe_dual_full_identity_SOURCE_pending')
    expected = APPROVED_NVME
    filesystem = expected['filesystem']
    fds = []
    before = {}
    plan.need((c['NVMe_device'], c['NVMe_major_minor']) == (filesystem['path'], filesystem['major_minor']) == ('/dev/nvme0n1p2', '259:2'), 'fixed_actual_filesystem_partition')
    try:
        for kind in ('filesystem', 'originating_io'):
            pin = expected[kind]
            path = Path(pin['path'])
            z = path.lstat()
            mm = str(os.major(z.st_rdev)) + ':' + str(os.minor(z.st_rdev))
            plan.need(stat.S_ISBLK(z.st_mode) and z.st_uid == 0 and (z.st_gid == 6) and (f9(z) == pin['stat']) and (z.st_rdev == pin['rdev']) and (mm == pin['major_minor']), 'dual_NVMe_Root_disk_fullF9_rdev')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            fds.append(fd)
            held_device = os.fstat(fd)
            plan.need(f9(held_device) == f9(z) and held_device.st_rdev == z.st_rdev, 'held_dual_actual_NVMe_device')
            before[kind] = (path, z, fd)
        payload = Path('/var/lib/dgx-v4').lstat()
        stage = Path(plan.STAGE).lstat()
        for d in (payload, stage):
            plan.need(stat.S_ISDIR(d.st_mode) and d.st_uid == d.st_gid == 0 and (not d.st_mode & 18), 'actual_NVMe_Root_filesystem_directories')
        plan.need(filesystem['rdev'] == payload.st_dev == stage.st_dev == 66306, 'both_filesystems_on_partition_not_whole_disk')
        sysfs = sysfs_original(expected)
        for path, z, fd in before.values():
            plan.need(f9(os.fstat(fd)) == f9(z) == f9(path.lstat()) and os.fstat(fd).st_rdev == path.lstat().st_rdev, 'dual_NVMe_held_named_fullF9_after')
        plan.need(f9(payload) == f9(Path('/var/lib/dgx-v4').lstat()) and f9(stage) == f9(Path(plan.STAGE).lstat()) and (sysfs_original(expected) == sysfs), 'filesystem_and_sysfs_exact_after')
        v = {'schema': 'registry-R26-NVMe-filesystem-originating-IO-identity/v1', 'filesystem': filesystem, 'originating_io': expected['originating_io'], 'sysfs_original': sysfs, 'payload_parent_device': payload.st_dev, 'stage_device': stage.st_dev}
        plan.validate_nvme_identity(v)
        return v
    finally:
        for fd in reversed(fds):
            os.close(fd)

def collect():
    phase('source_admission')
    plan.need(APPROVED_ENTRY is not None and os.getuid() == os.geteuid() == 0 and (platform.node() == 'spark-a321') and (sys.platform == 'linux'), 'entry_source_None_or_not_fixed_Root_A')
    raw, s = held(Path(plan.STAGE) / 'source-index.json', APPROVED_ENTRY['index_sha256'], mode=384)
    index = plan.strict(raw)
    phase('source_context')
    ctx, cs = held(Path(plan.STAGE) / 'entry-context.json', mode=384)
    c = plan.strict(ctx)
    plan.need(c['operation'] == plan.OPERATION and c['review_sha256'] == index['review_sha256'] == APPROVED_ENTRY['review_sha256'] and (len(c['current_PC_source118']) == 118), 'entry_exact_newsource_scope')
    phase('source_closure')
    sources = {}
    for name, pin in index['files'].items():
        raw, st = held(Path(plan.STAGE) / name, pin, mode=384)
        sources[name] = {'sha256': sha(raw), 'stat': st}
    phase('payload_absence')
    plan.need(not Path(plan.ROOT).exists(), 'new_payload_namespace_absent_before_grant')
    phase('resource_floor')
    mem = {x.split(':', 1)[0]: x.split(':', 1)[1].strip() for x in Path('/proc/meminfo').read_text().splitlines()}
    available = int(mem['MemAvailable'].split()[0]) * 1024
    plan.need(os.stat(plan.STAGE).st_dev == os.stat('/var/lib/dgx-v4').st_dev, 'same_actual_NVMe_stage_and_payload_parent')
    phase('NVMe_identity')
    nvme = nvme_identity(c)
    free = os.statvfs('/var/lib/dgx-v4')
    freebytes = free.f_bavail * free.f_frsize
    plan.need(available >= 8 * 1024 ** 3 and freebytes >= plan.WORKSPACE + plan.RESERVE, 'actual_A_RAM_NVMe_floors')
    phase('kernel_readonly')
    kernel = readonly_kernel()
    phase('tools')
    tools = {}
    end = time.monotonic() + 80
    for name, t in c['tools'].items():
        code, st = held(t['path'], t['sha256'], cap=128 * 1024 ** 2)
        plan.need(st == t['stat'], 'actual_entry_tool_identity')
        tools[name] = {'path': t['path'], 'sha256': sha(code), 'stat': st}
    phase('route')
    route = capture([c['tools']['ip']['path'], '-j', 'route', 'get', '192.0.2.10'], env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, deadline=min(end, time.monotonic() + 5), cap=16384)
    plan.need(route.returncode == 0 and (not route.stderr), 'actual_source_route_nonzero')
    r = plan.strict(route.stdout)
    plan.need(len(r) == 1 and r[0]['dev'] == 'enP7s7' and (r[0]['prefsrc'] == '192.0.2.10') and (r[0]['gateway'] == '192.0.2.10'), 'actual_A_direct_wired_route')
    phase('config_raw')
    import private_config
    cfg = private_config.config_bytes(plan.ROOT)
    actual, _ = held(Path(plan.STAGE) / 'containerd.candidate.toml')
    plan.need(actual == cfg, 'fixed_private_containerd_raw')
    phase('config_CLI')
    version = capture([tools['containerd']['path'], '--version'], env={'PATH': '/usr/bin:/usr/sbin:/bin', 'LANG': 'C'}, deadline=min(end, time.monotonic() + 5), cap=16384)
    dump = capture([tools['containerd']['path'], '--config', plan.STAGE + '/containerd.candidate.toml', 'config', 'dump'], env={'PATH': '/usr/bin:/usr/sbin:/bin', 'LANG': 'C', 'HOME': plan.ROOT + '/home', 'CONTAINERD_DISABLE_PIGZ': 'true', 'CONTAINERD_DISABLE_IGZIP': 'true'}, deadline=end, cap=262144)
    command_original('containerd-version-command.json', [tools['containerd']['path'], '--version'], version)
    command_original('containerd-dump-command.json', [tools['containerd']['path'], '--config', plan.STAGE + '/containerd.candidate.toml', 'config', 'dump'], dump)
    fresh(Path(plan.ENTRY_STATE) / 'config-dump.raw', dump.stdout)
    fresh(Path(plan.ENTRY_STATE) / 'route.raw', route.stdout)
    plan.need(version.returncode == dump.returncode == 0 and (not version.stderr) and (not dump.stderr), 'actual_config_CLI_exit0')
    phase('config_merged')
    config = private_config.validate(cfg, dump.stdout, plan.ROOT, tools['containerd']['sha256'], version.stdout)
    phase('returned')
    body = {'schema': 'registry-R26-A-entry-returned/v1', 'operation': plan.OPERATION, 'worker_pid': os.getpid(), 'worker_sha256': sha(Path(__file__).read_bytes()), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': os.environ['INVOCATION_ID'], 'child_rc': 0, 'stderr_bytes': 0, 'result': {'sources': sources, 'index_sha256': sha(raw), 'current_PC_source118': c['current_PC_source118'], 'manager_identity': c['manager_identity'], 'PC_config_sha256': c['PC_config_sha256'], 'private_config': config, 'tools': tools, 'NVMe_identity': nvme, 'kernel_original': kernel, 'MemAvailable_bytes': available, 'NVMe_free_bytes': freebytes, 'actual_route_raw_sha256': sha(route.stdout), 'payload_namespace_absent': True, 'daemon_started': False, 'models_started': 0}, 'observed_at': time.time()}
    body['result']['index_sha256'] = APPROVED_ENTRY['index_sha256']
    fresh(Path(plan.ENTRY_STATE) / 'returned-zero.json', plan.encode(body))
    return 0
if __name__ == '__main__':
    if APPROVED_ENTRY is None:
        raise SystemExit(0)
    try:
        raise SystemExit(collect())
    except Exception as e:
        raise SystemExit(failure(e))
