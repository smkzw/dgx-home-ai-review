# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual fixed PC Root read-only producer; no runtime/Manager/Adapter creation."""
import os, stat, time, types
from pathlib import Path
from B_OWNER_RECOVERY_R25_WIRING.common import need, sha, strict, protected_read, metadata, HeldParent
CONFIG = Path('/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json')
OPERATOR = Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d')
SOCKET = str(OPERATOR / 'operator.sock')
HERE = Path(__file__).resolve().parent
APPROVED_INPUT_PINS = None
APPROVED_CONFIG_SHA = None
APPROVED_OLD_CONFIG_SHA = None

def held_module(name, relative):
    raw, _ = protected_read(HERE / relative, limit=2097152)
    need(APPROVED_INPUT_PINS is not None and sha(raw) == APPROVED_INPUT_PINS[relative], 'fixed_root_current_dependencies')
    m = types.ModuleType(name)
    m.__file__ = str(HERE / relative)
    exec(compile(raw, m.__file__, 'exec'), m.__dict__)
    return m

def socket_owners(inode, deadline):
    result = set()
    count = 0
    procs = list(Path('/proc').iterdir())
    need(len(procs) <= 8192, 'bounded_proc_inventory')
    for p in procs:
        need(time.monotonic() < deadline, 'socket_owner_deadline')
        if not p.name.isdigit():
            continue
        try:
            descriptors = list((p / 'fd').iterdir())
        except FileNotFoundError:
            continue
        for fd in descriptors:
            count += 1
            need(count <= 131072 and time.monotonic() < deadline, 'bounded_FD_inventory')
            try:
                target = os.readlink(fd)
            except FileNotFoundError:
                continue
            if target == 'socket:[' + inode + ']':
                result.add(int(p.name))
    return sorted(result)

class CurrentReader:

    def __init__(self, expected_config_sha=None):
        need(APPROVED_INPUT_PINS is not None and APPROVED_CONFIG_SHA is not None and (os.geteuid() == 0) and (__import__('sys').platform == 'linux'), 'negative_Root_current_SOURCE_pending')
        expected_config_sha = APPROVED_CONFIG_SHA if expected_config_sha is None else expected_config_sha
        need(expected_config_sha in (APPROVED_CONFIG_SHA, APPROVED_OLD_CONFIG_SHA), 'fixed_current_or_original_config_only')
        self.io = held_module('negative_fixed_existing_IO', 'inputs/io_utils.py')
        self.helpers = held_module('negative_fixed_existing_helpers', 'inputs/old_installer_helpers.py')
        raw, st = protected_read(CONFIG)
        need(sha(raw) == expected_config_sha, 'new_config_current_SHA')
        self.config = strict(raw)
        self.config['_config_sha256'] = sha(raw)
        self.cfgmeta = st

    def capture(self, deadline):
        need(time.monotonic() < deadline, 'Root_current_deadline')
        unit = self.io.unit()
        pid = int(unit['MainPID'])
        need(pid > 1, 'current_sole_not_running')
        self.io.original_manager(pid)
        inv = self.io.command(['/usr/bin/systemctl', 'show', self.io.UNIT, '--property=InvocationID'], timeout=min(10, max(0.1, deadline - time.monotonic())))
        need(inv.returncode == 0 and (not inv.stderr), 'current_invocation_unknown')
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        rawstat = Path('/proc/' + str(pid) + '/stat').read_text()
        ticks = rawstat.rsplit(')', 1)[1].split()[19]
        identity = {'pid': pid, 'start_ticks': ticks, 'boot_id': boot, 'invocation_id': inv.stdout.decode().strip().removeprefix('InvocationID=')}
        files = {}
        for path, pin in self.config['PC_source_pins'].items():
            need(time.monotonic() < deadline, 'current_source_deadline')
            body, st = protected_read(path)
            need(sha(body) == pin, 'current118_source_drift')
            files[path] = {'sha256': pin, 'stat': st}
        need(len(files) == 118, 'exact_current118')
        cfg, cs = protected_read(CONFIG)
        need(sha(cfg) == self.config['_config_sha256'] and cs == self.cfgmeta, 'current_config_fullF9')
        leaf, ls = protected_read(OPERATOR / 'C-parent-acceptance.json')
        need(sha(leaf) == self.config['C_actual_parent_acceptance_sha256'], 'current_Cleaf')
        lock = self.io.lock_identity()
        need([lock.st_dev, lock.st_ino] == [2096, 69257] and self.io.holders() == [pid], 'actual_original_lease_held_by_sole')
        with HeldParent(Path(SOCKET), legacy=True) as ancestry:
            s = ancestry.named_leaf()
            need(stat.S_ISSOCK(s.st_mode) and (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink) == (999, 989, 384, 1), 'current_owned_socket_FS')
            rows = Path('/proc/net/unix').read_text().splitlines()[1:]
            entries = [r.split()[6] for r in rows if len(r.split()) == 8 and r.split()[7] == SOCKET]
            need(len(entries) == 1, 'unique_current_kernel_socket')
            owners = socket_owners(entries[0], min(deadline, time.monotonic() + 15))
            need(owners == [pid], 'unique_socket_FD_sole_owner')
            socket = {'path': SOCKET, 'stat': metadata(s), 'kernel_inode': entries[0], 'owners': owners}
        rows = self.helpers.actual_rows(self.io)
        commands = self.helpers.read_command_history()
        need(time.monotonic() < deadline, 'complete_Root_current_deadline')
        self.io.original_manager(pid)
        need(Path('/proc/' + str(pid) + '/stat').read_text().rsplit(')', 1)[1].split()[19] == ticks and metadata(self.io.lock_identity()) == metadata(lock), 'source_epoch_lease_PID_stable')
        return {'manager_identity': identity, 'current_source118': self.config['PC_source_pins'], 'source_files': files, 'config_sha256': sha(cfg), 'config_stat': cs, 'Cleaf': {'sha256': sha(leaf), 'stat': ls}, 'lease_dev_inode': [lock.st_dev, lock.st_ino], 'lease_full_F9': metadata(lock), 'socket': socket, 'rows_original': rows, 'commands': commands, 'observed_at': time.time()}

    def capture_stopped(self, deadline):
        files = {}
        for path, pin in self.config['PC_source_pins'].items():
            need(time.monotonic() < deadline, 'stopped_source_deadline')
            body, st = protected_read(path)
            need(sha(body) == pin, 'stopped118_source_drift')
            files[path] = {'sha256': pin, 'stat': st}
        raw, st = protected_read(CONFIG)
        need(sha(raw) == self.config['_config_sha256'] and st == self.cfgmeta, 'stopped_config_original')
        leaf, ls = protected_read(OPERATOR / 'C-parent-acceptance.json')
        need(sha(leaf) == self.config['C_actual_parent_acceptance_sha256'], 'stopped_actual_Cleaf')
        lock = self.io.lock_identity()
        need([lock.st_dev, lock.st_ino] == [2096, 69257] and self.io.holders() == [os.getpid()], 'stopped_original_lease_installer_only')
        rows = self.helpers.actual_rows(self.io)
        commands = self.helpers.read_command_history()
        need(time.monotonic() < deadline, 'stopped_rows_deadline')
        need(protected_read(OPERATOR / 'C-parent-acceptance.json') == (leaf, ls) and metadata(self.io.lock_identity()) == metadata(lock) and (self.io.holders() == [os.getpid()]), 'stopped_Cleaf_lease_after_actual_rows')
        return {'current_source118': self.config['PC_source_pins'], 'source_files': files, 'config_sha256': sha(raw), 'config_stat': st, 'Cleaf': {'sha256': sha(leaf), 'stat': ls}, 'lease_dev_inode': [lock.st_dev, lock.st_ino], 'lease_full_F9': metadata(lock), 'rows_original': rows, 'commands': commands, 'observed_at': time.time()}

    def connect(self, seconds):
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(seconds)
        try:
            s.connect(SOCKET)
            return s
        except BaseException:
            s.close()
            raise
