# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Private transaction file/sole-service checks; no Manager or model control."""
import fcntl, hashlib, json, os, re, stat, subprocess, time
from pathlib import Path
ROOT = Path('/opt/dgx-v4/hx')
BOOT = ROOT / 'bin/hx-bootstrap.py'
UNIT_PATH = Path('/etc/systemd/system/dgx-v4-hx-manager.service')
UNIT = 'dgx-v4-hx-manager.service'
LOCK = Path('/srv/dgx-home-ai/runtime/MAINTENANCE.lock')
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def need(ok, code):
    if not ok:
        raise RuntimeError(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):

    def pairs(rows):
        v = {}
        for k, x in rows:
            need(k not in v, 'duplicate_JSON_key')
            v[k] = x
        return v
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_JSON'))

def identity(st):
    return [getattr(st, k) for k in FIELDS]

def protected(path):
    for p in Path(path).parents:
        s = p.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and (not s.st_mode & 18), 'protected_root_ancestors_required')

def read(path, cap=8 * 1024 ** 2):
    protected(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and (s.st_nlink == 1) and (not s.st_mode & 18) and (s.st_size <= cap), 'root_held_file_required')
        raw = os.pread(fd, s.st_size + 1, 0)
        need(len(raw) == s.st_size and identity(s) == identity(os.fstat(fd)) == identity(Path(path).lstat()), 'held_identity_changed')
        return (raw, s)
    finally:
        os.close(fd)

def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def fresh(path, raw, mode=384, gid=0):
    protected(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, mode)
        v = memoryview(raw)
        while v:
            n = os.write(fd, v)
            need(n > 0, 'partial_write_failed')
            v = v[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    sync(Path(path).parent)

def command(argv, timeout=30):
    p = subprocess.run(argv, capture_output=True, timeout=timeout, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/srv/dgx-home-ai/hx-service', 'PYTHONDONTWRITEBYTECODE': '1'})
    need(len(p.stdout) <= 2 * 1024 ** 2 and len(p.stderr) <= 65536, 'bounded_command_output_required')
    return p

def unit():
    p = command(['/usr/bin/systemctl', 'show', UNIT, '--property=MainPID,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload'])
    need(p.returncode == 0 and (not p.stderr), 'original_unit_observation_failed')
    return dict((s.split('=', 1) for s in p.stdout.decode().splitlines()))

def lock_identity():
    s = LOCK.lstat()
    need(stat.S_ISREG(s.st_mode) and (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode), s.st_nlink, s.st_ino) == (999, 989, 384, 1, 69257), 'original_physical_lock_required')
    return s

def holders():
    s = lock_identity()
    key = f'{os.major(s.st_dev):02x}:{os.minor(s.st_dev):02x}:{s.st_ino}'
    return [int(a[4]) for a in (row.split() for row in Path('/proc/locks').read_text().splitlines()) if len(a) == 8 and a[1:4] == ['FLOCK', 'ADVISORY', 'WRITE'] and (a[5] == key)]

def existing_manager_groups(status):
    lines = [row for row in status.splitlines() if row.startswith('Groups:')]
    need(len(lines) == 1, 'actual_original_Manager_groups_required')
    values = lines[0].split(':', 1)[1].split()
    need(len(values) == 2 and all((re.fullmatch('[0-9]+', x) for x in values)) and (sorted((int(x) for x in values)) == [989, 1000]), 'exact_existing_Manager_groups_989_1000_required')

def original_manager(pid):
    v = unit()
    need(v['MainPID'] == str(pid) and v['ActiveState'] == 'active' and (v['SubState'] == 'running') and (v['UnitFileState'] == 'enabled') and (v['FragmentPath'] == str(UNIT_PATH)) and (v['DropInPaths'] == '') and (v['NeedDaemonReload'] == 'no') and (holders() == [pid]), 'original_sole_unit_required')
    expected = [b'/usr/bin/python3', b'-I', b'-B', bytes(BOOT), b'--serve']
    need(Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\x00').split(b'\x00') == expected, 'exact_original_manager_argv_required')
    status = Path(f'/proc/{pid}/status').read_text()
    need('Uid:\t999\t999\t999\t999' in status and 'Gid:\t989\t989\t989\t989' in status, 'original_manager_UID_GID_required')
    existing_manager_groups(status)
    no_other_manager(allowed=pid)

def no_other_manager(allowed=None):
    found = []
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():
            continue
        try:
            status = (p / 'status').read_text()
            args = (p / 'cmdline').read_bytes().rstrip(b'\x00').split(b'\x00')
        except FileNotFoundError:
            continue
        if bytes(BOOT) in args and b'--serve' in args:
            need('Uid:\t999\t999\t999\t999' in status and args == [b'/usr/bin/python3', b'-I', b'-B', bytes(BOOT), b'--serve'], 'foreign_manager_process_required_refusal')
            found.append(int(p.name))
    need(found == ([] if allowed is None else [allowed]), 'no_second_Manager_required')

def stopped(old_pid):
    v = unit()
    need(v['MainPID'] == '0' and v['ActiveState'] == 'inactive' and (not holders()) and (not Path(f'/proc/{old_pid}').exists()), 'graceful_original_Manager_exit_required')
    no_other_manager()

def lease():
    s = lock_identity()
    fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW)
    try:
        need(identity(os.fstat(fd)) == identity(s), 'physical_lock_replaced')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise

def release(fd):
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
