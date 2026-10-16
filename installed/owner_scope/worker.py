# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Dedicated readonly process entry; fixed source closure and real cgroup gate."""
import base64, builtins, hashlib, json, os, re, stat, sys, time, types
from pathlib import Path
APPROVED_MODULES = {'plan': '3881c8b277f643444497595fcb1ba966d430cb67090f6c88bb8f3da71881a473', 'root_io': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e', 'bounded_process': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f', 'old_failed_kernel': 'cd351ae2db35d0a09d88e5faa05020f9bdec51c898794607fc44c2c148550053'}
APPROVED_BODY = None
APPROVED_UNIT = 'dgx-v4-prelaunch-release-e21f830185b7e1ffbd0ca049a040b4a2.service'
APPROVED_OPERATION = '2b9e9b631cebc13ae6b1550ee59c13ed'
F = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def need(v, r):
    if not v:
        raise RuntimeError(r)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def held(path, pin=None):
    fds = []
    p = Path(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fds.append(fd)
    anchors = []
    try:
        for n in p.parts[1:-1]:
            child = os.open(n, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            z = os.fstat(child)
            need(stat.S_ISDIR(z.st_mode) and z.st_uid == 0 and (not z.st_mode & 18), 'owner_worker_Root_ancestry')
            anchors.append((fd, n, [z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode]))
            fds.append(child)
            fd = child
        leaf = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        fds.append(leaf)
        z = os.fstat(leaf)
        meta = lambda s: [getattr(s, n) for n in F]
        st = meta(z)
        need(stat.S_ISREG(z.st_mode) and st[3:7] == [0, 0, 33152, 1] and (0 < st[2] <= 2097152), 'owner_worker_bounded_leaf_before_read')
        b = os.pread(leaf, z.st_size + 1, 0)
        need(st[3:7] == [0, 0, 33152, 1] and len(b) == st[2] <= 2097152 and (st == meta(os.fstat(leaf)) == meta(os.stat(p.name, dir_fd=fd, follow_symlinks=False))) and (pin is None or sha(b) == pin), 'owner_worker_full_SHA_FD_named')
        for parent, n, before in anchors:
            z = os.stat(n, dir_fd=parent, follow_symlinks=False)
            need(before == [z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode], 'owner_worker_ancestor_after')
        return (b, st)
    finally:
        for fd in reversed(fds):
            os.close(fd)

def main():
    need(os.getuid() == os.geteuid() == 0 and sys.platform == 'linux' and (type(APPROVED_MODULES) is dict) and (set(APPROVED_MODULES) == {'plan', 'root_io', 'bounded_process', 'old_failed_kernel'}) and (type(APPROVED_BODY) is bytes), 'owner_worker_SOURCE_None')
    root = Path(__file__).parent
    mods = {}
    sources = {}
    path_before = list(sys.path)
    table_before = {n: sys.modules.get(n) for n in APPROVED_MODULES}
    need(all((v is None for v in table_before.values())), 'owner_worker_no_ambient_helpers')

    def imports(n, g=None, l=None, fromlist=(), level=0):
        need(not level, 'owner_worker_no_relative_ambient_import')
        if n in mods:
            return mods[n]
        need(n.split('.')[0] in sys.stdlib_module_names, 'owner_worker_closed_import')
        return builtins.__import__(n, g, l, fromlist, 0)
    try:
        for n in ('plan', 'root_io', 'bounded_process', 'old_failed_kernel'):
            path = root / (n + '.py')
            b, f = held(path, APPROVED_MODULES[n])
            sources[n] = (b, f)
            m = types.ModuleType('_owner_readonly_' + n)
            m.__file__ = str(path)
            m.__dict__['__builtins__'] = dict(vars(builtins), __import__=imports)
            mods[n] = m
            exec(compile(b, str(path), 'exec'), m.__dict__)
        inv = os.environ.get('INVOCATION_ID', '')
        need(re.fullmatch('[0-9a-f]{32}', inv) and Path('/proc/self/cgroup').read_text().strip() == '0::/system.slice/' + APPROVED_UNIT, 'owner_worker_exact_scope_invocation')
        cg = Path('/sys/fs/cgroup/system.slice') / APPROVED_UNIT
        resources = {n: (cg / n).read_text().strip() for n in ('cpu.max', 'memory.max', 'memory.swap.max', 'pids.max', 'cgroup.procs')}
        need(resources == {'cpu.max': '100000 100000', 'memory.max': '201326592', 'memory.swap.max': '0', 'pids.max': '32', 'cgroup.procs': str(os.getpid())}, 'owner_worker_CPU1_memory192_swap0_tasks32')
        request, rf = held(root / 'request.json')
        begin, bf = held(root / 'PC-BEGIN-original.json')
        start = time.time()
        body = types.ModuleType('_owner_readonly_body')
        body.__file__ = str(root / 'worker.py')
        body.__dict__['__builtins__'] = dict(vars(builtins), __import__=imports)
        exec(compile(APPROVED_BODY, body.__file__, 'exec'), body.__dict__)
        value = body.run(request, json.loads(begin))
        raw = encode(value)
        mods['root_io'].fresh(root / 'body.raw.json', raw)
        own, own_f = held(root / 'worker.py')
        returned = {'operation': APPROVED_OPERATION, 'worker_sha256': sha(own), 'worker_path': str(root / 'worker.py'), 'worker_stat': own_f, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'invocation_id': inv, 'worker_pid': os.getpid(), 'child_rc': 0, 'stderr_bytes': 0, 'proof_sha256': sha(raw), 'request_sha256': sha(request), 'stdout_sha256': sha(raw), 'started_at': start, 'observed_at': time.time(), 'finished_at': time.time(), 'PC_begin_raw_sha256': json.loads(begin)['sha256']}
        mods['root_io'].fresh(root / 'returned.json', encode(returned))
        need(all((held(root / (n + '.py'), APPROVED_MODULES[n]) == r for n, r in sources.items())), 'owner_worker_source_fullF9_after')
        return 0
    finally:
        need(sys.path == path_before and all((sys.modules.get(n) is old for n, old in table_before.items())), 'owner_worker_canonical_path_unchanged')
if __name__ == '__main__':
    raise SystemExit(main())
