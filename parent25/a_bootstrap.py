# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure stdlib held-source bootstrap for the existing PC Root RPC only."""
import hashlib, importlib.abc, importlib.util, json, os, stat, sys
from pathlib import Path
POLICY = None
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def need(v, s):
    if not v:
        raise RuntimeError(s)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def f9(z):
    return [getattr(z, k) for k in FIELDS]

def held(path, pin, expected=None, cap=2097152):
    p = Path(path)
    need(p.is_absolute(), 'fixed_absolute_source')
    chain = []
    try:
        parent = None
        for x in [Path('/'), *reversed(p.parent.parents[:-1]), p.parent] if p.parent != Path('/') else [Path('/')]:
            if chain and x == chain[-1][0]:
                continue
            fd = os.open(x, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            z = os.fstat(fd)
            n = x.lstat()
            ident = (z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode)
            need(stat.S_ISDIR(z.st_mode) and z.st_uid == 0 and (not z.st_mode & 18) and (ident == (n.st_dev, n.st_ino, n.st_uid, n.st_gid, n.st_mode)), 'Root_source_ancestor')
            chain.append((x, fd, ident))
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=chain[-1][1])
        try:
            z = os.fstat(fd)
            need(stat.S_ISREG(z.st_mode) and z.st_uid == 0 and (z.st_nlink == 1) and (not z.st_mode & 18) and (0 <= z.st_size <= cap), 'Root_source_leaf')
            raw = os.pread(fd, z.st_size + 1, 0)
            need(len(raw) == z.st_size and sha(raw) == pin and (f9(z) == f9(os.fstat(fd)) == f9(p.lstat())) and (expected is None or f9(z) == expected), 'full_source_SHA_F9')
        finally:
            os.close(fd)
        for x, fd, ident in chain:
            a = os.fstat(fd)
            b = x.lstat()
            need(ident == (a.st_dev, a.st_ino, a.st_uid, a.st_gid, a.st_mode) == (b.st_dev, b.st_ino, b.st_uid, b.st_gid, b.st_mode), 'Root_ancestor_identity_changed')
        return (raw, f9(z))
    finally:
        for _, fd, _ in reversed(chain):
            os.close(fd)

def strict(raw):

    def pairs(xs):
        d = {}
        for k, v in xs:
            need(k not in d, 'duplicate_bootstrap_key')
            d[k] = v
        return d
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_bootstrap'))

class Loader(importlib.abc.Loader):

    def __init__(self, path, pin, meta):
        self.path, self.pin, self.meta = (path, pin, meta)

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        raw, _ = held(self.path, self.pin, self.meta)
        module.__file__ = self.path
        exec(compile(raw, self.path, 'exec'), module.__dict__)

class Finder(importlib.abc.MetaPathFinder):

    def __init__(self, table):
        self.table = table

    def find_spec(self, fullname, path=None, target=None):
        if fullname not in self.table:
            need(not fullname.startswith('B_OWNER_RECOVERY_R25_WIRING.'), 'unknown_protected_package_submodule')
            return None
        p, h, pkg, meta = self.table[fullname]
        spec = importlib.util.spec_from_loader(fullname, Loader(p, h, meta), origin=p, is_package=pkg)
        if pkg:
            spec.submodule_search_locations = [str(Path(p).parent)]
        return spec

def main():
    need(type(POLICY) is dict and os.getuid() == os.geteuid() == 0 and (sys.platform == 'linux'), 'A_fixed_cold_bootstrap_pending')
    p = POLICY
    root = p['stage']
    table = {}
    for name, pin in p['files'].items():
        rel = Path(name)
        need(not rel.is_absolute() and '..' not in rel.parts, 'fixed_A_relative_source')
        raw, st = held(root + '/' + name, pin, cap=2097152)
        if name.endswith('.py'):
            mod = name[:-3].replace('/', '.')
            need(mod not in sys.modules, 'no_ambient_A_module')
            table[mod] = (root + '/' + name, pin, False, st)
    finder = Finder(table)
    sys.meta_path.insert(0, finder)
    raw, st = held(root + '/root_agent.py', p['agent_sha256'])
    exec(compile(raw, root + '/root_agent.py', 'exec'), {'__name__': '__main__', '__file__': root + '/root_agent.py'})
if __name__ == '__main__':
    main()
