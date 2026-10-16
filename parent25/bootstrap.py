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
            need(not fullname.startswith(('B_OWNER_RECOVERY_R25_WIRING.', 'node_adapter.', 'control_plane.')) and fullname not in ('node_adapter', 'control_plane'), 'unknown_protected_package_submodule')
            return None
        p, h, pkg, meta = self.table[fullname]
        spec = importlib.util.spec_from_loader(fullname, Loader(p, h, meta), origin=p, is_package=pkg)
        if pkg:
            spec.submodule_search_locations = [str(Path(p).parent)]
        return spec

def main(mode='rpc'):
    need(mode in ('rpc', 'current-only'), 'fixed_bootstrap_entry_mode')
    need(type(POLICY) is dict and os.getuid() == os.geteuid() == 0 and (sys.platform == 'linux'), 'PC_cold_bootstrap_SOURCE_pending')
    p = POLICY
    root = p['PC_ROOT']
    cfg = strict(held(p['config_path'], p['config_sha256'], p['config_stat'])[0])
    pins = cfg['PC_source_pins']
    need(type(pins) is dict and len(pins) == 118 and (cfg['review_sha256'] == p['review_sha256']), 'actual_current118_config')
    index = strict(held(root + '/epoch-index.json', p['index_sha256'], p['index_stat'])[0])
    need(index['review_sha256'] == p['review_sha256'] and index['operation'] == p['operation'] and (type(p['index_count']) is int) and (1 <= p['index_count'] <= 128) and (len(index['files']) == p['index_count']) and (index['files']['parent-root-rpc.py'] == p['RPC_sha256']), 'actual_exact_reviewed_Root_index')
    sources = {}
    for name, pin in dict(index['files'], **p['extra_sources']).items():
        rel = Path(name)
        need(not rel.is_absolute() and '..' not in rel.parts, 'only_closed_source_relative_leaf')
        _, meta = held(root + '/' + name, pin)
        sources[root + '/' + name] = (pin, meta)
    for path, row in p['package'].items():
        need(pins[path] == row['sha256'], 'same_current118_package')
        _, meta = held(path, row['sha256'], row['stat'])
        sources[path] = (row['sha256'], meta)
    for rel in ('node_adapter/__init__.py', 'node_adapter/protocol.py', 'control_plane/__init__.py', 'control_plane/errors.py', 'node_adapter/client.py'):
        path = '/opt/dgx-v4/hx/runtime/' + rel
        need(path in pins, 'complete_external_current118_closure')
        _, meta = held(path, pins[path])
        sources[path] = (pins[path], meta)
    table = {}
    for path, (pin, meta) in sources.items():
        if not path.endswith('.py'):
            continue
        if path.startswith(root + '/service/'):
            name = path[len(root + '/service/'):-3]
            pkg = False
        elif path.startswith(('/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/', '/opt/dgx-v4/hx/runtime/node_adapter/', '/opt/dgx-v4/hx/runtime/control_plane/')):
            rel = path[len('/opt/dgx-v4/hx/runtime/'):]
            pkg = rel.endswith('/__init__.py')
            name = rel[:-12].replace('/', '.') if pkg else rel[:-3].replace('/', '.')
        else:
            continue
        need(name not in sys.modules, 'no_unverified_ambient_source_module')
        table[name] = (path, pin, pkg, meta)
    finder = Finder(table)
    sys.meta_path.insert(0, finder)
    sys.path.insert(0, '/opt/dgx-v4/hx/runtime')
    for name in ('B_OWNER_RECOVERY_R25_WIRING.common', 'B_OWNER_RECOVERY_R25_WIRING.collector', 'control_plane.errors', 'node_adapter.protocol', 'node_adapter.client'):
        __import__(name, fromlist=('*',))
    raw, _ = held(root + '/parent-root-rpc.py', p['RPC_sha256'], sources[root + '/parent-root-rpc.py'][1])
    ns = {'__name__': '__main__' if mode == 'rpc' else '_fixed_readonly_current', '__file__': root + '/parent-root-rpc.py'}
    exec(compile(raw, root + '/parent-root-rpc.py', 'exec'), ns)
    if mode == 'current-only':
        cfg, identity = ns['current']()
        return {'schema': 'R11-R3-parent-pure-current/v1', 'manager_identity': identity, 'config_sha256': cfg['_config_sha256'], 'review_sha256': cfg['review_sha256'], 'current_source118': cfg['PC_source_pins'], 'RPC_source_sha256': p['RPC_sha256'], 'requests_sent': 0, 'controls': 0}
if __name__ == '__main__':
    main()
