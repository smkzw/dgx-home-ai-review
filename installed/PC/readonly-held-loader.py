# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Held complete stdlib-only closure. No ambient application imports."""
import builtins, hashlib, json, os, stat, sys, types
from pathlib import Path
F9 = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def need(v, r):
    if not v:
        raise RuntimeError(r)

def sha(b):
    return hashlib.sha256(b).hexdigest()
FIELDS = F9

def f9(s):
    return [getattr(s, k) for k in FIELDS]

def held(path, pin=None, cap=4 * 1024 ** 2, mode=None, *, stat_only=False):
    path = Path(path)
    directories = []
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directories.append((fd, f9(os.fstat(fd)), None, None))
    leaf = None
    try:
        for part in path.parts[1:-1]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            s = os.fstat(new)
            need(s.st_uid == 0 and (not s.st_mode & 18) and stat.S_ISDIR(s.st_mode), 'Root_ancestor_actual_identity')
            directories.append((new, f9(s), fd, part))
            fd = new
        leaf = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        before = os.fstat(leaf)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and (before.st_nlink == 1) and (not before.st_mode & 18) and (stat_only or before.st_size <= cap) and (mode is None or stat.S_IMODE(before.st_mode) == mode), 'Root_held_leaf')
        need(not stat_only or pin is None, 'stat_only_must_not_claim_content_SHA')
        raw = b'' if stat_only else os.pread(leaf, before.st_size + 1, 0)
        need((stat_only or len(raw) == before.st_size) and f9(before) == f9(os.fstat(leaf)) == f9(os.stat(path.name, dir_fd=fd, follow_symlinks=False)) and (pin is None or sha(raw) == pin), 'Root_leaf_fullSHA_F9_stable')
        for d, before_dir, parent, name in directories:
            current = f9(os.fstat(d))
            need([current[i] for i in (0, 1, 3, 4, 5)] == [before_dir[i] for i in (0, 1, 3, 4, 5)], 'Root_ancestor_held_recheck')
            if parent is not None:
                named = f9(os.stat(name, dir_fd=parent, follow_symlinks=False))
                need([named[i] for i in (0, 1, 3, 4, 5)] == [before_dir[i] for i in (0, 1, 3, 4, 5)], 'Root_ancestor_named_held_binding')
        return (raw, f9(before))
    finally:
        if leaf is not None:
            os.close(leaf)
        for d, *_ in reversed(directories):
            os.close(d)

def read(path, pin=None, cap=4194304):
    return held(path, pin, cap=cap)

def load(root, spec_sha):
    root = Path(root)
    raw, _ = read(root / 'spec.json', spec_sha)
    spec = json.loads(raw)
    need(spec['schema'] == 'asset-zero-readonly-spec/v1' and spec['role'] in ('A', 'PC'), 'zero_spec_type')
    mods = {}
    sources = spec['sources']
    need(type(sources) is dict and spec['mode'] in ('historical-fixed', 'current-stage-prebind', 'failed-empty-range-repair'), 'zero_fixed_closed_source_table')
    for row in sources.values():
        need(type(row) is dict and set(row) == {'file', 'sha256'} and (type(row['file']) is str) and (row['file'] not in ('', '.', '..')) and ('/' not in row['file']), 'zero_flat_fixed_dependency_leaf')

    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name in sources:
            return module(name)
        if not level and name.split('.')[0] in sys.stdlib_module_names:
            return builtins.__import__(name, globals, locals, fromlist, level)
        raise ImportError('unheld_zero_dependency:' + name)

    def module(name):
        if name in mods:
            return mods[name]
        row = sources[name]
        p = root / 'src' / row['file']
        body, _ = read(p, row['sha256'])
        m = types.ModuleType(name)
        m.__file__ = str(p)
        m.__package__ = name.rpartition('.')[0]
        m.__dict__['__builtins__'] = dict(vars(builtins), __import__=importer)
        mods[name] = m
        exec(compile(body, str(p), 'exec'), m.__dict__)
        for k, v in spec['bindings'].get(name, {}).items():
            need(k in m.__dict__, 'zero_known_literal_binding')
            m.__dict__[k] = Path(v) if name == 'zero_negative' and k == 'ROOT' else v
        return m
    return types.SimpleNamespace(root=root, spec=spec, module=module, modules=mods, read=read, sha=sha, need=need)
