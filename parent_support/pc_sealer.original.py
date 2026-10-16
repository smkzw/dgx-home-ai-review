# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Last literal Root source sealer. Default inert; exact OWN new tree only."""
import base64, os, platform, stat
from pathlib import Path
import hashlib, json
PC_ROOT = Path('/opt/dgx-v4/hx/mimo-registry-native-r26-cpath-r11-r3')
HISTORY_ROOT = Path('/opt/dgx-v4/hx/mimo-registry-native-r26-history')

class Refused(RuntimeError):
    pass

def need(value, code):
    if not value:
        raise Refused(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):

    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, 'duplicate_key')
            out[k] = v
        return out
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite'))

def protected_read(path, limit=2097152):
    for p in Path(path).parents:
        z = p.lstat()
        need(stat.S_ISDIR(z.st_mode) and z.st_uid == 0 and (not z.st_mode & 18), 'Root_ancestor_boundary')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        z = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        need(stat.S_ISREG(z.st_mode) and z.st_uid == 0 and (z.st_nlink == 1) and (not z.st_mode & 18) and (z.st_size <= limit), 'Root_held_source_leaf')
        raw = os.pread(fd, z.st_size + 1, 0)
        need(len(raw) == z.st_size and all((getattr(z, k) == getattr(os.fstat(fd), k) == getattr(Path(path).lstat(), k) for k in keys)), 'Root_source_F9_stable')
        return (raw, [getattr(z, k) for k in keys])
    finally:
        os.close(fd)

class IO:

    @staticmethod
    def fresh(path, raw, mode=288, gid=989):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        try:
            os.fchown(fd, 0, gid)
            os.fchmod(fd, mode)
            view = memoryview(raw)
            while view:
                n = os.write(fd, view)
                need(n > 0, 'whole_fresh_write')
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        parent = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
io = IO()
APPROVED_BUNDLE_SHA = None
APPROVED_REVIEW = None
BUNDLE = Path('/home/REDACTED_USER/dgx-r26-registry-source-bundle.json')
ROLE = None

def directory(fd, owned):
    z = os.fstat(fd)
    need(stat.S_ISDIR(z.st_mode) and z.st_uid == 0 and (not z.st_mode & 18), 'Root_held_directory')
    if owned:
        need(z.st_gid == 989 and stat.S_IMODE(z.st_mode) == 488, 'exact_source_directory_mode')
    return (z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode)

def stage(files, source_root, role, allow_inherited=True, create_root=False):
    need(role in ('history', 'epoch') and source_root.is_absolute(), 'fixed_stage_role')
    holds = []

    def child(parent, name, owned, create=False):
        if create:
            os.mkdir(name, mode=488, dir_fd=parent)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        if create:
            os.fchown(fd, 0, 989)
            os.fchmod(fd, 488)
            os.fsync(fd)
            os.fsync(parent)
        ident = directory(fd, owned)
        holds.append((parent, name, fd, ident))
        return fd
    rootfd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    holds.append((None, None, rootfd, directory(rootfd, False)))
    try:
        parent = rootfd
        for name in source_root.parts[1:-1]:
            parent = child(parent, name, False)
        name = source_root.name
        if role == 'history':
            os.mkdir(name, mode=488, dir_fd=parent)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.fchown(fd, 0, 989)
            os.fchmod(fd, 488)
            os.fsync(fd)
            os.fsync(parent)
            holds.append((parent, name, fd, directory(fd, True)))
            sourcefd = fd
        else:
            sourcefd = child(parent, name, True, create=create_root)
        directories = {(): sourcefd}
        for relative, body in files.items():
            path = Path(relative)
            need(type(relative) is str and relative == path.as_posix() and (not path.is_absolute()) and path.parts and all((n not in ('.', '..') for n in path.parts)) and (len(body) <= 2097152), 'fixed_relative_source_leaf')
            parent = sourcefd
            parts = ()
            for name in path.parts[:-1]:
                parts += (name,)
                if parts not in directories:
                    try:
                        os.stat(name, dir_fd=parent, follow_symlinks=False)
                        exists = True
                    except FileNotFoundError:
                        exists = False
                    directories[parts] = child(parent, name, True, create=not exists)
                parent = directories[parts]
            name = path.name
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 288, dir_fd=parent)
            except FileExistsError:
                need(allow_inherited, 'sealed_marker_replay_denied')
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    z = os.fstat(fd)
                    need(stat.S_ISREG(z.st_mode) and (z.st_uid, z.st_gid, stat.S_IMODE(z.st_mode), z.st_nlink) == (0, 989, 288, 1), 'exact_inherited_leaf_identity')
                    need(z.st_size == len(body) and os.pread(fd, z.st_size + 1, 0) == body, 'inherited_source_no_overwrite')
                    keys = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
                    after = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    need(all((getattr(z, k) == getattr(os.fstat(fd), k) == getattr(after, k) for k in keys)), 'held_leaf_stable')
                finally:
                    os.close(fd)
            else:
                try:
                    os.fchown(fd, 0, 989)
                    os.fchmod(fd, 288)
                    view = memoryview(body)
                    while view:
                        n = os.write(fd, view)
                        need(n > 0, 'whole_fresh_write')
                        view = view[n:]
                    os.fsync(fd)
                    z = os.fstat(fd)
                    after = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    need((z.st_dev, z.st_ino) == (after.st_dev, after.st_ino) and z.st_size == len(body), 'published_owned_leaf_identity')
                finally:
                    os.close(fd)
                os.fsync(parent)
        for parent, name, fd, ident in holds:
            need(directory(fd, parent is not None and (fd == sourcefd or fd in directories.values())) == ident, 'held_directory_mutated')
            if parent is not None:
                z = os.stat(name, dir_fd=parent, follow_symlinks=False)
                need((z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode) == ident, 'held_parent_path_mutated')
    finally:
        for _, _, fd, _ in reversed(holds):
            os.close(fd)

def publish_packed_history_origin(root, files):
    import types
    name = 'service/receipt_codec.py'
    raw, st = protected_read(root / name)
    need(raw == files[name], 'sealed_history_codec_exact_final_source')
    codec = types.ModuleType('fixed_new_history_codec')
    exec(compile(raw, str(root / name), 'exec'), codec.__dict__)
    names = ('not-launched-A-MAC-history.compact.json', 'not-launched-PC-MAC-history.compact.json')
    rows = {}
    held = {}
    for name in names:
        body, f9 = protected_read(root / name)
        need(body == files[name] and f9[3:7] == [0, 989, 33056, 1], 'sealed_packed_history_actual_F9')
        decoded = codec.unpack(strict(body))
        rows[name] = {'packed_sha256': sha(body), 'raw_sha256': sha(decoded), 'F9': f9}
        held[name] = (body, f9)
    receipt = encode({'schema': 'stage-not-launched-packed-history-origin/v1', 'source_review_sha256': APPROVED_REVIEW, 'files': rows})
    io.fresh(root / 'not-launched-histories-origin.json', receipt)
    need(protected_read(root / 'not-launched-histories-origin.json')[0] == receipt and all((protected_read(root / name) == value for name, value in held.items())), 'sealed_packed_history_origin_complete_readback')

def main():
    need(APPROVED_BUNDLE_SHA is not None and APPROVED_REVIEW is not None and (ROLE in ('history', 'epoch')), 'SOURCE_seal_default_None')
    need(os.getuid() == os.geteuid() == 0 and platform.node() == 'vicky' and (os.sys.platform == 'linux'), 'fixed_Root_PC_source_seal')
    fd = os.open(BUNDLE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 1000 and (stat.S_IMODE(s.st_mode) == 384) and (s.st_nlink == 1) and (s.st_size <= 8 * 1024 ** 2), 'ordinary_source_bundle_identity')
        raw = os.pread(fd, s.st_size + 1, 0)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) == s.st_size and sha(raw) == APPROVED_BUNDLE_SHA and all((getattr(s, k) == getattr(os.fstat(fd), k) == getattr(BUNDLE.lstat(), k) for k in fields)), 'literal_bundle_held_stable')
    finally:
        os.close(fd)
    p = strict(raw)
    need(p['review_sha256'] == APPROVED_REVIEW and p['role'] == ROLE and (set(p) == {'review_sha256', 'role', 'files', 'index'}), 'fixed_review_bundle_schema')
    files = {k: base64.b64decode(v, validate=True) for k, v in p['files'].items()}
    need(sum(map(len, files.values())) <= 4 * 1024 ** 2, 'finite_stage_source_size')
    expected = p['index']
    need(set(expected['files']) <= set(files) and set(files) == set(expected['files']) | {ROLE + '-index.json', ROLE + '-launch.py', ROLE + '-finalize-stop.py', 'renewal-launch.py', 'renewal-finalize-stop.py'}, 'exact_final_stage_index_set')
    need(expected['review_sha256'] == APPROVED_REVIEW and expected['role'] == ROLE and all((sha(files[k]) == v for k, v in expected['files'].items())), 'every_final_leaf_in_index')
    source_root = HISTORY_ROOT if ROLE == 'history' else PC_ROOT
    stage(files, source_root, ROLE, create_root=True)
    if ROLE == 'epoch':
        publish_packed_history_origin(source_root, files)
    seal = encode({'role': ROLE, 'review_sha256': APPROVED_REVIEW, 'bundle_sha256': sha(raw), 'index': expected, 'observed_at': __import__('time').time(), 'model_commands': 0})
    stage({ROLE + '-sealed-source.json': seal}, source_root, 'epoch', allow_inherited=False)
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
