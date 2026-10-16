# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
from __future__ import annotations
import hashlib, json, math, os, stat
from pathlib import Path
C_ACCEPTANCE_PATH = Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d/C-parent-acceptance.json')
SERVICE_ANCESTORS = {Path('/srv/dgx-home-ai/runtime/hx-service-state'): 999, Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d'): 999}

class Refused(RuntimeError):
    pass

def need(value, reason):
    if not value:
        raise Refused(reason)

def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def metadata(s):
    return [getattr(s, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')]

def strict(raw):

    def pairs(xs):
        d = {}
        for k, v in xs:
            need(k not in d, 'duplicate_key')
            d[k] = v
        return d

    def constant(x):
        raise Refused('nonfinite_json')
    v = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    encode(v)
    return v
LEGACY_DIRECTORY_PINS = None
DIRECTORY_IDENTITY = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode')

def directory_identity(s):
    return tuple((getattr(s, k) for k in DIRECTORY_IDENTITY))

def directory_policy(path, s, *, legacy):
    need(stat.S_ISDIR(s.st_mode), 'directory_not_real')
    if legacy and str(path) in LEGACY_DIRECTORY_PINS:
        need(directory_identity(s) == LEGACY_DIRECTORY_PINS[str(path)], 'exact_legacy_directory_binding')
    elif legacy and str(path) == '/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d':
        need((s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (999, 989, 448), 'exact_new_operator_directory')
    else:
        need(s.st_uid == 0 and (not s.st_mode & 18), 'Root_directory_boundary')

class HeldParent:
    """Held NOFOLLOW component chain with exact named/FD identities at exit.

 Directory entry times/size may change as a service writes or installer creates
 its fixed child. Identity/owner/mode cannot change. Root file bytes/F9 retain
 their independent strict check. This is no immutable-ancestor claim.
 """

    def __init__(self, path, *, legacy=False):
        self.path = Path(path)
        self.legacy = legacy
        self.chain = []

    def __enter__(self):
        need(self.path.is_absolute() and '..' not in self.path.parts, 'fixed_absolute_path')
        try:
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.chain.append((Path('/'), fd, None, None, directory_identity(os.fstat(fd))))
            directory_policy(Path('/'), os.fstat(fd), legacy=self.legacy)
            current = Path('/')
            for component in self.path.parent.parts[1:]:
                parentfd = fd
                current = current / component
                before = os.stat(component, dir_fd=parentfd, follow_symlinks=False)
                directory_policy(current, before, legacy=self.legacy)
                fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
                ident = directory_identity(before)
                self.chain.append((current, fd, parentfd, component, ident))
                need(ident == directory_identity(os.fstat(fd)), 'directory_changed_at_open')
            self.parent_fd = fd
            self.recheck()
            return self
        except BaseException:
            self.close()
            raise

    def recheck(self):
        for path, fd, parentfd, name, ident in self.chain:
            held = os.fstat(fd)
            named = path.lstat() if parentfd is None else os.stat(name, dir_fd=parentfd, follow_symlinks=False)
            need(directory_identity(held) == directory_identity(named) == ident == directory_identity(path.lstat()), 'held_directory_chain_changed')
            directory_policy(path, held, legacy=self.legacy)

    def open_leaf(self):
        return os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.parent_fd)

    def named_leaf(self):
        return os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)

    def close(self):
        for _, fd, _, _, _ in reversed(self.chain):
            os.close(fd)
        self.chain = []

    def __exit__(self, *_):
        try:
            self.recheck()
        finally:
            self.close()

def protected_read(path, *, owner=0, limit=1048576):
    path = Path(path)
    with HeldParent(path, legacy=path == C_ACCEPTANCE_PATH) as chain:
        fd = chain.open_leaf()
        try:
            a = os.fstat(fd)
            need(stat.S_ISREG(a.st_mode) and a.st_uid == owner and (a.st_nlink == 1) and (not a.st_mode & 18) and (a.st_size <= limit), 'protected_file')
            chunks = bytearray()
            while len(chunks) <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            need(len(chunks) == a.st_size and metadata(a) == metadata(os.fstat(fd)) == metadata(chain.named_leaf()), 'protected_file_changed')
            chain.recheck()
            return (bytes(chunks), metadata(a))
        finally:
            os.close(fd)

def exclusive(path, value):
    raw = encode(value)
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
    try:
        os.fchmod(fd, 384)
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(d)
    finally:
        os.close(d)
    return sha(raw)

def fresh(stamp, now, age):
    need(type(stamp) in (float, int) and math.isfinite(stamp) and (0 <= now - stamp <= age), 'fresh_original_timestamp')
