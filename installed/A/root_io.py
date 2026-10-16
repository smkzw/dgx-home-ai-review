# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Root held source/tool/proof originals. No pathname from private requests."""
import hashlib
import os
import stat
from pathlib import Path
from plan import need
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def f9(s):
    return [getattr(s, k) for k in FIELDS]

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

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

def fresh(path, raw, mode=384):
    path = Path(path)
    need(type(raw) is bytes and len(raw) <= 4 * 1024 ** 2, 'bounded_Root_receipt')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        n = 0
        while n < len(raw):
            n += os.write(fd, raw[n:])
        os.fsync(fd)
    finally:
        os.close(fd)
    d = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(d)
    finally:
        os.close(d)
