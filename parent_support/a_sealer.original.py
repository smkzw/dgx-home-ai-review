# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Last fixed source Root sealer. No authority comes from argv/env/bundle bool."""
import base64, json, os, platform, stat
from pathlib import Path
import hashlib
APPROVED_BUNDLE_SHA = None
OPERATION = None
BUNDLE = Path('/home/REDACTED_USER/dgx-r26-A-source-bundle.json')
STAGE = Path('/opt/dgx-v4/mimo-registry-native-r26')

def need(v, c):
    if not v:
        raise RuntimeError(c)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def stage(files, root=STAGE):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    holds = [fd]
    links = []
    try:
        for name in root.parts[1:-1]:
            nxt = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            z = os.fstat(nxt)
            need(stat.S_ISDIR(z.st_mode) and z.st_uid == 0 and (not z.st_mode & 18), 'immutable_Root_stage_parent')
            links.append((fd, name, (z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode)))
            holds.append(nxt)
            fd = nxt
        os.mkdir(root.name, 448, dir_fd=fd)
        parent = fd
        fd = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 448)
        holds.append(fd)
        z = os.fstat(fd)
        identity = (z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode)
        links.append((parent, root.name, identity))
        dirs = {(): fd}
        for name, raw in files.items():
            p = Path(name)
            need(type(name) is str and p.as_posix() == name and (not p.is_absolute()) and p.parts and ('..' not in p.parts) and (len(raw) <= 2097152), 'fixed_relative_source_leaf')
            current = fd
            parts = ()
            for part in p.parts[:-1]:
                parts += (part,)
                if parts not in dirs:
                    os.mkdir(part, 448, dir_fd=current)
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
                    os.fchown(child, 0, 0)
                    os.fchmod(child, 448)
                    os.fsync(current)
                    dirs[parts] = child
                    holds.append(child)
                    cz = os.fstat(child)
                    links.append((current, part, (cz.st_dev, cz.st_ino, cz.st_uid, cz.st_gid, cz.st_mode)))
                current = dirs[parts]
            leaf = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=current)
            try:
                os.fchown(leaf, 0, 0)
                os.fchmod(leaf, 384)
                v = memoryview(raw)
                while v:
                    n = os.write(leaf, v)
                    need(n > 0, 'whole_source_write')
                    v = v[n:]
                os.fsync(leaf)
            finally:
                os.close(leaf)
            os.fsync(current)
        for parentfd, name, expected in links:
            z = os.stat(name, dir_fd=parentfd, follow_symlinks=False)
            need((z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode) == expected, 'all_held_named_parent_links_after_write')
        now = os.stat(root.name, dir_fd=parent, follow_symlinks=False)
        need((now.st_dev, now.st_ino, now.st_uid, now.st_gid, now.st_mode) == identity, 'held_stage_named_root_after_write')
        os.fsync(parent)
    finally:
        for f in reversed(holds):
            os.close(f)

def main():
    need(APPROVED_BUNDLE_SHA is not None, 'SOURCE_sealer_None')
    need(os.getuid() == os.geteuid() == 0 and platform.node() == 'spark-a321' and (os.sys.platform == 'linux'), 'fixed_Root_A')
    fd = os.open(BUNDLE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        z = os.fstat(fd)
        need(stat.S_ISREG(z.st_mode) and z.st_uid == 1000 and (stat.S_IMODE(z.st_mode) == 384) and (z.st_nlink == 1) and (z.st_size <= 8 * 1024 ** 2), 'ordinary_user_exact_source_bundle')
        raw = os.pread(fd, z.st_size + 1, 0)
        need(sha(raw) == APPROVED_BUNDLE_SHA and len(raw) == z.st_size, 'literal_whole_source_bundle')
        keys = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        need(all((getattr(z, k) == getattr(os.fstat(fd), k) == getattr(BUNDLE.lstat(), k) for k in keys)), 'source_bundle_F9_stable')
    finally:
        os.close(fd)
    v = json.loads(raw)
    need(OPERATION is not None and v['operation'] == OPERATION and (set(v) == {'operation', 'files', 'pins'}), 'fixed_bundle_scope')
    files = {k: base64.b64decode(b, validate=True) for k, b in v['files'].items()}
    need(sum(map(len, files.values())) <= 4 * 1024 ** 2 and set(files) == set(v['pins']) and all((sha(files[k]) == v['pins'][k] for k in files)), 'all_final_source_closed')
    stage(files)
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
