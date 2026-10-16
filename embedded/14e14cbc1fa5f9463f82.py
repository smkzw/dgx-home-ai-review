# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import base64, hashlib, json, os, platform, stat, sys
from pathlib import Path
APPROVED_BUNDLE = None
APPROVED_ROLE = None
APPROVED_REVIEW_SHA = None
ROOTS = {'c': '/opt/dgx-v4/runtime/g8-clock-probe-c30-mimo-registry-r16'}

def sha(v):
    return hashlib.sha256(v).hexdigest()

def seal():
    if APPROVED_BUNDLE is None:
        return {'status': 'SOURCE_inert', 'native_actions': 0}
    if os.geteuid() != 0 or os.getuid() != 0 or sys.platform != 'linux' or (APPROVED_ROLE not in ROOTS) or (platform.node() != ('vicky' if APPROVED_ROLE == 'pc' else 'gx10-753c')):
        raise RuntimeError('fixed_Root_host')
    root = Path(ROOTS[APPROVED_ROLE])
    raws = {n: base64.b64decode(v, validate=True) for n, v in APPROVED_BUNDLE.items()}
    if root.exists() or root.is_symlink() or sum(map(len, raws.values())) > 2097152:
        raise RuntimeError('new_bounded_namespace_absent')
    for p in root.parents:
        st = p.lstat()
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 18:
            raise RuntimeError('protected_Root_parent')
    root.mkdir(mode=448)
    try:
        for n, raw in raws.items():
            if Path(n).name != n:
                raise RuntimeError('fixed_leaf_only')
            fd = os.open(root / n, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
            try:
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 384)
                view = memoryview(raw)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise RuntimeError('partial_write')
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        for n, raw in raws.items():
            st = (root / n).lstat()
            if (root / n).read_bytes() != raw or st.st_uid != 0 or st.st_gid != 0 or (stat.S_IMODE(st.st_mode) != 384) or (st.st_nlink != 1):
                raise RuntimeError('sealed_readback')
        return {'schema': 'g8-C-R25-Root-readonly-source-sealed/v1', 'root': str(root), 'source_review_sha256': APPROVED_REVIEW_SHA, 'files': {n: sha(v) for n, v in raws.items()}, 'launch_calls': 0, 'ARM_model_POST': 0}
    except BaseException:
        raise
if __name__ == '__main__':
    print(json.dumps(seal()))
