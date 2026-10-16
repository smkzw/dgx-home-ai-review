# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Source-inert fixed parent entry. Held local 0600 nonsecret data/whole index."""
import os, stat, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import plan
from root_io import sha
APPROVED_PARENT_INDEX_SHA = 'dfb76be142e58d73f3cc9d89e94327506c237d8bb1fbc7987a52188289fb97e1'

def local(path, pin=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        a = os.fstat(fd)
        plan.need(stat.S_ISREG(a.st_mode) and a.st_uid == os.getuid() and (stat.S_IMODE(a.st_mode) == 384) and (a.st_nlink == 1) and (a.st_size <= 4194304), 'private_parent_SOURCE_or_nonsecret_data')
        b = os.pread(fd, a.st_size + 1, 0)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        z = Path(path).lstat()
        plan.need(len(b) == a.st_size and all((getattr(a, k) == getattr(os.fstat(fd), k) == getattr(z, k) for k in fields)) and (pin is None or sha(b) == pin), 'actual_private_parent_fullSHA_F9')
        return b
    finally:
        os.close(fd)

def main():
    plan.need(APPROVED_PARENT_INDEX_SHA is not None, 'parent_entry_SOURCE_None')
    root = Path(__file__).resolve().parent
    v = plan.strict(local(root / 'parent-final-index.json', APPROVED_PARENT_INDEX_SHA))
    plan.need(v['schema'] == 'registry-R26-parent-final-index/v1' and v['operation'] == plan.OPERATION, 'fixed_parent_final_scope')
    for n, pin in v['files'].items():
        plan.need(Path(n).name == n, 'only_fixed_parent_leaf')
        local(root / n, pin)
    c = plan.strict(local(root / 'runtime-context.json'))
    plan.need(c['operation'] == plan.OPERATION and c['source_release_sha256'] == v['review_sha256'] and (c['current_epoch_raw_sha256'] == c['actual_current_epoch_qualified_sha256']) and (c['historical_ancestor_sha256'] == c['actual_ancestor_qualified_sha256']), 'late_actual_qualified_bindings')
    from parent_io import IO
    from segment_parent import run
    plan.need(0 < c['remaining_seconds'] <= 1800, 'bounded_parent_whole_not_reset')
    end = time.monotonic() + c['remaining_seconds']
    io = IO(end)
    try:
        return run(io, io.window, c, root / 'asset-stage-once')
    finally:
        io.close_transport()
if __name__ == '__main__':
    main()
