# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed held Root publication and sole-service consumer; no public callbacks."""
import os, stat, time
from pathlib import Path
import plan, entry_clock
from root_io import held, sha
from observer import positive
from B_OWNER_RECOVERY_R25_WIRING.common import HeldParent, metadata
ROOT = Path(plan.PC_STAGE) / 'entry-clock'
NONCE = 'e21f830185b7e1ffbd0ca049a040b4a2'

def read(path):
    return held(path, cap=2097152)

def write(path, raw, *, mode, gid):
    plan.need(path.parent == ROOT / NONCE and path.name in ('send.json', 'send-moment.json', 'response.json', 'received.json') and (type(raw) is bytes) and (len(raw) <= 2097152) and (mode == 288) and (gid == 989), 'fixed_clock_four_leaves_only')
    with HeldParent(path) as chain:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=chain.parent_fd)
        try:
            os.fchown(fd, 0, gid)
            os.fchmod(fd, mode)
            view = memoryview(raw)
            while view:
                n = os.write(fd, view)
                plan.need(n > 0, 'whole_clock_original_write')
                view = view[n:]
            os.fsync(fd)
            actual = metadata(os.fstat(fd))
            plan.need(actual == metadata(chain.named_leaf()), 'clock_held_named_leaf_before_close')
        finally:
            os.close(fd)
        os.fsync(chain.parent_fd)
        chain.recheck()
    actual, s = read(path)
    plan.need(actual == raw and s[3:7] == [0, gid, 32768 | mode, 1], 'actual_Root_clock_full_write_readback')

def directory(path, create=False):
    plan.need(path in (ROOT, ROOT / NONCE), 'only_two_fixed_clock_directories')
    with HeldParent(path) as chain:
        if create:
            os.mkdir(path.name, 488, dir_fd=chain.parent_fd)
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain.parent_fd)
        try:
            if create:
                os.fchown(fd, 0, 989)
                os.fchmod(fd, 488)
                os.fsync(fd)
            z = os.fstat(fd)
            named = chain.named_leaf()
            plan.need((z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode) == (named.st_dev, named.st_ino, named.st_uid, named.st_gid, named.st_mode) and (z.st_uid, z.st_gid, stat.S_IMODE(z.st_mode)) == (0, 989, 488), 'actual_shared_Root_clock_directory')
        finally:
            os.close(fd)
        os.fsync(chain.parent_fd)
        chain.recheck()

def resource(v):
    r = v['result']
    plan.validate_nvme_identity(r['NVMe_identity'])
    plan.need(r['payload_namespace_absent'] is True and r['daemon_started'] is False and (r['models_started'] == 0) and (r['MemAvailable_bytes'] >= 8 * 1024 ** 3) and (r['NVMe_free_bytes'] >= plan.WORKSPACE + plan.RESERVE), 'actual_readonly_resource_source_ready_not_GPU')

def begin(config, identity):
    plan.need(os.getuid() == os.geteuid() == 0 and NONCE is not None, 'fixed_Root_entry_clock_nonce_pending')
    directory(ROOT, create=True)
    directory(ROOT / NONCE, create=True)
    return entry_clock.begin(write, read, ROOT / NONCE, config, identity, NONCE)

def finish(config, identity, response_raw):
    plan.need(os.getuid() == os.geteuid() == 0 and NONCE is not None, 'Root_clock_finish_only')
    directory(ROOT)
    directory(ROOT / NONCE)
    response = entry_clock.strict(response_raw)
    raw = entry_clock.decode(response['entry_raw_b64'])
    resource(entry_clock.strict(raw))
    return entry_clock.finish(read, write, ROOT / NONCE, response_raw, config, identity, positive=positive)

def consume(config, identity, now):
    plan.need(NONCE is not None, 'new_entry_clock_SOURCE_pending')
    directory(ROOT)
    directory(ROOT / NONCE)
    return entry_clock.consume(read, ROOT / NONCE, config, identity, now, positive=positive, validate_resources=resource)['entry_original']
