# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fixed Root stage source/context loader; no external callbacks or code."""
import os, re, platform, time
from pathlib import Path
import plan
from stage_naming import unit as readiness_unit
from root_io import held, sha
APPROVED = {'index_sha256': '6bd34702b74fd9cf6af1764da5a75e520b63fd7c924be424257cc59e1691ca32', 'review_sha256': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'}
BASE_DATA = '/var/lib/dgx-v4/mimo-registry-native-r26-role-r14'

def configure(stage, *, readonly=False):
    plan.need(APPROVED is not None and BASE_DATA is not None and re.fullmatch('[0-9a-f]{32}', stage) and (stage != plan.OPERATION), 'stage_runtime_SOURCE_pending')
    control = Path(plan.STAGE) / 'stages' / stage
    root = Path(BASE_DATA) / 'stages' / stage
    plan.UNIT = 'dgx-v4-image-segment-' + stage + '.service'
    plan.CG = '/system.slice/' + plan.UNIT
    plan.ROOT = str(Path(BASE_DATA) if readonly else root / 'range')
    plan.SOCKET = str(Path(BASE_DATA) / 'sockets' / (stage + '.sock'))
    plan.need(len(plan.SOCKET.encode()) < 108, 'fixed_stage_UNIX_socket_path_cap')
    plan.ENTRY_UNIT = readiness_unit(stage)
    plan.ENTRY_STATE = str(control / 'readiness')
    plan.STAGE_ENTRY_CONTEXT = str(control / 'entry-context.json')
    plan.STAGE_CONTROL = str(control)
    return (control, root)

def context(stage, *, admit=True):
    plan.need(os.getuid() == os.geteuid() == 0 and platform.node() == 'spark-a321' and (__import__('sys').platform == 'linux'), 'fixed_A_stage_Root')
    control, root = configure(stage)
    indexraw, st = held(Path(plan.STAGE) / 'source-index.json', APPROVED['index_sha256'], mode=384)
    ix = plan.strict(indexraw)
    for n, pin in ix['files'].items():
        held(Path(plan.STAGE) / n, pin, mode=384)
    raw, st = held(control / 'context.json', mode=384)
    c = plan.strict(raw)
    rawplan, ps = held(control / 'plan.json', mode=384)
    p = plan.strict(rawplan)
    plan.need(c['stage_operation'] == p['stage_operation'] == stage and c['operation'] == p['operation_family'] == plan.OPERATION and (c['source_release_sha256'] == p['review_sha256'] == APPROVED['review_sha256']) and (c['owned_aggregate_unit'] == plan.UNIT) and (c['owned_aggregate_cgroup'] == plan.CG) and (c['context_producer_sha256'] == sha(held(Path(plan.STAGE) / 'root_agent.py')[0])) and (c['plan_sha256'] == sha(rawplan)), 'actual_bound_stage_context_source_plan')
    from qualification import parent_preflight
    proof, pr = held(control / 'parent-proof.json', c['parent_proof_sha256'], mode=384)
    parent_preflight(plan.strict(proof), c)
    from asset_segments import exact_ranges
    exact_ranges(p['ranges'])
    pulse = plan.strict(__import__('base64').b64decode(c['initial_pulse_original']['original_raw_b64'], validate=True))
    plan.need(pulse['clear_reservation_original']['stage_operation'] == stage and pulse['clear_reservation_original']['plan_ref']['sha256'] == sha(rawplan), 'stage_specific_original_reservation')
    plan.need(c['A_boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'same_current_A_boot')
    age = time.time() - c['initial_pulse_original']['A_received_at']
    plan.need(0 <= age < (30 if admit else 1800), 'original_stage_pulse_arrival_age')
    if admit:
        c = dict(c, remaining_seconds=c['remaining_seconds'] - age)
        plan.need(30 < c['remaining_seconds'] <= p['duration_seconds'] <= 1800, 'original_stage_remaining_runtime_no_extension')
    return (c, p)

def payload_parent(stage, *, create):
    """Only the configured new stage parent; never recursive mkdir or old retry."""
    import stat
    control, root = configure(stage)
    if create:
        provision_base()
    fds = []
    names = []
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fds.append(fd)
    try:
        for part in Path(BASE_DATA).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            z = os.fstat(child)
            plan.need(z.st_uid == z.st_gid == 0 and stat.S_ISDIR(z.st_mode) and (not z.st_mode & 18), 'stage_payload_parent_Root_ancestry')
            names.append((fd, part, child))
            fds.append(child)
            fd = child
        base = os.fstat(fd)
        plan.need(stat.S_IMODE(base.st_mode) == 448, 'stage_payload_BASE_private')
        for part in ('stages', stage):
            if create:
                try:
                    os.mkdir(part, mode=448, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    plan.need(part == 'stages', 'new_stage_payload_parent_not_retry')
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            z = os.fstat(child)
            plan.need(z.st_uid == z.st_gid == 0 and stat.S_ISDIR(z.st_mode) and (stat.S_IMODE(z.st_mode) == 448), 'stage_payload_parent_private')
            names.append((fd, part, child))
            fds.append(child)
            fd = child
        plan.need(os.listdir(fd) == [], 'new_stage_payload_parent_empty')
        for parent, name, child in names:
            z = os.fstat(child)
            n = os.stat(name, dir_fd=parent, follow_symlinks=False)
            plan.need((z.st_dev, z.st_ino, z.st_uid, z.st_gid, z.st_mode) == (n.st_dev, n.st_ino, n.st_uid, n.st_gid, n.st_mode), 'stage_payload_parent_named_FD')
        return root
    finally:
        for child in reversed(fds):
            os.close(child)

def provision_base():
    """Create only final BASE_DATA under the held Root parent FD at asset-start."""
    import stat
    plan.need(APPROVED is not None and BASE_DATA is not None, 'BASE_SOURCE_pending')
    path = Path(BASE_DATA)
    plan.need(path.is_absolute() and len(path.parts) > 2 and all((x not in ('.', '..') for x in path.parts)), 'fixed_BASE_path')
    fds = []
    names = []
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fds.append(fd)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            z = os.fstat(child)
            plan.need(z.st_uid == 0 and z.st_gid == 0 and stat.S_ISDIR(z.st_mode) and (not z.st_mode & 18), 'BASE_existing_Root_parent')
            names.append((fd, part, child))
            fds.append(child)
            fd = child
        created = False
        try:
            os.mkdir(path.name, mode=448, dir_fd=fd)
            created = True
        except FileExistsError:
            pass
        child = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        fds.append(child)
        names.append((fd, path.name, child))
        if created:
            os.fchmod(child, 448)
            os.fsync(child)
            os.fsync(fd)
        z = os.fstat(child)
        plan.need(z.st_uid == z.st_gid == 0 and stat.S_ISDIR(z.st_mode) and (stat.S_IMODE(z.st_mode) == 448), 'BASE_exact_Root_private')
        for parent, name, held in names:
            a = os.fstat(held)
            b = os.stat(name, dir_fd=parent, follow_symlinks=False)
            plan.need((a.st_dev, a.st_ino, a.st_uid, a.st_gid, a.st_mode) == (b.st_dev, b.st_ino, b.st_uid, b.st_gid, b.st_mode), 'BASE_held_named_identity')
        return {'path': str(path), 'created': created, 'stat': [getattr(z, n) for n in ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')]}
    finally:
        for held in reversed(fds):
            os.close(held)
