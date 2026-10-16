# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Parent-only fixed source RO collector. Default inert. No installer/ARM main."""
import base64, json, os, platform, stat, sys, time, types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate import A, need, sha, strict
APPROVED_READONLY_SOURCE_REVIEW_SHA256 = None
REQUEST_SHA = None
REQUEST_NONCE = None
NAMES = {'c': 'dgx-v4-c-unarmed-before-pc-r30-readonly.service'}

def own_scope(role):
    need(APPROVED_READONLY_SOURCE_REVIEW_SHA256 is not None and os.getuid() == os.geteuid() == 0 and (sys.platform == 'linux'), 'reviewed_parent_Root_RO_only')
    need(platform.node() == ('vicky' if role == 'pc' else 'gx10-753c') and platform.machine() == ('x86_64' if role == 'pc' else 'aarch64'), 'fixed_target_host')
    rows = [x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::')]
    need(len(rows) == 1 and rows[0].endswith('/' + NAMES[role]), 'new_owned_readonly_unit')
    cg = Path('/sys/fs/cgroup') / rows[0].lstrip('/')
    quota = (cg / 'cpu.max').read_text().split()
    need(quota[0] != 'max' and 0 < int(quota[0]) <= int(quota[1]) and (0 < int((cg / 'memory.max').read_text()) <= 192 * 1024 ** 2) and ((cg / 'memory.swap.max').read_text().strip() == '0') and (0 < int((cg / 'pids.max').read_text()) <= 32) and (os.getpriority(os.PRIO_PROCESS, 0) >= 10), 'readonly_scope_kernel_caps')

def held_root(path, limit=2097152):
    path = Path(path)
    parents = []
    for a in path.parents:
        st = a.lstat()
        need(stat.S_ISDIR(st.st_mode) and (not stat.S_ISLNK(st.st_mode)) and (st.st_uid == 0) and (not st.st_mode & 18), 'protected_root_ancestor')
        parents.append((a, (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode)))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and (st.st_nlink == 1) and (not st.st_mode & 18) and (st.st_size <= limit), 'Root_RO_leaf')
        raw = os.pread(fd, st.st_size + 1, 0)
        need(len(raw) == st.st_size and all((getattr(st, k) == getattr(os.fstat(fd), k) == getattr(path.lstat(), k) for k in keys)), 'Root_RO_F9_stable')
        need(all(((a.lstat().st_dev, a.lstat().st_ino, a.lstat().st_uid, a.lstat().st_gid, a.lstat().st_mode) == v for a, v in parents)), 'Root_RO_ancestor_changed')
        return raw
    finally:
        os.close(fd)

def load(name, path, raw):
    m = types.ModuleType(name)
    m.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m
ARCHIVE_ROOT = Path('/opt/dgx-v4/runtime/g8-clock-probe-c30-mimo-registry-r16')

def archive_candidate(value):
    need(Path(__file__).resolve().parent == ARCHIVE_ROOT, 'fixed_C_only_archive_namespace')
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    need(len(raw) <= 4194304, 'candidate_raw4MiB')
    folder = ARCHIVE_ROOT / 'once'
    dirfd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.fstat(dirfd)
        need(st.st_uid == st.st_gid == 0 and stat.S_IMODE(st.st_mode) == 448, 'owned_archive_Root_directory')
        fd = os.open('candidate-before-validation.raw.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=dirfd)
        try:
            os.fchmod(fd, 384)
            os.fchown(fd, 0, 0)
            view = memoryview(raw)
            while view:
                n = os.write(fd, view)
                need(n > 0, 'candidate_partial_write')
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(dirfd)
    finally:
        os.close(dirfd)
    return {'path': str(folder / 'candidate-before-validation.raw.json'), 'sha256': sha(raw), 'bytes': len(raw)}

def guard_process(pid):
    originals = {}
    for name in ('cmdline', 'status', 'stat'):
        p = Path('/proc') / str(pid) / name
        before = p.lstat()
        raw = p.read_bytes()
        after = p.lstat()
        keys = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) <= 1048576 and all((getattr(before, k) == getattr(after, k) for k in keys)), 'current_guard_proc_named_stable')
        originals[name] = {'path': str(p), 'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'stat9': [getattr(before, k) for k in keys]}
    raw = base64.b64decode(originals['stat']['raw_b64'])
    return {'pid': pid, 'start_ticks': raw.rsplit(b')', 1)[1].split()[19].decode(), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'originals': originals}

def c_capture():
    reader = A['ARM_reader']
    rp = Path(reader['path'])
    raw = held_root(rp)
    need(sha(raw) == reader['sha256'], 'fixed_historical_RO_reader_SHA')
    E = load('finite_RO_reader', rp, raw)
    h = A['ROOT_helper']
    raw = E.root_held(Path(h['path']))[0]
    need(sha(raw) == h['sha256'], 'fixed_C_RO_helper_SHA')
    m = load('fixed_C_RO_IO', Path(h['path']), raw)
    record_before = m.FENCE.lstat()
    record = m.node_record()
    record_after = m.FENCE.lstat()
    record_fields = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
    need(all((getattr(record_before, k) == getattr(record_after, k) for k in record_fields)), 'actual_SQL_record_F9_stable')
    record_original = {'path': str(m.FENCE), 'canonical_utf8': m.encoded(record).decode(), 'sha256': sha(m.encoded(record)), 'stat9': [getattr(record_after, k) for k in record_fields]}
    from validate import record_policy
    record_policy(record, time.time())
    root_changed = {}
    source_files = {}
    for path, h in A['C']['source19'].items():
        body, st = E.root_held(Path(path))
        need(sha(body) == h, 'actual_root19')
        source_files[path] = {'sha256': h, 'stat': st}
    for path, row in A['C']['changed'].items():
        body, st = E.root_held(Path(path))
        need({'sha256': sha(body), 'stat': st} == row, 'success_C3fullstat')
        root_changed[path] = {'sha256': sha(body), 'stat': st}
    lock = E.root_held(m.LOCK)[1]
    pid = m.guard_pid()
    m.sole_guard(pid)
    status = strict(E.root_held(E.STATUS, 384)[0])
    state = strict(E.root_held(E.GUARD_STATE, 384)[0])
    samples = []
    for i in range(3):
        import uuid
        request = {'schema': 'dgx-v4-node-v1', 'request_id': uuid.uuid4().hex, 'action': 'preflight', 'node': 'spark-c', 'profile': 'qwen-a-c', 'owner': 'dgx-hx-service', 'generation': record['generation']}
        request_raw = m.encoded(request)
        sent = time.time()
        r = m.command(['/usr/bin/python3', '-I', '-B', str(m.WRAPPER)], raw=request_raw, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'PYTHONDONTWRITEBYTECODE': '1', 'SSH_ORIGINAL_COMMAND': 'dgx-v4-node-v1'}, timeout=10)
        received = time.time()
        need(r.returncode == 0 and (not r.stderr), 'single_actual_RO_preflight')
        reply = strict(r.stdout)
        need(all((reply.get(k) == v for k, v in request.items())), 'same_RO_request_nonce')
        samples.append({'request_raw_b64': base64.b64encode(request_raw).decode(), 'request_sha256': sha(request_raw), 'sent_at': sent, 'received_at': received, 'reply': reply, 'raw_b64': base64.b64encode(r.stdout).decode(), 'sha256': sha(r.stdout)})
        if i < 2:
            time.sleep(2.0)
    status = strict(E.root_held(E.STATUS, 384)[0])
    state = strict(E.root_held(E.GUARD_STATE, 384)[0])
    need(m.node_record() == record and m.guard_pid() == pid, 'C_identity_stable_during_RO')
    m.sole_guard(pid)
    controls = json.loads((Path(__file__).resolve().parent / 'Root_C_pins.json').read_bytes())['control_files']
    control_files = {}
    for path, h in controls.items():
        body, st = E.root_held(Path(path))
        need(sha(body) == h, 'five_original_C_controls')
        control_files[path] = {'sha256': h, 'stat': st}
    originals = {}
    from validate import read_historical_originals
    originals = read_historical_originals(E.root_held)
    receipt = strict(E.root_held(E.INPUTS, 288)[0])
    sys.path.insert(0, '/opt/dgx-v4/runtime')
    from G8_C_FIRSTTRIAL_CANDIDATE_R1.input_receipt import verify
    verify('441ebb261880f6de7dbfd96acce7e3cd370a57ef2f13d4696d18a517c4afabf6')
    total = dict((line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines()))['MemTotal'].split()
    need(total[1] == 'kB', 'MemTotal_units')
    proof_raw, proof_stat = E.root_held(E.PROOF, 384)
    historical = {'path': str(E.PROOF), 'raw_b64': base64.b64encode(proof_raw).decode(), 'sha256': sha(proof_raw), 'stat9': [proof_stat[k] for k in ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')]}
    out = {'schema': 'g8-C-R25-C-current-readonly/v1', 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'observed_at': time.time(), 'node_record': record, 'resource_lock': lock, 'guard_pid': pid, 'session_id': state['session_id'], 'status': status, 'guard_state': state, 'NODE_permit_absent': not os.path.lexists(E.PERMIT), 'approval_absent': not os.path.lexists(E.APPROVAL), 'historical_inactive_proof': historical, 'source_files': source_files, 'control_files': control_files, 'historical_root_originals': originals, 'root_changed': root_changed, 'host_facts': {'total_bytes': int(total[0]) * 1024, 'cpu_count': len(os.sched_getaffinity(0))}, 'input_receipt_sha256': sha(E.root_held(E.INPUTS, 288)[0]), 'preflights': samples, 'native_model_POST': 0}
    for path, row in {**source_files, **control_files, **root_changed}.items():
        body, st = E.root_held(Path(path))
        need({'sha256': sha(body), 'stat': st} == row, 'C_source_changed_during_RO_capture')
    need(E.root_held(E.PROOF, 384) == (proof_raw, proof_stat), 'historical_proof_changed_during_capture')
    need(all((getattr(record_after, k) == getattr(m.FENCE.lstat(), k) for k in record_fields)), 'current_Node_DB_F9_after_three_frames')
    out['node_record_original'] = record_original
    out['current_guard_process'] = guard_process(pid)
    out['current_guard_originals'] = {}
    for name, path, key in (('status', E.STATUS, 'status'), ('state', E.GUARD_STATE, 'guard_state')):
        body, st = E.root_held(path, 384)
        need(strict(body) == out[key], 'current_Guard_stable_until_archive')
        out['current_guard_originals'][name] = {'path': str(path), 'raw_b64': base64.b64encode(body).decode(), 'sha256': sha(body), 'stat': st}
    archive_candidate(out)
    from validate import c
    c(out, time.time())
    return out

def main(role):
    if APPROVED_READONLY_SOURCE_REVIEW_SHA256 is None:
        return {'status': 'SOURCE_inert', 'native_actions': 0, 'ARM_eligible': False}
    need(role == 'c' and role in NAMES, 'fixed_C_RO_role')
    own_scope(role)
    request_raw = held_root(ARCHIVE_ROOT / 'request.json')
    request = strict(request_raw)
    need(REQUEST_SHA is not None and REQUEST_NONCE is not None and (sha(request_raw) == REQUEST_SHA) and (request['nonce'] == REQUEST_NONCE) and (request['source_review_sha256'] == APPROVED_READONLY_SOURCE_REVIEW_SHA256) and (request['action'] == 'collect-current-C'), 'actual_Root_request_bound_collector')
    import signal

    def expired(*_):
        raise TimeoutError('owned_readonly90s')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(90)
    try:
        result = c_capture()
        raw = json.dumps(result, allow_nan=False).encode()
        need(len(raw) <= 4194304, 'stdout4MiB')
        return result
    finally:
        signal.alarm(0)
if __name__ == '__main__':
    print(json.dumps(main(sys.argv[1] if len(sys.argv) == 2 else ''), allow_nan=False))
