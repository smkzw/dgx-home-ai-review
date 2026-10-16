# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Parent-reviewed readonly scope only. No Manager/Guard/model lifecycle."""
import base64, hashlib, json, os, platform, selectors, signal, stat, subprocess, sys, time
from pathlib import Path
ROLE = None
ROOT = None
DATA_PINS = None
REVIEW_SHA = None
WORKER_SHA = None
REQUEST_SHA = None
REQUEST_NONCE = None
UNITS = {'c': 'dgx-v4-c-unarmed-renewal-r26-2d8bb6adefd99ead39104bf44bf247d9.service'}
ROOTS = {'c': '/opt/dgx-v4/c-unarmed-renewal-r26-2d8bb6adefd99ead39104bf44bf247d9'}
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
UNIT_FIELDS = ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'ExecMainPID', 'ExecMainCode', 'ExecMainStatus', 'InvocationID', 'NRestarts', 'ControlGroup', 'CPUQuotaPerSecUSec', 'MemoryMax', 'MemorySwapMax', 'TasksMax', 'Nice', 'IOSchedulingClass', 'RuntimeMaxUSec', 'SendSIGKILL', 'Type', 'Restart', 'RemainAfterExit', 'Result', 'User', 'Group', 'KillMode', 'ExecStart')

def need(v, k):
    if not v:
        raise RuntimeError(k)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encoded(v):
    return (json.dumps(v, sort_keys=True, allow_nan=False) + '\n').encode()

def strict(raw):

    def pairs(xs):
        d = {}
        for k, v in xs:
            need(k not in d, 'duplicate_json')
            d[k] = v
        return d
    v = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_json'))
    encoded(v)
    return v

def f9(st):
    return [getattr(st, k) for k in FIELDS]

def read(path, cap=2097152):
    p = Path(path)
    parents = []
    for a in p.parents:
        s = a.lstat()
        need(stat.S_ISDIR(s.st_mode) and (not stat.S_ISLNK(s.st_mode)) and (s.st_uid == 0) and (not s.st_mode & 18), 'Root_chain')
        parents.append((a, (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)))
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and (st.st_nlink == 1) and (not st.st_mode & 18) and (st.st_size <= cap), 'Root_leaf')
        raw = os.pread(fd, st.st_size + 1, 0)
        need(len(raw) == st.st_size and f9(st) == f9(os.fstat(fd)) == f9(p.lstat()), 'Root_named_F9')
        need(all(((q.lstat().st_dev, q.lstat().st_ino, q.lstat().st_uid, q.lstat().st_gid, q.lstat().st_mode) == v for q, v in parents)), 'Root_chain_changed')
        return (raw, f9(st))
    finally:
        os.close(fd)

def fresh(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
    try:
        os.fchmod(fd, 384)
        os.fchown(fd, 0, 0)
        v = memoryview(raw)
        while v:
            n = os.write(fd, v)
            need(n > 0, 'short_write')
            v = v[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def context():
    need(REVIEW_SHA is not None and ROLE in UNITS and (ROOT == ROOTS[ROLE]) and (DATA_PINS is not None), 'source_pending')
    need(os.geteuid() == os.getuid() == 0 and sys.platform == 'linux' and (platform.node() == ('vicky' if ROLE == 'pc' else 'gx10-753c')), 'fixed_Root_host')
    need(Path(__file__).resolve().parent == Path(ROOT), 'fixed_new_namespace')
    result = {}
    for n, h in DATA_PINS.items():
        raw, st = read(Path(ROOT) / n)
        need(sha(raw) == h, 'sealed_five_SHA')
        result[n] = {'sha256': h, 'stat': st}
    return result

def command(argv):
    r = subprocess.run(argv, capture_output=True, timeout=10)
    need(len(r.stdout) <= 1048576 and len(r.stderr) <= 65536, 'bounded_control_output')
    return r

def observe():
    r = command(['/usr/bin/systemctl', 'show', UNITS[ROLE], '--property=' + ','.join(UNIT_FIELDS)])
    need(r.returncode == 0 and (not r.stderr), 'unit_observation')
    unit = dict((x.split('=', 1) for x in r.stdout.decode().splitlines()))
    cg = unit.get('ControlGroup', '')
    procs = []
    if cg:
        need(cg.startswith('/') and '..' not in Path(cg).parts and cg.endswith('/' + UNITS[ROLE]), 'owned_scope_cgroup_only')
        path = Path('/sys/fs/cgroup') / cg.lstrip('/')
        procs = [int(x) for f in path.rglob('cgroup.procs') for x in f.read_text().split()] if path.exists() else []
    return {'observed_at': time.time(), 'unit': unit, 'unit_raw_b64': base64.b64encode(r.stdout).decode(), 'unit_raw_sha256': sha(r.stdout), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'cgroup_procs': procs}

def run_child(argv, on_chunk=None):
    p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
    sel = selectors.DefaultSelector()
    out = bytearray()
    err = bytearray()
    end = time.monotonic() + 100
    for pipe, name in ((p.stdout, 'out'), (p.stderr, 'err')):
        os.set_blocking(pipe.fileno(), False)
        sel.register(pipe, selectors.EVENT_READ, name)
    try:
        while sel.get_map():
            need(time.monotonic() < end, 'owned_readonly_child_deadline')
            for key, _ in sel.select(min(0.2, max(0, end - time.monotonic()))):
                raw = os.read(key.fileobj.fileno(), 65536)
                if not raw:
                    sel.unregister(key.fileobj)
                    continue
                target = out if key.data == 'out' else err
                target.extend(raw)
                need(len(target) <= (4194304 if key.data == 'out' else 65536), 'owned_child_output_cap')
                if on_chunk is not None:
                    on_chunk(key.data, raw)
        rc = p.wait(timeout=max(0.001, end - time.monotonic()))
        return (rc, bytes(out), bytes(err))
    except BaseException:
        if p.poll() is None:
            p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise RuntimeError('owned_readonly_child_alive_unknown_no_force')
        raise
    finally:
        sel.close()
        p.stdout.close()
        p.stderr.close()

def worker():
    data = context()
    request, request_stat = read(Path(ROOT) / 'request.json')
    need(REQUEST_SHA is not None and REQUEST_NONCE is not None and (sha(request) == REQUEST_SHA) and (strict(request)['nonce'] == REQUEST_NONCE), 'actual_Root_request_bound_worker')
    cgrows = [x[3:] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::')]
    need(len(cgrows) == 1 and cgrows[0].endswith('/' + UNITS[ROLE]), 'worker_own_scope_before_write')
    cg = Path('/sys/fs/cgroup') / cgrows[0].lstrip('/')
    cpu = (cg / 'cpu.max').read_text().split()
    need(cpu[0] != 'max' and 0 < int(cpu[0]) <= int(cpu[1]) and (0 < int((cg / 'memory.max').read_text()) <= 201326592) and ((cg / 'memory.swap.max').read_text().strip() == '0') and (0 < int((cg / 'pids.max').read_text()) <= 32) and (os.getpriority(os.PRIO_PROCESS, 0) >= 10), 'worker_actual_kernel_caps')
    root = Path(ROOT)
    state = root / 'once'
    need(not state.exists(), 'once_exists')
    state.mkdir(mode=448)
    selfraw, selfstat = read(root / 'worker.py')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    inv = os.environ.get('INVOCATION_ID', '')
    need(len(inv) == 32 and all((x in '0123456789abcdef' for x in inv)), 'actual_invocation')
    intent = {'role': ROLE, 'unit': UNITS[ROLE], 'worker_pid': os.getpid(), 'boot_id': boot, 'invocation_id': inv, 'worker_sha256': sha(selfraw), 'worker_stat': selfstat, 'five_source': data, 'source_review_sha256': REVIEW_SHA, 'observed_at': time.time(), 'automatic_retry': False, 'request_original': {'raw_b64': base64.b64encode(request).decode(), 'sha256': REQUEST_SHA, 'stat': request_stat}, 'nonce': REQUEST_NONCE}
    fresh(state / 'intent.json', encoded(intent))
    try:
        fds = {name: os.open(state / file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384) for name, file in [('out', 'stdout.raw'), ('err', 'stderr.raw')]}

        def append(name, raw):
            view = memoryview(raw)
            while view:
                n = os.write(fds[name], view)
                need(n > 0, 'partial_raw_write')
                view = view[n:]
            os.fsync(fds[name])
        try:
            rc, out, err = run_child(['/usr/bin/python3', '-I', '-B', str(root / 'readonly_once.py'), ROLE], append)
        finally:
            for fd in fds.values():
                os.fsync(fd)
                os.close(fd)
        fresh(state / 'returned.json', encoded({**intent, 'observed_at': time.time(), 'child_rc': rc, 'stdout_sha256': sha(out), 'stderr_sha256': sha(err)}))
        need(rc == 0 and (not err), 'collector_not_positive')
        v = strict(out)
        need(v['schema'] == ('g8-C-R25-PC-current-readonly/v1' if ROLE == 'pc' else 'g8-C-R25-C-current-readonly/v1'), 'collector_not_actual_schema')
        need(context() == data, 'source_changed_during_RO')
        fresh(state / 'worker-completed.json', encoded({**intent, 'observed_at': time.time(), 'stdout_sha256': sha(out), 'actual_Root_collector_rc': 0, 'ARM_or_model_POST': 0}))
        return 0
    except BaseException as e:
        fresh(state / 'failed.json', encoded({**intent, 'observed_at': time.time(), 'error_type': type(e).__name__, 'partial_preserved': True, 'automatic_retry': False}))
        raise

def launch():
    context()
    request, request_stat = read(Path(ROOT) / 'request.json')
    need(REQUEST_SHA is not None and REQUEST_NONCE is not None and (sha(request) == REQUEST_SHA) and (strict(request)['nonce'] == REQUEST_NONCE), 'actual_Root_request_bound_launcher')
    need(WORKER_SHA is not None, 'launcher_pin_pending')
    root = Path(ROOT)
    worker_raw, worker_stat = read(root / 'worker.py')
    need(sha(worker_raw) == WORKER_SHA, 'exact_worker_SHA')
    o = observe()
    need(o['unit']['LoadState'] == 'not-found' and (not (root / 'once').exists()), 'new_unit_once_absent')
    fresh(root / 'launch-intent.json', encoded({'worker_sha256': WORKER_SHA, 'worker_stat': worker_stat, 'original': o, 'source_review_sha256': REVIEW_SHA, 'issued_at': time.time(), 'launch_calls': 1, 'automatic_retry': False, 'request_original': {'sha256': REQUEST_SHA, 'stat': request_stat}, 'nonce': REQUEST_NONCE}))
    argv = ['/usr/bin/systemd-run', '--unit=' + UNITS[ROLE], '--property=Type=exec', '--property=User=root', '--property=Group=root', '--property=RemainAfterExit=yes', '--property=Restart=no', '--property=CPUQuota=100%', '--property=MemoryMax=201326592', '--property=MemorySwapMax=0', '--property=TasksMax=32', '--property=Nice=10', '--property=IOSchedulingClass=idle', '--property=RuntimeMaxSec=120', '--property=KillMode=control-group', '--property=SendSIGKILL=no', '--property=TimeoutStopSec=20', '--property=UMask=0077', '--', '/usr/bin/python3', '-I', '-B', str(root / 'worker.py'), '--worker']
    r = command(argv)
    fresh(root / 'launch-result.json', encoded({'rc': r.returncode, 'stdout_b64': base64.b64encode(r.stdout).decode(), 'stderr_b64': base64.b64encode(r.stderr).decode(), 'observed_at': time.time()}))
    need(r.returncode == 0, 'launch_unknown_no_retry')
    return {'phase': 'launched_pending_actual_terminal', 'native_acceptance': False}

def capture_then_stop():
    data = context()
    root = Path(ROOT)
    o = observe()
    u = o['unit']
    intent = strict(read(root / 'once/intent.json')[0])
    returned = strict(read(root / 'once/returned.json')[0])
    complete = strict(read(root / 'once/worker-completed.json')[0])
    out, outs = read(root / 'once/stdout.raw', 4194304)
    err, errs = read(root / 'once/stderr.raw')
    worker, ws = read(root / 'worker.py')
    need(u['LoadState'] == 'loaded' and u['ActiveState'] == 'active' and (u['SubState'] == 'exited') and (u['MainPID'] == '0') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['NRestarts'] == '0') and (u['Result'] == 'success') and (u['Type'] == 'exec') and (u['User'] == 'root') and (u['Group'] == 'root') and (u['KillMode'] == 'control-group') and ('argv[]=/usr/bin/python3 -I -B ' + str(root / 'worker.py') + ' --worker ;' in u['ExecStart']) and (u['InvocationID'] == intent['invocation_id']) and (int(u['ExecMainPID']) == intent['worker_pid']) and (o['boot_id'] == intent['boot_id']) and (o['cgroup_procs'] == []), 'retained_true_EXIT0_same_identity')
    need(u['CPUQuotaPerSecUSec'] == '1s' and u['MemoryMax'] == '201326592' and (u['MemorySwapMax'] == '0') and (u['TasksMax'] == '32') and (u['Nice'] == '10') and (u['IOSchedulingClass'] == '3') and (u['RuntimeMaxUSec'] == '2min') and (u['SendSIGKILL'] == 'no') and (u['Restart'] == 'no') and (u['RemainAfterExit'] == 'yes'), 'actual_scope_resource_contract')
    need(data == intent['five_source'] and sha(worker) == intent['worker_sha256'] == WORKER_SHA and (ws == intent['worker_stat']) and (returned['child_rc'] == 0) and (not err) and (sha(out) == returned['stdout_sha256'] == complete['stdout_sha256']) and (sha(err) == returned['stderr_sha256']), 'actual_sources_raw_F9_completed')
    v = strict(out)
    need(v['schema'] == 'g8-C-R25-C-current-readonly/v1', 'positive_readonly_payload')
    candidate, candidate_stat = read(root / 'once/candidate-before-validation.raw.json', 4194304)
    need(strict(candidate) == v, 'archived_original_candidate_matches_stdout')
    originals = {}
    for name in ('intent.json', 'returned.json', 'worker-completed.json', 'stdout.raw', 'stderr.raw', 'candidate-before-validation.raw.json'):
        raw, st = read(root / 'once' / name, 4194304)
        originals[name] = {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'stat': st}
    source_originals = {}
    for name in (*DATA_PINS, 'worker.py', 'launch-and-capture.py'):
        body, st = read(root / name, 2097152)
        source_originals[name] = {'raw_b64': base64.b64encode(body).decode(), 'sha256': sha(body), 'stat': st}
    need(len(source_originals) == 8 and source_originals['parent-review.raw']['sha256'] == REVIEW_SHA, 'actual_complete_source8_review')
    request, request_stat = read(root / 'request.json')
    need(sha(request) == REQUEST_SHA and strict(request)['nonce'] == REQUEST_NONCE and (intent['nonce'] == REQUEST_NONCE) and (intent['request_original'] == {'raw_b64': base64.b64encode(request).decode(), 'sha256': REQUEST_SHA, 'stat': request_stat}), 'same_actual_original_Root_request')
    receipt = {'schema': 'c-unarmed-renewal-R26-owned-readonly-completed/v1', 'originals': originals, 'role': ROLE, 'source_review_sha256': REVIEW_SHA, 'observed_at': time.time(), 'actual_retained_EXIT0': o, 'intent': intent, 'returned': returned, 'worker_completed': complete, 'stdout_sha256': sha(out), 'stdout_stat': outs, 'stderr_sha256': sha(err), 'stderr_stat': errs, 'actual_result': v, 'ARM_or_trial_accepted': False, 'owner_scope_stop_pending': True, 'root': ROOT, 'unit': UNITS[ROLE], 'nonce': REQUEST_NONCE, 'request_original': intent['request_original'], 'source_originals': source_originals}
    fresh(root / 'readonly-qualified.json', encoded(receipt))
    fresh(root / 'owned-stop-intent.json', encoded({'unit': UNITS[ROLE], 'invocation_id': intent['invocation_id'], 'issued_at': time.time(), 'owned_scope_stop_calls': 1}))
    r = command(['/usr/bin/systemctl', 'stop', UNITS[ROLE]])
    fresh(root / 'owned-stop-result.json', encoded({'rc': r.returncode, 'stdout_b64': base64.b64encode(r.stdout).decode(), 'stderr_b64': base64.b64encode(r.stderr).decode(), 'observed_at': time.time()}))
    need(r.returncode == 0 and (not r.stderr), 'owned_stop_unknown')
    after = observe()
    fresh(root / 'owned-stop-observed.json', encoded(after))
    need(after['unit']['MainPID'] == '0' and after['unit']['ActiveState'] in ('inactive', 'failed') and (after['cgroup_procs'] == []), 'owned_stopped_empty_required')
    return receipt
if __name__ == '__main__':
    if REVIEW_SHA is None:
        print(json.dumps({'status': 'SOURCE_inert', 'native_actions': 0}))
    elif sys.argv[1:] == ['--worker']:
        raise SystemExit(worker())
    elif sys.argv[1:] == ['--launch']:
        print(json.dumps(launch()))
    elif sys.argv[1:] == ['--capture-owned-stop']:
        print(json.dumps(capture_then_stop()))
    else:
        raise SystemExit(126)
