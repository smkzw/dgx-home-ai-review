# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import errno, base64, hashlib, json, os, re, stat, subprocess, sys, time
from pathlib import Path
import observer, ready_history
PROPS = 'Id,LoadState,ActiveState,SubState,MainPID,ExecMainPID,ExecStart,Type,User,Group,ExecMainCode,ExecMainStatus,Result,NRestarts,InvocationID,ControlGroup,RemainAfterExit,Restart,KillMode,SendSIGKILL,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,Nice,IOSchedulingClass,RuntimeMaxUSec,TimeoutStopUSec'
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def need(v, r):
    if not v:
        raise RuntimeError(r)

def sha(v):
    return hashlib.sha256(v).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):

    def pairs(items):
        d = {}
        for k, v in items:
            need(k not in d, 'duplicate_key')
            d[k] = v
        return d
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_json'))

def read(p, cap=4194304):
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        z = os.fstat(fd)
        s = [getattr(z, k) for k in FIELDS]
        need(stat.S_ISREG(z.st_mode) and s[3] == 0 and (s[6] == 1) and (not s[5] & 18) and (0 <= s[2] <= cap), 'actual_Root_held_leaf')
        raw = os.pread(fd, s[2] + 1, 0)
        need(len(raw) == s[2] and s == [getattr(os.fstat(fd), k) for k in FIELDS] == [getattr(p.lstat(), k) for k in FIELDS], 'full_actual_FD_named_F9')
        return {'raw_b64': base64.b64encode(raw).decode(), 'sha256': sha(raw), 'F9': s}
    finally:
        os.close(fd)

def write(p, raw):
    fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 384)
    try:
        os.fchmod(fd, 384)
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)

def command(argv, end):
    need(time.monotonic() < end, 'readonly_phase_absolute_budget')
    r = subprocess.run(argv, capture_output=True, timeout=min(10, max(0.001, end - time.monotonic())), env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    need(len(r.stdout) + len(r.stderr) <= 262144, 'bounded_command_original')
    return r

def observe(unit, end):
    r = command(['/usr/bin/systemctl', 'show', unit, '--property=' + PROPS], end)
    need(r.returncode == 0 and (not r.stderr), 'readonly_actual_unit_observation')
    u = dict((x.split('=', 1) for x in r.stdout.decode().splitlines()))
    need(u['Id'] == unit, 'own_unit_exact')
    cg = u['ControlGroup']
    procs = []
    if cg:
        need(cg == '/system.slice/' + unit, 'own_scope_cgroup')
        folder = Path('/sys/fs/cgroup' + cg)
        if folder.exists():
            for file in folder.rglob('cgroup.procs'):
                procs.extend(file.read_text().splitlines())
    return {'unit': u, 'unit_raw_utf8': r.stdout.decode(), 'unit_sha256': sha(r.stdout), 'cgroup_procs': procs, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'observed_at': time.time()}

def meta(z):
    return [getattr(z, k) for k in FIELDS]

def stable_directory(a, b):
    return all((a[i] == b[i] for i in (0, 1, 3, 4, 5)))

def kernel_leaf(directory, name, path):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        before = meta(os.fstat(fd))
        need(stat.S_ISREG(before[5]) and before[3] == 0 and (before[6] == 1) and (not before[5] & 18), 'fixed_kernel_leaf_identity')
        raw = bytearray()
        while True:
            part = os.read(fd, min(16384, 65537 - len(raw)))
            if not part:
                break
            raw.extend(part)
            need(len(raw) <= 65536, 'kernel_original_cap')
        need(before == meta(os.fstat(fd)) == meta(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'kernel_leaf_FD_named_identity')
        return {'path': path, 'raw_utf8': bytes(raw).decode(), 'sha256': sha(bytes(raw)), 'stat': before}
    finally:
        os.close(fd)

def kernel_after_stop(unit, pid, boot, end):
    need(type(pid) is int and pid > 1 and re.fullmatch('dgx-v4-prelaunch-(before-stop|after-stop|release)-[0-9a-f]{32}\\.service', unit), 'fixed_owned_kernel_target')
    started = time.time()
    fds = []

    def directory(path):
        need(time.monotonic() < end, 'readonly_phase_absolute_budget')
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fds.append((fd, path, meta(os.fstat(fd))))
        z = os.fstat(fd)
        need(z.st_uid == 0 and stat.S_ISDIR(z.st_mode) and (not z.st_mode & 18), 'kernel_anchor_Root_directory')
        return fd

    def boot_original():
        fd = directory('/proc/sys/kernel/random')
        return kernel_leaf(fd, 'boot_id', '/proc/sys/kernel/random/boot_id')
    try:
        first = boot_original()
        need(first['raw_utf8'].strip() == boot, 'same_actual_boot_before_kernel')
        proc = directory('/proc')
        try:
            os.stat(str(pid), dir_fd=proc, follow_symlinks=False)
        except FileNotFoundError as e:
            need(e.errno == errno.ENOENT, 'positive_original_PID_ENOENT')
        else:
            need(False, 'original_worker_PID_still_exists_unknown')
        parent = directory('/sys/fs/cgroup/system.slice')
        fixed = '/sys/fs/cgroup/system.slice/' + unit
        nodes = []
        try:
            cg = os.open(unit, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError as e:
            need(e.errno == errno.ENOENT, 'positive_fixed_CG_ENOENT')
            state = 'absent'
        else:
            state = 'present-empty'
            fds.append((cg, fixed, meta(os.fstat(cg))))

            def walk(fd, path):
                need(len(nodes) < 128 and time.monotonic() < end, 'bounded_owned_CG_tree')
                before = meta(os.fstat(fd))
                need(before[3] == 0 and stat.S_ISDIR(before[5]) and (not before[5] & 18), 'Root_owned_CG_tree')
                names = sorted(os.listdir(fd))
                leaf = kernel_leaf(fd, 'cgroup.procs', path + '/cgroup.procs')
                need(not leaf['raw_utf8'].strip(), 'owned_CG_nonempty_unknown')
                children = []
                for name in names:
                    z = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(z.st_mode):
                        children.append(name)
                    else:
                        need(not stat.S_ISLNK(z.st_mode), 'owned_CG_symlink_unknown')
                node = {'path': path, 'before_stat': before, 'after_stat': None, 'entries_before': names, 'entries_after': None, 'children': children, 'procs_original': leaf}
                nodes.append(node)
                for name in children:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    fds.append((child, path + '/' + name, meta(os.fstat(child))))
                    walk(child, path + '/' + name)
                node['entries_after'] = sorted(os.listdir(fd))
                node['after_stat'] = meta(os.fstat(fd))
                need(node['entries_before'] == node['entries_after'] and stable_directory(before, node['after_stat']), 'owned_CG_tree_drift')
            walk(cg, fixed)
        second = boot_original()
        need(second['raw_utf8'] == first['raw_utf8'], 'same_actual_boot_after_kernel')
        anchors = []
        for fd, path, before in fds:
            after = meta(os.fstat(fd))
            named = meta(os.stat(path, follow_symlinks=False))
            need(stable_directory(before, after) and stable_directory(before, named), 'kernel_directory_named_identity')
            anchors.append({'path': path, 'before_stat': before, 'after_stat': after, 'named_stat': named})
        need(time.monotonic() < end, 'readonly_phase_absolute_budget')
        return {'schema': 'owned-readonly-poststop-kernel/v1', 'unit': unit, 'original_worker_pid': pid, 'boot_before': first, 'boot_after': second, 'PID_absence': {'path': '/proc/' + str(pid), 'errno': errno.ENOENT}, 'fixed_cgroup': fixed, 'cgroup_state': state, 'cgroup_nodes': nodes, 'directory_anchors': anchors, 'started_at': started, 'finished_at': time.time()}
    finally:
        for fd, _, _ in reversed(fds):
            os.close(fd)

def stopped_unit_branch(before, after):
    u = after['unit']
    old = before['unit']
    need(u['Id'] == old['Id'] and u['MainPID'] == '0' and (u['ActiveState'] == 'inactive') and (u['SubState'] == 'dead') and (u['ControlGroup'] in ('', '/system.slice/' + old['Id'])) and (u['NRestarts'] == '0'), 'poststop_current_unit_not_active')
    if u['LoadState'] == 'loaded':
        need(u['InvocationID'] == old['InvocationID'] and u['ExecMainPID'] == old['ExecMainPID'] and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['Result'] == 'success'), 'loaded_poststop_same_original_invocation')
        return 'loaded-same-invocation'
    need(u['LoadState'] == 'not-found' and u['InvocationID'] == '' and (u['ControlGroup'] == '') and (u['ExecMainPID'] == u['ExecMainCode'] == u['ExecMainStatus'] == '0') and (u['Type'] == u['User'] == u['Group'] == '') and (u['Result'] == 'success'), 'collected_poststop_exact_missing_unit')
    return 'collected-with-independent-kernel-proof'

def argv(worker, unit):
    return ['/usr/bin/systemd-run', '--quiet', '--unit=' + unit, '--service-type=exec', '-p', 'User=root', '-p', 'Group=root', '-p', 'CPUQuota=100%', '-p', 'MemoryMax=192M', '-p', 'MemorySwapMax=0', '-p', 'TasksMax=32', '-p', 'Nice=10', '-p', 'IOSchedulingClass=idle', '-p', 'UMask=0077', '-p', 'RuntimeMaxSec=90', '-p', 'RemainAfterExit=yes', '-p', 'Restart=no', '-p', 'KillMode=process', '-p', 'SendSIGKILL=no', '-p', 'TimeoutStopSec=30', '/usr/bin/python3', '-I', '-B', str(worker)]
'Actual bounded owner readonly launch/EXIT0/capture/owned-stop envelope.'
APPROVED_FILES = {'plan.py': '834751e701152262c05a7c83c9b9a06c712351179a895b61d7769c8415cc7462', 'root_io.py': 'aed53aa0956f8c8645fe9f4ddb3bbbc15f5276c060566f32ebc4f92858186f2e', 'bounded_process.py': '3823d1deefe97145cab4275f60d0d00cff3c156b7606647bd5541872eaffd84f', 'old_failed_kernel.py': 'cd351ae2db35d0a09d88e5faa05020f9bdec51c898794607fc44c2c148550053', 'observer.py': 'ab162251ba0e2a01fb749da8f9f329a10e1a4fe404cc9141d600eafce90f87ef', 'ready_history.py': '3409bf6dbc76be748e28e2f2c605c251e7286501b81f8be09372a0f37ac2b8d5', 'worker.py': 'e09f637548d128507d48238294659ab028df04d267e278835e36721238ad5d72'}
APPROVED_WORKER_SHA = 'e09f637548d128507d48238294659ab028df04d267e278835e36721238ad5d72'
APPROVED_UNIT = 'dgx-v4-prelaunch-release-e3f0db75d5b0c39cbddfd4f05130b622.service'
APPROVED_OPERATION = '2b9e9b631cebc13ae6b1550ee59c13ed'
STAGE = Path('/opt/dgx-v4/r17-owner-readonly-cpu-e3f0db75d5b0c39cbddfd4f05130b622')

def run(input_raw):
    need(type(APPROVED_FILES) is dict and os.getuid() == os.geteuid() == 0 and (sys.platform == 'linux'), 'R16_owner_scope_SOURCE_None')
    value = strict(input_raw)
    need(type(value) is dict and set(value) == {'request_raw_b64', 'PC_begin_original'}, 'owner_scope_same_full_PC_BEGIN_input')
    request = base64.b64decode(value['request_raw_b64'], validate=True)
    begin = value['PC_begin_original']
    br = base64.b64decode(begin['raw_b64'], validate=True)
    bm = strict(br)
    r = strict(request)
    need(sha(br) == begin['sha256'] and begin['F9'][2] == len(br) and (begin['F9'][3:7] == [0, 989, 33056, 1]) and (bm['request_original']['sha256'] == sha(request)) and (r['nonce'] in APPROVED_UNIT) and (r['schema'] == 'failed-owner-terminal-PC-request/v1'), 'owner_scope_actual_PC_BEGIN_before_launch')
    root = STAGE
    u = APPROVED_UNIT
    end = time.monotonic() + 30
    saved = {n: read(root / n, 2097152) for n in APPROVED_FILES}
    need(all((row['sha256'] == APPROVED_FILES[n] for n, row in saved.items())) and APPROVED_FILES['worker.py'] == APPROVED_WORKER_SHA, 'owner_scope_complete_exact_source')
    write(root / 'request.json', request)
    write(root / 'PC-BEGIN-original.json', encode(begin))
    absent = command(['/usr/bin/systemctl', 'show', u, '--property=LoadState,MainPID'], end)
    need(absent.returncode == 0 and (not absent.stderr) and (dict((x.split('=', 1) for x in absent.stdout.decode().splitlines())) == {'LoadState': 'not-found', 'MainPID': '0'}), 'owner_scope_new_unit_actual_absent')
    write(root / 'launch-intent.json', encode({'unit': u, 'request_sha256': sha(request), 'PC_begin_sha256': sha(br), 'issued_at': time.time(), 'automatic_retry': False}))
    launch = command(argv(root / 'worker.py', u), end)
    write(root / 'launch-result.json', encode({'rc': launch.returncode, 'stdout_b64': base64.b64encode(launch.stdout).decode(), 'stderr_b64': base64.b64encode(launch.stderr).decode()}))
    need(launch.returncode == 0 and (not launch.stderr), 'owner_scope_launch_once_no_retry')
    while not (root / 'returned.json').exists():
        need(not (root / 'failed.json').exists() and time.monotonic() < end, 'owner_scope_bounded_return_no_retry')
        time.sleep(0.02)
    while True:
        before = observe(u, end)
        state = before['unit']
        need(state['ActiveState'] in ('active', 'activating') and state['NRestarts'] == '0', 'owner_scope_no_failed_restart')
        if state['MainPID'] == '0' and state['ActiveState'] == 'active' and (state['SubState'] == 'exited'):
            break
        need(time.monotonic() < end, 'owner_scope_bounded_quiescence')
        time.sleep(0.02)
    scope = observer.collect(u, root / 'returned.json', root / 'worker.py', APPROVED_WORKER_SHA, end)
    returned = ready_history.positive(scope, u, APPROVED_WORKER_SHA, True, operation=APPROVED_OPERATION)
    body = read(root / 'body.raw.json')
    need(returned['proof_sha256'] == body['sha256'] and returned['request_sha256'] == sha(request) and (returned['PC_begin_raw_sha256'] == sha(br)), 'owner_scope_retained_EXIT0_binds_actual_body_BEGIN')
    write(root / 'retained-scope.json', encode(scope))
    intent = {'unit': u, 'invocation_id': state['InvocationID'], 'worker_pid': returned['worker_pid'], 'body_sha256': body['sha256'], 'issued_at': time.time(), 'owned_stop_calls': 1}
    write(root / 'owned-stop-intent.json', encode(intent))
    stop = command(['/usr/bin/systemctl', 'stop', u], end)
    write(root / 'owned-stop-result.json', encode({'rc': stop.returncode, 'stdout_b64': base64.b64encode(stop.stdout).decode(), 'stderr_b64': base64.b64encode(stop.stderr).decode(), 'observed_at': time.time()}))
    need(stop.returncode == 0 and (not stop.stderr), 'owner_scope_owned_stop_success')
    after = observe(u, end)
    after['poststop_unit_branch'] = stopped_unit_branch(before, after)
    after['poststop_kernel_original'] = kernel_after_stop(u, returned['worker_pid'], scope['boot_id'], end)
    write(root / 'owned-stop-observed.json', encode(after))
    scope['owner_scope_termination'] = {n: read(root / n) for n in ('owned-stop-intent.json', 'owned-stop-result.json', 'owned-stop-observed.json')}
    need(all((read(root / n, 2097152) == row for n, row in saved.items())) and time.monotonic() < end, 'owner_scope_sources_after_actual_stop30')
    result = {'A_original': body, 'scope': scope}
    write(root / 'owner-qualified-origin.json', encode(result))
    return result
