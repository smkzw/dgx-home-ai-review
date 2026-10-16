# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One normal stop/CAS/start of the existing PC unit. SOURCE, not run here."""
from __future__ import annotations
import hashlib, http.client, json, os, platform, sqlite3, stat, subprocess, sys, time, types
from pathlib import Path
STAGE = Path('/opt/dgx-v4/hx/b-owner-recovery-r25-install-r1d/inputs')
STATE = Path('/opt/dgx-v4/hx/b-owner-recovery-r25-install-r1d/private')
RECEIPT = Path('/opt/dgx-v4/hx/CURRENT_SOURCE_RECEIPT_B_OWNER_RECOVERY_R25_R1D.json')
OLD_RECEIPT = Path('/opt/dgx-v4/hx/CURRENT_SOURCE_RECEIPT_G8_HX_C_ATTACH_CLEANUP_R23.json')
OLD_RECEIPT_SHA = 'cc56340926fce7df11109c237fb38a0991aea63bd92971ce30c097bc45b85ea9'
OLD_PID = 165691
BOOT = 'redacted-2606f3e07a03'
LOCK = [2096, 69257]
APPROVED_PARENT_SOURCE_REVIEW_SHA256 = None
OPERATOR_CONFIG = Path('/etc/dgx-home-ai/b-owner-recovery-r25-r1d.json')
OPERATOR_ROOT = Path('/srv/dgx-home-ai/runtime/hx-service-state/b-owner-recovery-r25-r1d')
C_ACCEPTANCE_SHA = 'b1d728c53944f59d03671f1f5b9cfd5e9fcb83178f816697964d96ff67b0f020'
IO_SHA = 'ce9101cbfae347a7d951c720d45d8ce37985e8aba087afb842841542c5efa9d6'
EVIDENCE_SHA = '0159cda548f3da47d4ee0fedb70bfbe208eab4aa328a189cb23676ee04ef57ab'
EVIDENCE_PATH = Path('/opt/dgx-v4/hx/g8-hx-integration-transaction-r1b/inputs/evidence.py')

class Refused(RuntimeError):
    pass

def need(ok, reason):
    if not ok:
        raise Refused(reason)

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict(raw):

    def pairs(items):
        d = {}
        for k, v in items:
            need(k not in d, 'duplicate_key')
            d[k] = v
        return d
    v = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite'))
    encode(v)
    return v

def load_io():
    path = STAGE / 'io_utils.py'
    raw = path.read_bytes()
    need(sha(raw) == IO_SHA, 'held_IO_source')
    module = types.ModuleType('B_R25_existing_IO')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    need(sha(module.read(path)[0]) == IO_SHA, 'physical_IO_source')
    return module

def unit_constraints(io):
    p = io.command(['/usr/bin/systemctl', 'show', io.UNIT, '--property=Type,Restart,KillSignal,KillMode,SendSIGKILL,TimeoutStopUSec,ControlGroup,Result,NRestarts'], timeout=10)
    need(p.returncode == 0 and (not p.stderr), 'unit_semantics_unknown')
    d = dict((x.split('=', 1) for x in p.stdout.decode().splitlines()))
    need(d.get('Type') == 'exec' and d.get('Restart') == 'no' and (d.get('KillMode') == 'process') and (d.get('SendSIGKILL') == 'no') and (d.get('KillSignal') in ('15', 'SIGTERM')), 'normal_TERM_no_forcekill_required')
    return d

def actual_rows(io):
    source = EVIDENCE_PATH
    raw, _ = io.read(source)
    need(sha(raw) == EVIDENCE_SHA, 'real_original_row_producer')
    sent = time.time()
    result = io.command(['/usr/bin/setpriv', '--reuid=999', '--regid=989', '--groups=989,1000', '/usr/bin/python3', '-I', '-B', str(source)], timeout=20)
    received = time.time()
    need(result.returncode == 0 and (not result.stderr), 'real_UID999_rows_failed')
    d = strict(result.stdout)
    need(sent <= d['observed_at'] <= received, 'raw_original_time_interval')
    return {'raw_utf8': result.stdout.decode(), 'sha256': sha(result.stdout), 'rows': d, 'sent_at': sent, 'received_at': received}

def idle_gate(proof):
    rows = proof['rows']
    need(rows['active_requests'] == rows['active_jobs'] == [], 'current_work_requires_stop_refusal')
    need(rows['historical_terminal_uncertain_count'] == 9 and rows['historical_terminal_uncertain_sha256'] == 'e0746d81ec98ad0f246b52dcb776a393943359bff517505f89709d42b4a81f5c', 'history9_mismatch')
    p = rows['profiles']['glm-ab']
    need(p['owner'] == 'dgx-hx-service' and p['generation'] == 10 and (p['state'] in ('STARTING', 'RECONCILING', 'FAILED', 'QUARANTINED', 'READY')), 'original_owner_gen10')
    for node in ('spark-a', 'spark-b'):
        n = next((r for r in rows['nodes'] if r['name'] == node))
        need((n['hold_profile'], n['hold_owner'], n['hold_generation']) == ('glm-ab', 'dgx-hx-service', 10), 'whole_AB_holds')
    for profile in ('image-turbo-c', 'qwen-a-c'):
        p = rows['profiles'][profile]
        need(p['state'] == 'STOPPED' and p['owner'] is None, 'C_profile_not_idle')

def same_history_and_holds(before, after, *, after_start=False):
    a = before['rows']
    b = after['rows']
    for k in ('requests', 'active_requests', 'active_jobs', 'historical_terminal_uncertain_count', 'historical_terminal_uncertain_sha256'):
        need(a[k] == b[k], 'requests_or_history_changed')
    for name, p in a['profiles'].items():
        q = b['profiles'][name]
        for key in ('profile', 'owner', 'generation', 'nodes'):
            need(p[key] == q[key], 'profile_identity_changed')
        if not after_start:
            need(p == q, 'profile_changed_during_stop')
        else:
            need(q['state'] == p['state'] or (name == 'glm-ab' and q['state'] in ('RECONCILING', 'FAILED', 'QUARANTINED')), 'normal_reconcile_state_only')
    if not after_start:
        need(a['nodes'] == b['nodes'], 'held_nodes_changed')
    else:
        need(len(a['nodes']) == len(b['nodes']), 'node_inventory_changed')
        for old, new in zip(a['nodes'], b['nodes']):
            need(all((old[k] == new[k] for k in old if k != 'last_seen_at')), 'held_node_fence_changed')
            need(old['last_seen_at'] == new['last_seen_at'] or (type(new['last_seen_at']) in (int, float) and (old['last_seen_at'] is None or new['last_seen_at'] >= old['last_seen_at'])), 'node_observation_time_regressed')

def closure(io, mapping):
    files = {}
    metadata = {}
    raws = {}
    for path, pin in mapping.items():
        need(path.startswith(('/opt/dgx-v4/hx/', '/etc/dgx-home-ai/', '/etc/dgx-v4/')) and '/..' not in path, 'fixed_source_paths_only')
        raw, info = io.read(Path(path))
        need(sha(raw) == pin, 'source_epoch_drift')
        files[path] = pin
        metadata[path] = io.identity(info)
        raws[path] = raw
    return (files, metadata, raws)

def backup_databases(io):
    source = Path('/srv/dgx-home-ai/runtime/hx-service-state')
    output = {}
    for relative in ('control/control.db', 'gateway/llm_gateway.db', 'g8-c-firsttrial/commands.sqlite3'):
        p = source / relative
        s = p.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 999 and (s.st_nlink == 1) and (stat.S_IMODE(s.st_mode) == 384), 'original_metadata_DB')
        target = STATE / ('backup-' + relative.replace('/', '-'))
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384)
        os.close(fd)
        read = sqlite3.connect(p.as_uri() + '?mode=ro', uri=True, timeout=5)
        write = sqlite3.connect(target)
        try:
            read.execute('PRAGMA query_only=ON')
            read.backup(write)
            write.commit()
        finally:
            write.close()
            read.close()
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        io.sync(STATE)
        output[relative] = {'backup': str(target), 'sha256': sha(target.read_bytes()), 'original_stat': io.identity(s), 'backup_stat': io.identity(target.lstat())}
    return output
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

def read_command_history():
    path = Path('/srv/dgx-home-ai/runtime/hx-service-state/g8-c-firsttrial/commands.sqlite3')
    with HeldParent(path, legacy=True) as chain:
        fd = chain.open_leaf()
        try:
            before = os.fstat(fd)
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            need(directory_identity(before) == (2096, 41810, 999, 989, 33152) and before.st_nlink == 1, 'legacy_DB_original_file')
            c = sqlite3.connect('file:/proc/self/fd/' + str(chain.parent_fd) + '/' + path.name + '?mode=ro', uri=True, timeout=5)
            c.row_factory = sqlite3.Row
            try:
                c.execute('PRAGMA query_only=ON')
                c.execute('BEGIN')
                rows = {name: [dict(r) for r in c.execute('SELECT * FROM ' + name + ' ORDER BY ' + ('id' if name == 'run' else 'key'))] for name in ('run', 'commands')}
            finally:
                c.close()
            need(all((getattr(before, k) == getattr(os.fstat(fd), k) == getattr(chain.named_leaf(), k) for k in fields)), 'legacy_DB_named_identity_changed')
        finally:
            os.close(fd)
        need(all((r['state'] == 'FINISHED' for r in rows['commands'])), 'legacy_command_inflight')
        need(len(rows['run']) == 1 and rows['run'][0]['phase'] == 'CLEANED_RELEASED', 'legacy_trial_not_cleaned')
        return {'canonical_utf8': encode(rows).decode(), 'sha256': sha(encode(rows)), 'original_file_stat': {k: getattr(before, k) for k in fields}, 'observed_at': time.time()}

def replace(io, path, raw, before):
    p = Path(path)
    temp = p.parent / ('.' + p.name + '.B-owner-R25.tmp')
    if before is None:
        need(not p.exists() and (not p.is_symlink()), 'new_source_already_exists')
    else:
        need(io.read(p) == before, 'late_leaf_CAS')
    mode = 420 if before is None else stat.S_IMODE(before[1].st_mode)
    gid = 0 if before is None else before[1].st_gid
    io.fresh(temp, raw, mode=mode, gid=gid)
    if before is None:
        os.link(temp, p, follow_symlinks=False)
        temp.unlink()
    else:
        need(io.read(p) == before, 'late_replace_CAS')
        os.replace(temp, p)
    io.sync(p.parent)
    need(io.read(p)[0] == raw, 'new_leaf_unconfirmed')

def listener_auth(io, pid):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        io.original_manager(pid)
        result = io.command(['/usr/bin/ss', '-lntp', '( sport = :8088 )'], timeout=2)
        need(result.returncode == 0 and (not result.stderr), 'listener_owner_unknown')
        lines = result.stdout.decode().splitlines()[1:]
        if len(lines) == 1 and '127.0.0.1:8088' in lines[0] and ('pid=' + str(pid) + ',' in lines[0]):
            connection = http.client.HTTPConnection('127.0.0.1', 8088, timeout=min(1, max(0.01, deadline - time.monotonic())))
            try:
                connection.request('GET', '/v1/models', headers={'Connection': 'close'})
                response = connection.getresponse()
                body = response.read(65537)
                need(response.status == 401 and response.getheader('Location') is None and (len(body) <= 65536), 'anonymous_models_401')
                need(time.monotonic() < deadline, 'listener_deadline')
                return {'observed_at': time.time(), 'owned_pid': pid, 'anonymous_status': 401, 'body_sha256': sha(body), 'credential_read': False}
            finally:
                connection.close()
        need(not lines, 'wrong_or_extra_listener')
        time.sleep(0.1)
    raise Refused('listener_readiness_deadline_no_retry')

def validate_activation_inputs(oldmap, plan, payloads, raw, acceptance, parent_sha):
    config = strict(raw)
    newmap = dict(oldmap)
    newmap.update({p: r['sha256'] for p, r in plan.items()})
    need(config.get('enabled') is True and config.get('review_sha256') == parent_sha and (config.get('PC_source_pins') == newmap), 'exact_activated_new118_configuration')
    need(sha(acceptance) == C_ACCEPTANCE_SHA == config.get('C_actual_parent_acceptance_sha256'), 'exact_C_accepted_raw')
    import re, ast
    need(isinstance(config.get('operation'), str) and re.fullmatch('[0-9a-f]{32}', config['operation']), 'fixed_once_operation')
    target = '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/wiring.py'
    need(target in payloads, 'activation_wiring_required')
    tree = ast.parse(payloads[target])
    values = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == 'APPROVED_ACTIVATION_REVIEW_SHA256' for t in n.targets))]
    need(values == [parent_sha], 'same_review_literal_before_start')
    return config

def validate_node_source_proof(raw, expected, now):
    proof = strict(raw)
    need(set(proof) == {'schema', 'nodes'} and proof['schema'] == 'B-owner-R25-AB-current-physical9-parent-proof/v1', 'exact_AB_source_proof')
    need(set(proof['nodes']) == set(expected) == {'spark-a', 'spark-b'}, 'whole_AB_physical_proof')
    for node, pins in expected.items():
        actual = proof['nodes'][node]
        stamp = actual.get('observed_at')
        need(type(stamp) in (float, int) and 0 <= now - stamp <= 300, 'fresh_original_AB_source_time')
        need(type(actual.get('root_uid')) is int and actual['root_uid'] == 0 and (set(actual.get('files', {})) == set(pins)) and (len(pins) == 9), 'actual_Root_full_physical9')
        records = actual.get('NodeDB')
        need(isinstance(records, list) and len(records) == 1, 'actual_original_NodeDB')
        record = records[0]
        expected_cid = {'spark-a': '8eaedd8d066e43324a931462c83b3a205a5b78e8ff4e37b794e351a5d20bb495', 'spark-b': 'decf09c95739f06a1435a2404eff36556a02e32687032e34471c2ceffdb3f256'}[node]
        need((record['profile'], record['owner'], record['generation'], record['container_id']) == ('glm-ab', 'dgx-hx-service', 10, expected_cid) and record['state'] in ('RUNNING', 'QUARANTINED') and (record['released_at'] is None), 'actual_original_owner_gen_CID')
        for key in ('guard_state', 'guard_status'):
            g = actual.get(key)
            need(isinstance(g, dict), 'actual_guard_original_required')
            need(sha(g['raw_utf8'].encode()) == g['SHA256'] and strict(g['raw_utf8']) == g['body'], 'actual_guard_raw_identity')
            m = g['stat']
            need(set(m) == {'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'} and all((type(v) is int for v in m.values())) and (m['st_uid'] == 0) and (m['st_nlink'] == 1) and stat.S_ISREG(m['st_mode']) and (not m['st_mode'] & 18) and (m['st_size'] == len(g['raw_utf8'].encode())), 'actual_guard_Root_F9')
        status = actual['guard_status']['body']
        state = actual['guard_state']['body']
        need(type(status.get('guard_pid')) is int and status['guard_pid'] > 1 and isinstance(state.get('session_id'), str) and (len(state['session_id']) == 32), 'actual_guard_PID_session')
        need((status.get('node'), status.get('profile'), status.get('owner'), status.get('generation'), status.get('container_id')) == (node, 'glm-ab', 'dgx-hx-service', 10, expected_cid), 'actual_same_guard_owner')
        for path, pin in pins.items():
            f = actual['files'][path]
            m = f['stat']
            body = f['raw_utf8'].encode()
            need(sha(body) == f['SHA256'] == pin, 'actual_AB_source_raw_SHA')
            need(m['st_uid'] == 0 and m['st_nlink'] == 1 and stat.S_ISREG(m['st_mode']) and (not m['st_mode'] & 18) and (m['st_size'] == len(body)), 'actual_AB_source_fullstat')
            need(set(m) == {'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'} and all((type(v) is int for v in m.values())), 'actual_AB_exact_F9')
    return {'raw_utf8': raw.decode(), 'sha256': sha(raw), 'native_source_installed_not_inferred_from_configuration': True, 'native_origin_original_times_preserved': True}

def operator_ancestors():
    with HeldParent(OPERATOR_ROOT, legacy=True) as chain:
        chain.recheck()

def acceptance_read():
    path = OPERATOR_ROOT / 'C-parent-acceptance.json'
    with HeldParent(path, legacy=True) as chain:
        s = os.fstat(chain.parent_fd)
        fd = chain.open_leaf()
        try:
            a = os.fstat(fd)
            need(stat.S_ISREG(a.st_mode) and (a.st_uid, a.st_gid, stat.S_IMODE(a.st_mode), a.st_nlink) == (0, 989, 288, 1) and (a.st_size <= 1048576), 'Root_C_original_copy')
            raw = os.pread(fd, a.st_size + 1, 0)
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            need(len(raw) == a.st_size and all((getattr(a, k) == getattr(os.fstat(fd), k) == getattr(chain.named_leaf(), k) for k in fields)), 'C_original_copy_replaced')
            need(sha(raw) == C_ACCEPTANCE_SHA, 'C_original_copy_changed')
            return {'raw_sha256': sha(raw), 'stat': {k: getattr(a, k) for k in fields}, 'directory_stat': {k: getattr(s, k) for k in fields}}
        finally:
            os.close(fd)

def operator_file_state(io):
    raw, info = io.read(OPERATOR_CONFIG)
    need((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink) == (0, 989, 288, 1), 'exact_operator_config_Root_leaf')
    return {'config': {'sha256': sha(raw), 'stat': io.identity(info)}, 'C': acceptance_read()}

def publish_operator(io, raw, acceptance):
    with HeldParent(OPERATOR_ROOT, legacy=True) as ancestry:
        operator_ancestors()
        need(not OPERATOR_ROOT.exists() and (not OPERATOR_ROOT.is_symlink()), 'fresh_operator_directory')
        os.mkdir(OPERATOR_ROOT.name, mode=448, dir_fd=ancestry.parent_fd)
        directory = os.open(OPERATOR_ROOT.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ancestry.parent_fd)
        try:
            os.fchown(directory, 999, 989)
            os.fchmod(directory, 448)
            need(os.fstat(directory) == OPERATOR_ROOT.lstat(), 'created_operator_directory_replaced')
            fd = os.open('C-parent-acceptance.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 288, dir_fd=directory)
            try:
                os.fchown(fd, 0, 989)
                os.fchmod(fd, 288)
                view = memoryview(acceptance)
                while view:
                    n = os.write(fd, view)
                    need(n > 0, 'C_copy_partial_write')
                    view = view[n:]
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
            need(os.fstat(directory) == OPERATOR_ROOT.lstat(), 'operator_directory_changed_during_copy')
        finally:
            os.close(directory)
        io.sync(OPERATOR_ROOT.parent)
        io.fresh(OPERATOR_CONFIG, raw, mode=288, gid=989)
        return operator_file_state(io)

def check_operator_config(io, expected_sha, operation):
    code = "import sys,json;sys.path.insert(0,'/opt/dgx-v4/hx/runtime');from B_OWNER_RECOVERY_R25_WIRING.wiring import load_config; c=load_config();assert c is not None;print(json.dumps({'ok':True,'configuration_sha256':c['_config_sha256'],'operation':c['operation']}))"
    p = io.command(['/usr/bin/setpriv', '--reuid=999', '--regid=989', '--groups=989,1000', '/usr/bin/python3', '-I', '-B', '-c', code], timeout=10)
    need(p.returncode == 0 and (not p.stderr), 'actual_service_UID_activation_check_failed')
    value = strict(p.stdout)
    need(value == {'ok': True, 'configuration_sha256': expected_sha, 'operation': operation}, 'actual_activated_config_identity')
    return {'raw_utf8': p.stdout.decode(), 'sha256': sha(p.stdout), 'observed_at': time.time(), 'Manager_constructed': False}

def observe_operator_socket(pid):
    with HeldParent(OPERATOR_ROOT / 'operator.sock', legacy=True) as ancestry:
        operator_ancestors()
        s = OPERATOR_ROOT.lstat()
        need((s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode)) == (999, 989, 448), 'fixed_operator_directory')
        path = OPERATOR_ROOT / 'operator.sock'
        v = ancestry.named_leaf()
        need(stat.S_ISSOCK(v.st_mode) and (v.st_uid, v.st_gid, stat.S_IMODE(v.st_mode)) == (999, 989, 384), 'sole_service_operator_socket')
        rows = Path('/proc/net/unix').read_text().splitlines()[1:]
        found = [r.split()[6] for r in rows if len(r.split()) == 8 and r.split()[7] == str(path)]
        need(len(found) == 1, 'single_operator_unix_socket')
        fd_paths = list(Path('/proc/' + str(pid) + '/fd').iterdir())
        owned = []
        for p in fd_paths:
            try:
                owned.append(os.readlink(p))
            except FileNotFoundError:
                continue
        need('socket:[' + found[0] + ']' in owned, 'operator_socket_owned_by_new_sole_PID')
        return {'observed_at': time.time(), 'manager_pid': pid, 'path': str(path), 'kernel_inode': found[0], 'requests_sent': 0}

def transaction(io, oldmap, plan, payloads, *, parent_sha, operator_config_raw, acceptance_raw, node_source_proof_raw):
    need(APPROVED_PARENT_SOURCE_REVIEW_SHA256 is not None and parent_sha == APPROVED_PARENT_SOURCE_REVIEW_SHA256, 'installer_review_pending')
    need(len(oldmap) == 114 and len(plan) == 8, 'exact_114_to_118_eight_payloads')
    config = validate_activation_inputs(oldmap, plan, payloads, operator_config_raw, acceptance_raw, parent_sha)
    node_proof = validate_node_source_proof(node_source_proof_raw, config['node_source_pins'], time.time())
    need(not OPERATOR_CONFIG.exists() and (not OPERATOR_CONFIG.is_symlink()) and (not OPERATOR_ROOT.exists()) and (not OPERATOR_ROOT.is_symlink()), 'fresh_operator_namespace_required')
    need(not STATE.exists() and (not RECEIPT.exists()), 'once_namespace_already_exists')
    need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == BOOT, 'same_PC_boot')
    io.original_manager(OLD_PID)
    need([io.lock_identity().st_dev, io.lock_identity().st_ino] == LOCK, 'same_lease_inode')
    semantics = unit_constraints(io)
    files, metas, originals = closure(io, oldmap)
    prior, _ = io.read(OLD_RECEIPT)
    need(sha(prior) == OLD_RECEIPT_SHA and strict(prior)['files'] == oldmap, 'exact_preceding114_receipt')
    before = actual_rows(io)
    idle_gate(before)
    commands = read_command_history()
    for path, row in plan.items():
        need(sha(payloads[path]) == row['sha256'] and oldmap.get(path) == row['old_sha256'], 'payload_scope')
        compile(payloads[path], path, 'exec')
    STATE.mkdir(mode=448)
    io.sync(STATE.parent)

    def record(name, value):
        io.fresh(STATE / (name + '.json'), encode(value))
    record('00-intent', {'parent_source_review_sha256': parent_sha, 'oldPID': OLD_PID, 'old_boot': BOOT, 'source114': files, 'source114_metadata': metas, 'before': before, 'before_command_history': commands, 'unit_semantics': semantics, 'unit': io.unit(), 'observed_at': time.time(), 'node_source_original_proof': node_proof, 'old_epoch_atomic_admission_fence': False, 'cooperative_parent_callers_quiescence_required': True, 'automatic_retry': False})
    stop = 0
    start = 0
    committed = []
    lease = None
    try:
        for index, (path, raw) in enumerate(originals.items()):
            io.fresh(STATE / ('old-source-' + str(index) + '.raw'), raw)
        unit_raw, unit_stat = io.read(io.UNIT_PATH)
        io.fresh(STATE / 'old-unit.raw', unit_raw)
        record('01-backup', {'consistent_DB_backups': backup_databases(io), 'unit_stat': io.identity(unit_stat)})
        io.original_manager(OLD_PID)
        need(closure(io, oldmap)[:2] == (files, metas), 'source_changed_before_stop')
        late = actual_rows(io)
        idle_gate(late)
        same_history_and_holds(before, late)
        need(read_command_history()['canonical_utf8'] == commands['canonical_utf8'], 'command_history_changed_before_stop')
        validate_node_source_proof(node_source_proof_raw, config['node_source_pins'], time.time())
        record('02-stop-intent', {'unit': io.UNIT, 'observed_at': time.time(), 'late_rows': late, 'normal_stop_only': True})
        stop = 1
        p = io.command(['/usr/bin/systemctl', 'stop', io.UNIT], timeout=160)
        record('stop-command', {'returncode': p.returncode, 'stdout': p.stdout.decode(), 'stderr': p.stderr.decode(), 'observed_at': time.time()})
        need(p.returncode == 0, 'normal_stop_failed_partial')
        io.stopped(OLD_PID)
        control = unit_constraints(io)
        need(not control['ControlGroup'], 'stopped_cgroup_empty')
        need(io.read(io.UNIT_PATH) == (unit_raw, unit_stat), 'original_unit_changed_during_stop')
        lease = io.lease()
        stopped = actual_rows(io)
        idle_gate(stopped)
        same_history_and_holds(before, stopped)
        stopped_commands = read_command_history()
        need(stopped_commands['canonical_utf8'] == commands['canonical_utf8'], 'command_history_changed_during_stop')
        need(closure(io, oldmap)[:2] == (files, metas), 'source_changed_during_stop')
        record('03-positive-stopped', {'observed_at': time.time(), 'rows': stopped, 'command_history': stopped_commands, 'unit': io.unit(), 'FLOCK_holders_under_installer_lease': [os.getpid()]})
        package = Path('/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING')
        need(not package.exists() and (not package.is_symlink()), 'new_package_exists')
        package.mkdir(mode=493)
        for index, (path, row) in enumerate(plan.items()):
            pre = None if row['old_sha256'] is None else io.read(Path(path))
            if pre is not None:
                need(sha(pre[0]) == row['old_sha256'] and io.identity(pre[1]) == metas[path], 'leaf_metadata_fence')
            record('leaf-' + str(index) + '-intent', {'target': path, 'old_sha256': row['old_sha256'], 'new_sha256': row['sha256'], 'observed_at': time.time()})
            replace(io, path, payloads[path], pre)
            committed.append(path)
            record('leaf-' + str(index) + '-committed', {'target': path, 'observed_at': time.time(), 'new_sha256': row['sha256']})
        newmap = dict(oldmap)
        newmap.update({k: v['sha256'] for k, v in plan.items()})
        need(len(newmap) == 118, 'exact_new_epoch118')
        newfiles, newmeta, _ = closure(io, newmap)
        need(all((newmeta[k] == metas[k] for k in oldmap if k not in plan)), 'other110_source_fullstat_unchanged')
        record('operator-publication-intent', {'configuration_sha256': sha(operator_config_raw), 'C_raw_sha256': sha(acceptance_raw), 'observed_at': time.time(), 'same_start1': True})
        operator_files = publish_operator(io, operator_config_raw, acceptance_raw)
        config_check = check_operator_config(io, sha(operator_config_raw), config['operation'])
        record('operator-config-check', config_check)
        check = io.command(['/usr/bin/setpriv', '--reuid=999', '--regid=989', '--groups=989,1000', '/usr/bin/python3', '-I', '-B', str(io.BOOT), '--check'], timeout=40)
        record('check', {'rc': check.returncode, 'stdout': check.stdout.decode(), 'stderr': check.stderr.decode(), 'observed_at': time.time()})
        need(check.returncode == 0 and (not check.stderr) and (strict(check.stdout).get('ok') is True), 'new_source_check_refused')
        need(closure(io, newmap)[:2] == (newfiles, newmeta), 'source_changed_during_check')
        need(io.read(io.UNIT_PATH) == (unit_raw, unit_stat), 'original_unit_changed_before_start')
        record('04-start-intent', {'unit': io.UNIT, 'source_count': 118, 'observed_at': time.time()})
        io.release(lease)
        lease = None
        start = 1
        p = io.command(['/usr/bin/systemctl', 'start', io.UNIT], timeout=40)
        record('start-command', {'rc': p.returncode, 'stdout': p.stdout.decode(), 'stderr': p.stderr.decode(), 'observed_at': time.time()})
        need(p.returncode == 0, 'single_start_failed')
        deadline = time.monotonic() + 30
        pid = None
        while time.monotonic() < deadline:
            v = io.unit()
            need(v['ActiveState'] not in ('failed', 'inactive'), 'new_service_terminal')
            current = int(v['MainPID'])
            holders = io.holders()
            need(holders == [] or (current > 1 and current != OLD_PID and (holders == [current])), 'foreign_sole_holder')
            if current > 1 and current != OLD_PID and (v['ActiveState'] == 'active') and (v['SubState'] == 'running') and (holders == [current]):
                io.original_manager(current)
                pid = current
                break
            time.sleep(0.1)
        need(pid is not None, 'new_service_readiness_timeout_no_retry')
        listener = listener_auth(io, pid)
        operator_socket = observe_operator_socket(pid)
        need(operator_file_state(io) == operator_files, 'operator_files_changed_after_start')
        need(io.read(io.UNIT_PATH) == (unit_raw, unit_stat), 'original_unit_changed_after_start')
        after = actual_rows(io)
        idle_gate(after)
        same_history_and_holds(before, after, after_start=True)
        need(read_command_history()['canonical_utf8'] == commands['canonical_utf8'], 'legacy_commands_changed_after_start')
        need(closure(io, newmap)[:2] == (newfiles, newmeta), 'final_epoch_drift')
        result = {'schema': 'PC-B-owner-recovery-source-epoch118/v1', 'observed_at': time.time(), 'files': newfiles, 'metadata': newmeta, 'source_count': 118, 'preceding_receipt_path': str(OLD_RECEIPT), 'preceding_receipt_sha256': OLD_RECEIPT_SHA, 'oldPID': OLD_PID, 'manager_pid': pid, 'boot_id': BOOT, 'lease_dev_inode': LOCK, 'FLOCK_holders': io.holders(), 'unit': io.unit(), 'anonymous_listener': listener, 'before_rows': before, 'after_rows': after, 'original_command_history': commands, 'service_stop_calls': stop, 'service_start_calls': start, 'native_owner_recovery_performed': False, 'operator_activation_enabled': True, 'operator_configuration': operator_files, 'operator_socket': operator_socket, 'parent_source_review_sha256': parent_sha, 'source_activation_review_pending': False, 'source_count_excludes_new_operator_config_and_C_copy': True, 'node_expected_pins_are_not_installation_proof': True, 'historical_requests_preserved': True, 'automatic_retry': False, 'automatic_rollback': False}
        io.fresh(RECEIPT, encode(result))
        record('completed', {'receipt_sha256': sha(encode(result)), 'observed_at': time.time()})
        return result
    except BaseException as exc:
        record('failed', {'error_type': type(exc).__name__, 'reason': str(exc)[:160], 'observed_at': time.time(), 'service_stop_calls': stop, 'service_start_calls': start, 'committed': committed, 'commit_list_may_be_incomplete': True, 'partial_preserved': True, 'automatic_retry': False, 'automatic_rollback': False})
        raise
    finally:
        if lease is not None:
            io.release(lease)

def main():
    print(json.dumps({'status': 'SOURCE_only_inert', 'nativeeligible': False, 'approved_review_sha256': APPROVED_PARENT_SOURCE_REVIEW_SHA256}))
if __name__ == '__main__':
    main()
