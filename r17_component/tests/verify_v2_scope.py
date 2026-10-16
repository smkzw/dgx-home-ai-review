# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""New simulated v2 event through real permit/BEGIN/A collector/finish/fresh.
No Runtime, Manager, installed output, old phase, native clock or network. The
R16 module/FS catalogue is read only; all new records and A CPU tree live here.
"""
import ast, base64, builtins, copy, json, os, pathlib, subprocess, sys, time, types
H = pathlib.Path(__file__).resolve().parents[1]
R = H.parent
S = R / 'R26_R16_FAILED_OWNER_RECOVERY_JOINT_SOURCE_R1'
seed = (H / 'tests/verify_cold.py').read_text().split('# Fresh exact actor reader')[0]
ns = {'__file__': str(H / 'tests/verify_cold.py'), '__name__': 'R17_v2_scope_definition_seed'}
exec(compile(seed, '<exact-cold-definition-seed>', 'exec'), ns)
sys.path.insert(0, str(H))
import scope_v2
w = ns['w']
fs = ns['fs']
hr = ns['hr']
q = ns['q']
pid = ns['pid']
RPath = ns['RootPath']
role = ns['role']
derive = ns['derive']
fs.mapping['/proc/self'] = pathlib.Path(fs.path('/proc/' + str(pid)))
fs.getpid = lambda: pid
fs.environ = {'INVOCATION_ID': q['current']['manager_identity']['invocation_id']}
label = sys.argv[1] if len(sys.argv) > 1 else 'FIRST'
out = H / ('CPU_V2_SCOPE_' + label)
out.mkdir(mode=448)
nonce = 'e3f0db75d5b0c39cbddfd4f05130b622'
plan, scope = scope_v2.materialize_cpu(nonce)
(out / 'SCOPE_PINS.json').write_text(json.dumps({'pins': plan['pins'], 'worker_sha256': plan['worker_sha256'], 'body_sha256': plan['body_sha256'], 'actual': None, 'native': 0}, sort_keys=True, indent=2) + '\n')
p = copy.deepcopy(hr.owner_policy())
logical = '/opt/dgx-v4/hx/R17-CPU-owner-data-' + nonce
physical = out / 'PC-originals'
physical.mkdir(mode=488)
physical.chmod(488)
fs.mapping[logical] = physical
z = physical.lstat()
f = [getattr(z, k) for k in ns['F'].FIELDS]
f[3:6] = [0, 989, 16872]
fs.expected[str(physical)] = f
p.update(permit_path=logical + '/permit.json', qualified_path=logical + '/qualified.json', probe_nonce=nonce, probe_unit=plan['unit'], probe_worker_sha=plan['worker_sha256'])

def private(name, root_role):
    m = types.ModuleType(name)
    m.__dict__.update(hr.__dict__)
    for key, value in list(m.__dict__.items()):
        if isinstance(value, types.FunctionType) and key.startswith('owner_'):
            m.__dict__[key] = types.FunctionType(value.__code__, m.__dict__, value.__name__, value.__defaults__, value.__closure__)
    m.owner_APPROVED_POLICY = copy.deepcopy(p)
    m.owner_os = fs if root_role else role
    w.execute(compile(derive.clock_delta(derive.original('service/history_reader.py')), '<exact-copied-v2-clock-delta>', 'exec'), m.__dict__)
    m.owner_os = fs if root_role else role
    return m
root = private('R17_Root_v2_functions', True)
service = private('R17_service_v2_functions', False)
config = json.loads(ns['packet']['new_config_raw_utf8'])
config['_config_sha256'] = derive.sha(ns['packet']['new_config_raw_utf8'].encode())
identity = q['current']['manager_identity']
A = out / 'A'
A.mkdir()
wall = q['observed_at'] + 200
seal = A / 'SEAL.json'
seal.write_bytes(hr.owner_encode({'current': {'review_sha256': p['new_review'], 'config_sha256': config['_config_sha256'], 'manager_identity': identity, 'source118': config['PC_source_pins']}, 'wall': wall - 0.55, 'phase': {'root': plan['root']}, 'commands': [['seal', scope.A_seal(plan)]]}))
child = S / 'cpu_owner_child_r16.py'
r = subprocess.run([sys.executable, '-I', '-B', str(child), 'seal', str(seal)], capture_output=True, timeout=35)
(A / 'seal.stdout').write_bytes(r.stdout)
(A / 'seal.stderr').write_bytes(r.stderr)
assert r.returncode == 0, r.stderr.decode()
start = time.monotonic()
clock = types.SimpleNamespace(time=lambda: wall + time.monotonic() - start, monotonic=lambda: 100.0 + time.monotonic() - start)
root.owner_time = service.owner_time = clock

def write(path, raw, *, mode, gid):
    assert str(path).startswith(logical + '/') and mode == 288 and (gid == 989)
    target = pathlib.Path(fs.path(path))
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    f = [getattr(target.lstat(), k) for k in ns['F'].FIELDS]
    f[3:5] = [0, 989]
    fs.expected[str(target)] = f
permit = root.owner_permit_v2(w.read, write, config, identity)
begin = root.owner_begin_v2(w.read, write)
(A / 'RUN.json').write_bytes(hr.owner_encode({'code': scope.A_run(plan, hr.owner_encode({'request_raw_b64': begin['request_raw_b64'], 'PC_begin_original': begin['PC_begin_original']}))}))
r = subprocess.run([sys.executable, '-I', '-B', str(child), 'run', str(A / 'RUN.json')], capture_output=True, timeout=35)
(A / 'run.stdout').write_bytes(r.stdout)
(A / 'run.stderr').write_bytes(r.stderr)
assert r.returncode == 0, r.stderr.decode()
origin = json.loads(r.stdout)
finish = root.owner_finish_v2(w.read, write, origin['A_original'], origin['scope'])
native = json.loads((ns['P'] / 'R15-d46e-family-actor-history-protected-read-r2-once/complete-actor-history.raw.json').read_bytes())
record = native['actors'][p['stage']]
rows = {n: base64.b64decode(v['raw_b64'], validate=True) for n, v in record['rows'].items()}
stats = {n: v['F9'] for n, v in record['rows'].items()}
pend = service.owner_pending(w.read, rows, stats, p)
g = types.SimpleNamespace(config=config, clock=clock.monotonic, runtime=types.SimpleNamespace(manager=types.SimpleNamespace(_now=clock.time)))
body = {'action': 'activate-registry-source', 'operation': ns['packet']['operation'], 'request_nonce': '32e5470b3ef18a7ad6163315e7dc2ea3'}
eligibility = service.owner_fresh_v2(w.read, p, g, pend, body, clock.time())
assert eligibility['schema'] == 'failed-owner-terminal-release-eligibility/v2'
assert service.owner_fresh_v2(w.read, p, g, pend, None, eligibility['observed_at'], historical=True, event=eligibility) == eligibility
final = service.owner_final_clock_v2(eligibility, g)
(out / 'V2_ORIGINALS.json').write_bytes(hr.owner_encode({'permit': permit, 'begin': begin, 'finish': finish, 'eligibility': eligibility, 'policy': p, 'current': identity, 'config': config, 'Root_clock': {'wall_origin': wall, 'monotonic_origin': 100.0}, 'actual_CPU_elapsed': time.monotonic() - start, 'final_clock': final, 'native': 0}))
result = {'new_simulated_v2_actual_producers': ['permit', 'BEGIN', 'A_worker_scope_observer_ownedstop', 'PC_finish', 'eligibility'], 'original_v1_records_changed': 0, 'fresh_and_historical_event_equal': True, 'A_scope_worker_sha256': plan['worker_sha256'], 'A_body_sha256': plan['body_sha256'], 'PC_sameboot_direct_mono': final, 'actual_CPU_elapsed': time.monotonic() - start, 'Root_FS_A_kernel_ownership': 'explicit existing CPU suppliers', 'Runtime': 0, 'Manager': 0, 'native': 0}
(H / ('V2_SCOPE_' + label + '_RESULT.json')).write_bytes(hr.owner_encode(result))
print(json.dumps(result, sort_keys=True))
