# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Real Stages cold constructor on original complete historical catalogue.
No Runtime/Manager/adapter or old epoch launch; role/proc/F9 are CPU suppliers.
"""
import ast, base64, builtins, copy, hashlib, json, os, pathlib, sys, threading, types, unittest
H = pathlib.Path(__file__).resolve().parents[1]
R = H.parent
S = R / 'R26_R16_FAILED_OWNER_RECOVERY_JOINT_SOURCE_R1'
P = R / 'parent_checks/R25_RESUME/R26_R11_R3_FIRST_SUFFIX_PARENT'
sys.path[:0] = [str(H), str(S), str(S / 'recipes')]
import derive, cpu_world_r16
F = sys.modules['cpu_fs']
ServiceOS = sys.modules['cpu_runtime'].ServiceOS
cap = json.loads((S / 'CPU/OWNER_EIGHTH/machine-capsule.json').read_bytes())
fs = F.FS({k: pathlib.Path(v) for k, v in cap['mapping'].items()})
fs.expected = copy.deepcopy(cap['expected'])
RootPath = fs.rootpath()
role = ServiceOS(fs)

def listdir(path='.'):
    logical = fs.logical[path] if isinstance(path, int) else str(path)
    physical = fs.path(logical)
    names = set(os.listdir(physical))
    prefix = logical.rstrip('/') + '/'
    for source in fs.mapping:
        if source.startswith(prefix):
            tail = source[len(prefix):]
            if tail:
                names.add(tail.split('/', 1)[0])
    return sorted(names)
fs.listdir = listdir
RootPath.iterdir = lambda path: iter((path / name for name in listdir(str(path))))
q = json.loads((S / 'CPU/OWNER_EIGHTH/PC/current-source-qualified.json').read_bytes())
pid = q['current']['manager_identity']['pid']
original_read_text = RootPath.read_text
RootPath.read_text = lambda p, *a, **kw: '1: FLOCK ADVISORY WRITE ' + str(pid) + ' ' + f'{os.major(2096):02x}:{os.minor(2096):02x}:69257' + ' 0 EOF\n' if str(p) == '/proc/locks' else original_read_text(p, *a, **kw)
clock = types.SimpleNamespace(time=lambda: q['observed_at'] + 100, monotonic=lambda: 100.0)

class Machine:
    packet = cap['packet']
    R = RootPath
    W_RUNTIME = pathlib.Path('/opt/dgx-v4/hx/runtime')

    def execute(self, code, ns=None, *args):
        if ns is None:
            frame = sys._getframe(1)
            ns = frame.f_globals
            if not args:
                args = (frame.f_locals,)
        builtins.exec(code, ns, *args)
        for name in ('os', 'owner_os', 'epoch_os', 'old_os'):
            if name in ns:
                ns[name] = role
        for name in ('Path', 'owner_Path', 'old_Path', 'prefile_Path'):
            if name in ns:
                ns[name] = RootPath
        for name in ('time', 'owner_time'):
            if name in ns:
                ns[name] = clock
        if 'epoch_pathlib' in ns:
            ns['epoch_pathlib'] = types.SimpleNamespace(Path=RootPath)
        ns['exec'] = self.execute
        for name, value in list(ns.items()):
            if isinstance(value, pathlib.Path) and str(value).startswith(('/opt/', '/etc/', '/srv/', '/proc/', '/sys/')):
                ns[name] = RootPath(str(value))

    def read(self, p, limit=2097152, **kw):
        return self.common.protected_read(RootPath(p), limit=limit, **kw)
w = Machine()
w.fs = fs
common_path = '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/common.py'
common = types.ModuleType('B_OWNER_RECOVERY_R25_WIRING.common')
common.__file__ = common_path
w.execute(compile(pathlib.Path(fs.path(common_path)).read_bytes(), common_path, 'exec'), common.__dict__)
pkg = types.ModuleType('B_OWNER_RECOVERY_R25_WIRING')
pkg.__file__ = '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/__init__.py'
pkg.__path__ = ['/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING']
pkg.common = common
pkg.__package__ = pkg.__name__
sys.modules[pkg.__name__] = pkg
sys.modules[common.__name__] = common
w.common = common
from actual118 import Held118
loader = Held118(w)
safety = '/opt/dgx-v4/hx/scripts/safety_contract.py'
safe_raw = w.read(safety)[0]
assert derive.sha(safe_raw) == json.loads(cap['packet']['new_config_raw_utf8'])['PC_source_pins'][safety]
safe = types.ModuleType('safety_contract')
safe.__file__ = safety
w.execute(compile(safe_raw, safety, 'exec'), safe.__dict__)
sys.modules[safe.__name__] = safe
loader.load('hx_service.service')
loader.load('B_OWNER_RECOVERY_R25_WIRING.collector')
wire = loader.load('B_OWNER_RECOVERY_R25_WIRING.wiring')
packet = cap['packet']
tree = ast.parse(packet['wire_raw_utf8'])
fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_registry_callbacks'))
stage_before = derive.original('service/asset_stage.py')
stage_after = derive.stages(stage_before)
real_compile = builtins.compile
cold = (H / 'SOURCE/owner_cold.py').read_bytes()

def compile_candidate(raw, filename, *a, **kw):
    if raw == stage_before and str(filename).endswith('/service/asset_stage.py'):
        raw = stage_after
    if str(filename).endswith('/service/history_reader.py') and type(raw) is bytes and (derive.sha(raw) == '2273f86b869adc45ef2cb81b3cf9db4906497de40eb548af264eeacdecc08aa8'):
        raw = raw + b'\n' + cold
    return real_compile(raw, filename, *a, **kw)
wire.__dict__['__builtins__']['compile'] = compile_candidate
real_import = wire.__dict__['__builtins__']['__import__']
private_builtins = types.ModuleType('builtins')
private_builtins.__dict__.update(vars(builtins))
private_builtins.compile = compile_candidate
wire.__dict__['__builtins__']['__import__'] = lambda name, g=None, l=None, fromlist=(), level=0: private_builtins if name == 'builtins' and (not level) else real_import(name, g, l, fromlist, level)
wire.REGISTRY_HELPER_CACHE = None
cb = wire._registry_callbacks()
Stage = cb.Grant.__init__.__globals__['Stages']
hr = Stage.__init__.__globals__['epoch_asset_history_bridge']
assert hasattr(hr, 'owner_converged_cold')
root = str(Stage.__init__.__defaults__[-1])
native = json.loads((P / 'R15-d46e-family-actor-history-protected-read-r2-once/complete-actor-history.raw.json').read_bytes())
stage = hr.owner_policy()['stage']
before = native['actors'][stage]
out = H / ('CPU_COLD_' + (sys.argv[1] if len(sys.argv) > 1 else 'THIRD'))
out.mkdir(mode=448)
logical = root + '/' + stage
physical = out / 'actor'
physical.mkdir(mode=448)
physical.chmod(448)
for key in list(fs.mapping):
    if key == logical or key.startswith(logical + '/'):
        fs.mapping.pop(key)
fs.mapping[logical] = physical
for name, row in before['rows'].items():
    target = physical / name
    target.write_bytes(base64.b64decode(row['raw_b64'], validate=True))
    target.chmod(384)
    fs.expected[str(target)] = row['F9']
f = list(before['directory_F9'])
fs.expected[str(physical)] = f
pending_actor_names = set(before['rows'])
shared = '/opt/dgx-v4/hx/runtime/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/shared_scheduler.py'
raw = w.read(shared)[0]
ts = ast.parse(raw)
restore = next((n for n in ast.walk(ts) if isinstance(n, ast.FunctionDef) and n.name == 'restore_operator_block'))
ns = {}
exec(compile(ast.Module(body=[restore], type_ignores=[]), shared, 'exec'), ns)
lock = threading.RLock()
sched = types.SimpleNamespace(_lock=lock, _cv=threading.Condition(lock), _operator_maintenance=True)
sched.restore_operator_block = types.MethodType(ns['restore_operator_block'], sched)
config = json.loads(packet['new_config_raw_utf8'])
config['_config_sha256'] = derive.sha(packet['new_config_raw_utf8'].encode())
pc_raw = (S / 'FINAL_GRAPH/PC/pc/r11-gate/pc_recovery.py').read_bytes()
nt = ast.parse(pc_raw)
same = next((n for n in nt.body if isinstance(n, ast.FunctionDef) and n.name == 'lease_same'))
sx = {'Path': RootPath, 'os': role, 'HeldParent': common.HeldParent, 'metadata': common.metadata, 'need': common.need}
exec(compile(ast.Module(body=[same], type_ignores=[]), '<real physical lease_same>', 'exec'), sx)
import importlib.util
spec = importlib.util.spec_from_file_location('R17_cold_actual_journal', H / 'SOURCE/owner_decision.py')
journal_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journal_module)
journal_module.SERVICE_UID = os.getuid()
journal_module.SERVICE_GID = os.getgid()
journal_parent = out / 'decision-parent'
journal_parent.mkdir(mode=448)
journal_parent.chmod(448)
parent_fd = os.open(journal_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
journal = journal_module.Journal(parent_fd, '7' * 32)
try:
    journal.prepare({'operation': '7' * 32, 'stage': stage, 'prepared_closure_sha256': '0' * 64, 'initial_identity': q['current']['manager_identity'], 'original_deadline_monotonic': 1.0, 'old_terminal_sha256': hr.owner_policy()['old_terminal']['sha256']})
    bad_fd = os.open('decision.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 384, dir_fd=journal.fd)
    try:
        os.write(bad_fd, b'{')
        os.fchmod(bad_fd, 384)
        os.fsync(bad_fd)
    finally:
        os.close(bad_fd)
    os.fsync(journal.fd)
finally:
    os.close(parent_fd)
recovery = types.SimpleNamespace(owner_decision_state=journal.classify)
g = types.SimpleNamespace(config=config, s=sched, same=lambda: sx['lease_same'](pid), lock=threading.Lock(), runtime=types.SimpleNamespace(manager=types.SimpleNamespace(_now=clock.time)), prelaunch_recovery=recovery)
partial = physical / 'completed.json'
partial.write_bytes(b'{')
partial.chmod(384)
meta = [getattr(partial.stat(), n) for n in F.FIELDS]
meta[3:5] = [999, 989]
fs.expected[str(partial)] = meta
try:
    result = Stage(g, lambda *a, **kw: (_ for _ in ()).throw(AssertionError('unexpected current terminal call')), read=w.read, root=RootPath(root))
except BaseException as error:
    tb = error.__traceback__
    details = []
    while tb:
        frame = tb.tb_frame
        if frame.f_code.co_name == 'held_actor':
            loc = frame.f_locals
            details.append({k: str(loc[k]) if k == 'path' else loc[k] for k in ('path', 'expected', 'before', 'names') if k in loc})
        tb = tb.tb_next
    (out / 'ACTUAL-FIXTURE-FAILURE.json').write_text(json.dumps({'class': type(error).__name__, 'fixed_reason': str(error), 'actor': details}, sort_keys=True, indent=2) + '\n')
    raise
assert result.closed and result.failed_owner_pending is not None and sched._operator_maintenance and (result.owner_decision_diagnostic['state'] == 'UNKNOWN_HELD')
assert len(result.used) == 4 and partial.read_bytes() == b'{' and (result.active is None)
(H / 'COLD_RESULT.json').write_bytes(common.encode({'real_complete_Stages_ctor': True, 'actual_Journal_classify': True, 'real_owner_pending_and_old_terminal': True, 'partial_projection_preserved': True, 'state': result.owner_decision_diagnostic, 'used_count': len(result.used), 'no_Runtime_Manager': True, 'finish_calls': 0, 'role_FS_proc_F9': 'explicit CPU projection', 'native': 0}))
print(json.dumps({'cold': 'UNKNOWN_HELD', 'real_Stages': True, 'used': len(result.used), 'native': 0}))
