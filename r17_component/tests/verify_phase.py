# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Narrow original R16 two-phase semantic cut; no old epoch/Runtime rerun.

Reads immutable existing CPU originals/catalogue in place. Root physical paths,
metadata and original qualified PID here are explicitly inherited CPU fixtures.
The complete original initial consumer and both actual phase/receipt predicates
execute; only the reviewed historical phase cut and Root IO projection differ.
"""
import ast, builtins, copy, hashlib, json, os, pathlib, sys, types
H = pathlib.Path(__file__).resolve().parents[1]
R = H.parent
sys.path.insert(0, str(H))
import derive
seed = (H / 'tests/verify_bridge.py').read_text().split('before=dict(sys.modules)')[0]
namespace = {'__file__': str(H / 'tests/verify_bridge.py'), '__name__': 'r17_explicit_bridge_seed'}
exec(compile(seed, '<explicit-static-bridge-seed>', 'exec'), namespace)
history = namespace['history']
files = namespace['files']
history_prep = namespace['prep']
phase_prep = namespace['load']('r17_phase_prepare', H / 'SOURCE/phase_prepare.py')
S = R / 'R26_R16_FAILED_OWNER_RECOVERY_JOINT_SOURCE_R1'
run = S / 'CPU/OWNER_EIGHTH'
cap = json.loads((run / 'machine-capsule.json').read_bytes())
pc = run / 'PC'
base = S / 'FINAL_GRAPH/PC'
q = json.loads((pc / 'current-source-qualified.json').read_bytes())
installed = json.loads((pc / 'current-installed-original.json').read_bytes())
packet = json.loads((pc / 'epoch-packet.json').read_bytes())
config = json.loads(packet['new_config_raw_utf8'])
config['_config_sha256'] = derive.sha(packet['new_config_raw_utf8'].encode())
assert config['_config_sha256'] == q['current']['config_sha256']
fields = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def physical(path):
    path = str(path)
    matches = [n for n in cap['mapping'] if path == n or path.startswith(n.rstrip('/') + '/')]
    if matches:
        match = max(matches, key=len)
        return pathlib.Path(str(cap['mapping'][match]) + path[len(match):])
    raise KeyError(path)
refs = {str(base): None}
for field in ('noengine_before', 'noengine_after_stop'):
    ref = installed[field]['qualified_ref']
    path = ref['path']
    p = physical(path)
    raw = p.read_bytes()
    assert derive.sha(raw) == ref['sha256']
    files[path] = (raw, ref['stat'])
    v = json.loads(raw)
    for n, rf in [('begin.json', v['begin']), ('finish.json', v['finish'])]:
        body = __import__('base64').b64decode(rf['raw_b64'], validate=True)
        f = rf.get('F9', rf.get('stat'))
        files[str(pathlib.PurePosixPath(path).parent / n)] = (body, f)
    ref = v['context_ref']
    raw = physical(ref['path']).read_bytes()
    assert derive.sha(raw) == ref['sha256']
    files[ref['path']] = (raw, ref['F9'])
    requestpath = str(pathlib.PurePosixPath(path).parent / 'request.json')
    raw = physical(requestpath).read_bytes()
    f = cap['expected'].get(str(physical(requestpath)))
    if f is None:
        f = [getattr(physical(requestpath).stat(), n) for n in fields]
        f[3:7] = [0, 989, 33056, 1]
    files[requestpath] = (raw, f)
root = '/opt/dgx-v4/hx/mimo-registry-r16'
files[root + '/current-installed-original.json'] = ((pc / 'current-installed-original.json').read_bytes(), q['installed_mirror']['stat'])
files[root + '/epoch-scope/worker.py'] = (physical(root + '/epoch-scope/worker.py').read_bytes(), q['scope_sources']['worker.py']['stat'])
files[root + '/epoch-scope/loader.py'] = (physical(root + '/epoch-scope/loader.py').read_bytes(), q['scope_sources']['loader.py']['stat'])
read_trace = []

def read(path, *, limit=2097152, owner=0):
    key = str(path)
    if key in files:
        raw, f = files[key]
    else:
        target = physical(key)
        raw = target.read_bytes()
        f = cap['expected'].get(str(target))
        if f is None:
            f = [getattr(target.stat(), n) for n in fields]
            f[3:7] = [0, 989, 33056, 1]
        files[key] = (raw, f)
    assert len(raw) <= limit, (key, len(raw), limit)
    read_trace.append(key)
    return (raw, list(f))
common_path = '/opt/dgx-v4/hx/runtime/B_OWNER_RECOVERY_R25_WIRING/common.py'
common_raw, _ = read(common_path)
common = types.ModuleType('B_OWNER_RECOVERY_R25_WIRING.common')
common.__file__ = common_path
exec(compile(common_raw, common_path, 'exec'), common.__dict__)
common.protected_read = read
package = types.ModuleType('B_OWNER_RECOVERY_R25_WIRING')
package.common = common
saved = {n: sys.modules.get(n) for n in (package.__name__, common.__name__)}
sys.modules[package.__name__] = package
sys.modules[common.__name__] = common
original_phase = derive.original('pc/r11-gate/phase_history.py')
new_phase = derive.phase_history(original_phase)

def compilation(raw, filename, *args, **kwargs):
    if raw == original_phase and str(filename).endswith('/phase_history.py'):
        raw = new_phase
    return builtins.compile(raw, filename, *args, **kwargs)
gate_raw = derive.gate_loader(derive.original('pc/r11-gate/gate_loader.py'))
gate = types.ModuleType('R17_candidate_gate')
gate.__file__ = root + '/pc/r11-gate/gate_loader.py'
gate.__dict__['__builtins__'] = dict(vars(builtins), compile=compilation)
exec(compile(gate_raw, gate.__file__, 'exec'), gate.__dict__)
contract = types.ModuleType('r17_real_contract')
exec(compile((base / 'contract.py').read_bytes(), str(base / 'contract.py'), 'exec'), contract.__dict__)
managed = types.ModuleType('r17_real_managed_scope')
managed.__dict__.update(vars(contract))
managed_raw = (base / 'service/managed_scope.py').read_bytes()
tree = ast.parse(managed_raw)
tree.body = [n for n in tree.body if not isinstance(n, ast.ImportFrom)]
exec(compile(tree, str(base / 'service/managed_scope.py'), 'exec'), managed.__dict__)
ancestor_ast = ast.parse((base / 'service/ancestor.py').read_bytes())
fn = next((n for n in ancestor_ast.body if isinstance(n, ast.FunctionDef) and n.name == 'root'))
scope = dict(vars(contract))
exec(compile(ast.Module(body=[fn], type_ignores=[]), '<real ancestor.root>', 'exec'), scope)
current_raw = derive.current_epoch(derive.original('service/current_epoch.py'))
ct = ast.parse(current_raw)
selected = [n for n in ct.body if isinstance(n, ast.Assign) or (isinstance(n, ast.FunctionDef) and n.name == 'consume_initial')]
context = dict(vars(contract), root=scope['root'], positive=managed.positive)
exec(compile(ast.Module(body=selected, type_ignores=[]), str(base / 'service/current_epoch.py'), 'exec'), context)
try:
    bridge = history_prep.prepare_bridge(read, history, config)
    token = phase_prep.prepare(read, config, q['current']['manager_identity'], q['observed_at'] + 1, context['consume_initial'], gate, bridge, history_prep.restore_bridge)
    count = len(read_trace)
    value = token.installation(read, config)
    assert value['historical_only'] and value['initial_identity'] == q['current']['manager_identity']
    assert value['source_qualified_sha256'] == derive.sha((pc / 'current-source-qualified.json').read_bytes())
    assert len(read_trace) > count
    key = next((p for p in token.dependencies if p.endswith('/gate_loader.py')))
    raw, f = files[key]
    bad = list(f)
    bad[1] += 1
    files[key] = (raw, bad)
    try:
        token.installation(read, config)
    except phase_prep.PhasePreparationRefused as e:
        assert str(e) == 'prepared_installation_fresh_dependency_fullSHA_F9'
        reason = str(e)
    else:
        raise AssertionError('changed source inode accepted')
    files[key] = (raw, f)
    result = {'prepare_real_consume_initial': True, 'complete_original_phase_receipt_validators': 2, 'prepared_dependency_leaves': len(token.dependencies), 'bridge_dependency_leaves': len(bridge.dependency_refs), 'hot_use_fresh_reads': len(token.dependencies), 'new_inode_samebytes_refused': reason, 'pure_history_only': True, 'live_actor_lease_current_authority': False, 'native': 0}
    (H / 'PHASE_RESULT.json').write_bytes(phase_prep.encode(result))
    print(json.dumps(result, sort_keys=True))
finally:
    for n, v in saved.items():
        if v is None:
            sys.modules.pop(n, None)
        else:
            sys.modules[n] = v
