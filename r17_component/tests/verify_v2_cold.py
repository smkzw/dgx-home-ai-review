# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Saved real v2 CPU event -> Journal -> Recovery/original Stages, no new scope.
Only OS UID/proc/FD-F9 mapping and original scheduler initial fields are supplied.
No Runtime/Manager construction, current resource authority or native timing.
"""
import ast, base64, builtins, copy, hashlib, importlib.util, json, os, pathlib, sys, threading, types
H = pathlib.Path(__file__).resolve().parents[1]
seed = (H / 'tests/verify_cold.py').read_text().split('# Fresh exact actor reader')[0]
ns = {'__file__': str(H / 'tests/verify_cold.py'), '__name__': 'R17_v2_cold_seed'}
exec(compile(seed, '<exact existing cold definition seed>', 'exec'), ns)
w, fs, hr, Stage, role, RootPath = (ns[k] for k in ('w', 'fs', 'hr', 'Stage', 'role', 'RootPath'))
ev = json.loads((H / 'CPU_V2_SCOPE_FIRST/V2_ORIGINALS.json').read_bytes())
assert ev['native'] == 0
label = sys.argv[1] if len(sys.argv) > 1 else 'FIRST'
out = H / ('CPU_V2_COLD_' + label)
out.mkdir(mode=448)
inputs = {str(f.relative_to(H)): {'sha256': hashlib.sha256(f.read_bytes()).hexdigest(), 'bytes': f.stat().st_size} for f in [*list((H / 'SOURCE').glob('*.py')), H / 'derive.py', pathlib.Path(__file__)]}
(out / 'LOADED_SOURCE_PINS.json').write_text(json.dumps(inputs, sort_keys=True, indent=2) + '\n')
logical = str(pathlib.PurePosixPath(ev['policy']['permit_path']).parent)
physical = H / 'CPU_V2_SCOPE_FIRST/PC-originals'
fs.mapping[logical] = physical
refs = [ev['permit'], ev['begin']['request_original'], ev['begin']['send_moment_original'], ev['finish']['qualified_original']]
qraw = json.loads((physical / 'qualified.json').read_bytes())
refs += [qraw['received_original']]
for ref in refs:
    raw = (physical / pathlib.PurePosixPath(ref['path']).name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == ref['sha256'] and len(raw) == ref['F9'][2]
    fs.expected[str(physical / pathlib.PurePosixPath(ref['path']).name)] = ref['F9']
original_projected = fs.projected
private_roots = []

def projected(z, path):
    value = original_projected(z, path)
    if any((str(path) == r or str(path).startswith(r + '/') for r in private_roots)) and str(path) not in fs.expected:
        value.st_uid = 999
        value.st_gid = 989
    return value
fs.projected = projected
original_dup = os.dup

def dup(fd):
    value = original_dup(fd)
    fs.fds[value] = fs.fds[fd]
    fs.logical[value] = fs.logical[fd]
    return value
fs.dup = dup

def mkdir(name, mode=511, *, dir_fd=None):
    path = str(name) if str(name).startswith('/') else fs.logical[dir_fd].rstrip('/') + '/' + str(name)
    dest = pathlib.Path(fs.path(path))
    assert str(dest).startswith(str(out) + '/')
    return os.mkdir(dest, mode)
fs.mkdir = mkdir
fs.getpid = lambda: ev['current']['pid']
fs.environ = {'INVOCATION_ID': ev['current']['invocation_id']}
fs.mapping['/proc/self'] = pathlib.Path(fs.path('/proc/' + str(ev['current']['pid'])))

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
j = load('R17_v2_cold_decision', H / 'SOURCE/owner_decision.py')
pr = load('R17_v2_cold_projection', H / 'SOURCE/owner_projection.py')
j.os = pr.os = role
owned_builtins = hr.__dict__['__builtins__']
old_import = owned_builtins['__import__']

def imports(name, g=None, l=None, fromlist=(), level=0):
    if not level and name in ('owner_decision', 'owner_projection'):
        return {'owner_decision': j, 'owner_projection': pr}[name]
    value = old_import(name, g, l, fromlist, level)
    return role if name == 'os' and (not level) else value
owned_builtins['__import__'] = imports
w.execute(compile(ns['derive'].clock_delta(ns['derive'].original('service/history_reader.py')), '<v2 producers/consumer delta>', 'exec'), hr.__dict__)
w.execute(compile((H / 'SOURCE/owner_state.py').read_bytes(), '<candidate owner state>', 'exec'), hr.__dict__)
hr.owner_APPROVED_POLICY = copy.deepcopy(ev['policy'])
hr.owner_DECISION_POLICY = {'parent': str(pathlib.PurePosixPath(ev['policy']['activation_root']).parent / ('owner-decisions-' + ev['policy']['probe_operation'])), 'operation': ev['policy']['probe_nonce'], 'prepared_closure_sha256': '0' * 64}
raw = w.read('/opt/dgx-v4/hx/runtime/G8_INTEGRATION_RUNTIME_CANDIDATE_R2/shared_scheduler.py')[0]
tree = ast.parse(raw)
methods = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in ('restore_operator_block', 'finish_operator_maintenance')}
sx = {}
exec(compile(ast.Module(body=list(methods.values()), type_ignores=[]), '<original scheduler methods>', 'exec'), sx)
root = str(Stage.__init__.__defaults__[-1])
stage = hr.owner_policy()['stage']
p = hr.owner_policy()
native = json.loads((ns['P'] / 'R15-d46e-family-actor-history-protected-read-r2-once/complete-actor-history.raw.json').read_bytes())
old = native['actors'][stage]
lease_raw = (ns['S'] / 'FINAL_GRAPH/PC/pc/r11-gate/pc_recovery.py').read_bytes()
fn = next((n for n in ast.parse(lease_raw).body if isinstance(n, ast.FunctionDef) and n.name == 'lease_same'))
lx = {'Path': RootPath, 'os': role, 'HeldParent': w.common.HeldParent, 'metadata': w.common.metadata, 'need': w.common.need}
exec(compile(ast.Module(body=[fn], type_ignores=[]), '<original actual lease_same>', 'exec'), lx)
Recovery = ns['cb'].Grant.__init__.__globals__['Recovery']

def cold_method(self, stages):
    return hr.owner_restore_decision_cold(self, stages)
Recovery.owner_decision_cold = cold_method
config = ev['config']
results = []
finishes = []

def run(case, kind):
    folder = out / case
    folder.mkdir(mode=448)
    for name in ('actor', 'source-base', 'journal-parent'):
        (folder / name).mkdir(mode=448)
        (folder / name).chmod(448)
    private_roots.append(str(folder))
    for prefix, target in ((root + '/' + stage, folder / 'actor'), (p['activation_root'], folder / 'source-base'), (hr.owner_DECISION_POLICY['parent'], folder / 'journal-parent')):
        for key in list(fs.mapping):
            if key == prefix or key.startswith(prefix + '/'):
                fs.mapping.pop(key)
        fs.mapping[prefix] = target
    for name, row in old['rows'].items():
        leaf = folder / 'actor' / name
        leaf.write_bytes(base64.b64decode(row['raw_b64'], validate=True))
        leaf.chmod(384)
        fs.expected[str(leaf)] = row['F9']
    d = [getattr((folder / 'actor').lstat(), k) for k in ns['F'].FIELDS]
    d[3:5] = [999, 989]
    fs.expected[str(folder / 'actor')] = d
    lock = threading.RLock()
    scheduler = types.SimpleNamespace(_lock=lock, _cv=threading.Condition(lock), _operator_maintenance=True, _operator_tick_inflight=0, _creative=None, _operator_creative_pulse_inflight=0, _operator_public_inflight=0, _infos={}, _active={}, _ensuring={}, _dispatch_checks={}, _ready={}, _resident={}, _generation={}, _model_id={}, _health={})
    for key, fn in sx.items():
        if callable(fn):
            scheduler.__dict__[key] = types.MethodType(fn, scheduler)
    g = types.SimpleNamespace(config=config, s=scheduler, same=lambda: lx['lease_same'](ev['current']['pid']), lock=threading.Lock(), runtime=types.SimpleNamespace(manager=types.SimpleNamespace(_now=lambda: ev['eligibility']['observed_at'] + 100)), operator=types.SimpleNamespace(negative_cpu_release=types.SimpleNamespace(pending=True)))
    recovery = Recovery(g)
    g.prelaunch_recovery = recovery
    with hr.owner_decision_context() as journal:
        binding = {'operation': p['probe_nonce'], 'stage': stage, 'prepared_closure_sha256': '0' * 64, 'initial_identity': ev['current'], 'original_deadline_monotonic': ev['eligibility']['original_deadline_monotonic'], 'old_terminal_sha256': p['old_terminal']['sha256']}
        journal.prepare(binding)
        recipe = {'schema': 'owner-projection-recipe/v2', 'operation': p['probe_nonce'], 'stage': stage, 'old_terminal': p['old_terminal'], 'original_deadline_monotonic': binding['original_deadline_monotonic'], 'release_clock': ev['final_clock'], 'request': {'action': 'activate-registry-source', 'operation': p['probe_operation'], 'request_nonce': ev['eligibility']['activation_request_nonce']}, 'qualification': {'CPU_saved_scope_event': ev['finish']}, 'prior': {}, 'legacy_original': {}, 'eligibility': ev['eligibility'], 'current': {'CPU_only_no_resource_authority': True}, 'recorded_at': ev['eligibility']['observed_at']}
        if kind != 'unknown':

            def finish():
                scheduler.finish_operator_maintenance()
                finishes.append(case)
            journal.commit({'binding': binding, 'recipe': recipe}, lambda: copy.deepcopy(ev['final_clock']), finish, scheduler.restore_operator_block)
            scheduler.restore_operator_block()
            wanted = pr.render(recipe, hr.owner_held(w.read, p['old_terminal'], [0, 989, 33056, 1]), ev['final_clock'])
            if kind == 'complete':
                inv = ev['current']['invocation_id']
                (folder / 'source-base' / inv).mkdir(mode=448)
                with hr.owner_private_directory(root + '/' + stage, base=root) as actor:
                    with hr.owner_private_directory(p['activation_root'] + '/' + inv, base=p['activation_root']) as source:
                        pr.project(journal, actor, source, recipe, hr.owner_held(w.read, p['old_terminal'], [0, 989, 33056, 1]), set(p['old_records']))
            elif kind == 'missing_projection':
                leaf = folder / 'actor/completed.json'
                leaf.write_bytes(wanted['actor']['completed.json'])
                leaf.chmod(384)
            elif kind == 'broken_witness':
                leaf = folder / 'journal-parent' / p['probe_nonce'] / 'durability-witness.json'
                leaf.write_bytes(b'{')
                leaf.chmod(384)
        else:
            leaf = folder / 'journal-parent' / p['probe_nonce'] / 'decision.json'
            leaf.write_bytes(b'{')
            leaf.chmod(384)
    for directory in (folder / 'actor',):
        value = [getattr(directory.lstat(), k) for k in ns['F'].FIELDS]
        value[3:5] = [999, 989]
        fs.expected[str(directory)] = value
    (folder / 'BEFORE_CTOR.json').write_bytes(w.common.encode({'kind': kind, 'physical_finishes_before_cold': len(finishes), 'new_source_fence_initial': scheduler._operator_maintenance, 'negative_pending': g.operator.negative_cpu_release.pending, 'Recovery_released': recovery.released}))
    before_finishes = len(finishes)
    if label == 'DIAGNOSTIC':
        view = types.SimpleNamespace(g=g, root=RootPath(root), read=w.read, used=[])
        with lock:
            print(hr.owner_restore_decision_cold(recovery, view))
        raise SystemExit(0)
    result = Stage(g, lambda *a, **kw: (_ for _ in ()).throw(AssertionError('no terminal live replay')), read=w.read, root=RootPath(root))
    assert len(finishes) == before_finishes and g.operator.negative_cpu_release.pending is True and (recovery.released is False) and (scheduler._operator_maintenance is True)
    good = kind in ('complete', 'missing_projection')
    assert (result.failed_owner_pending is None) == good, (case, result.owner_decision_diagnostic)
    assert result.closed is (not good) and len(result.used) == 4 and (result.active is None)
    results.append({'case': case, 'Journal_state': result.owner_decision_diagnostic['state'], 'old_owner_pending': result.failed_owner_pending is not None, 'Stages_closed': result.closed, 'negative_pending': True, 'Recovery_released': False, 'scheduler_maintenance': True, 'current_source_activation_required': True, 'used': len(result.used), 'cold_physical_finish_calls': 0})
    (folder / 'RESULT.json').write_bytes(w.common.encode(results[-1]))
run('complete', 'complete')
run('missing_projection', 'missing_projection')
run('unknown', 'unknown')
run('broken_witness', 'broken_witness')
report = {'saved_scope_sha256': hashlib.sha256((H / 'CPU_V2_SCOPE_FIRST/V2_ORIGINALS.json').read_bytes()).hexdigest(), 'real_Recovery_ctor_and_Stages_ctor': True, 'real_v2_historical_eligibility': True, 'cases': results, 'scope_reruns': 0, 'new_source_fence': 'preserved, not released', 'full_Runtime_Grant_construction': 'pending integration', 'resource_proof_in_recipe': 'explicit CPU-only nonauthority boundary', 'native': 0}
(H / ('V2_COLD_' + label + '_RESULT.json')).write_bytes(w.common.encode(report))
print(json.dumps(report, sort_keys=True))
