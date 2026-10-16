# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Real wire closed callback import, canonical asset_stage stays absent.
This narrow test proves the callback boundary, not current qualification.
"""
import ast, copy, json, pathlib, sys
H = pathlib.Path(__file__).resolve().parents[1]
source = (H / 'tests/verify_cold.py').read_text().split('# Fresh exact actor reader')[0]
marker = " if raw==stage_before and str(filename).endswith('/service/asset_stage.py'):raw=stage_after\n"
extra = " if raw==derive.original('service/current_epoch.py')and str(filename).endswith('/service/current_epoch.py'):raw=derive.current_epoch(raw)\n if raw==derive.original('pc/r11-gate/gate_loader.py')and str(filename).endswith('/gate_loader.py'):raw=derive.gate_loader(raw)\n"
assert source.count(marker) == 1
source = source.replace(marker, marker + extra)
ns = {'__file__': str(H / 'tests/verify_cold.py'), '__name__': 'R17_private_identity_fixture'}
exec(compile(source, '<exact-cold-definition-seed>', 'exec'), ns)
fs = ns['fs']
pid = ns['pid']
fs.mapping['/proc/self'] = pathlib.Path(fs.path('/proc/' + str(pid)))
fs.getpid = lambda: pid
fs.environ = {'INVOCATION_ID': ns['q']['current']['manager_identity']['invocation_id']}
cb = ns['cb']
current_owner = cb.consume.__globals__['current_owner']
actual = ns['Stage'].__init__.__globals__['identity']()
assert 'asset_stage' not in sys.modules
bad = dict(actual, pid=actual['pid'] + 1)
try:
    current_owner(ns['w'].read, bad)
except RuntimeError as error:
    assert str(error) == 'R17_actual_internal_current_identity'
    reason = str(error)
else:
    raise AssertionError('foreign identity accepted')
assert 'asset_stage' not in sys.modules
gate = ast.parse(ns['derive'].gate_loader(ns['derive'].original('pc/r11-gate/gate_loader.py')))
fn = next((n for n in gate.body if isinstance(n, ast.FunctionDef) and n.name == 'verify_current_owner'))
assert not any((isinstance(n, ast.ImportFrom) and n.module == 'asset_stage' for n in ast.walk(fn)))
result = {'real_wire_68_callbacks': True, 'canonical_asset_stage_absent_before_after': True, 'internal_closed_identity_import_reached': True, 'exact_foreign_identity_refusal': reason, 'positive_full_actor_consumer': 'pending', 'Runtime': 0, 'native': 0}
(H / 'PRIVATE_IDENTITY_RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
print(json.dumps(result, sort_keys=True))
