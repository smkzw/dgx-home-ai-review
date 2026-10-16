# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Real frozen old bridge/terminal bodies + actual published immutable originals.
Only Root protected read/F9 and no-capability catalog supply are CPU boundaries.
No Runtime/Manager/current qualification/BEGIN is constructed.
"""
import ast, base64, copy, hashlib, json, pathlib, sys, types, zlib
H = pathlib.Path(__file__).resolve().parents[1]
R = H.parent
P = R / 'parent_checks/R25_RESUME/R26_R11_R3_FIRST_SUFFIX_PARENT'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def load(name, path):
    m = types.ModuleType(name)
    m.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), m.__dict__)
    return m
prep = load('r17_history_prepare', H / 'SOURCE/history_prepare.py')
original = R / 'R26_R16_FAILED_OWNER_RECOVERY_JOINT_SOURCE_R1/FINAL_GRAPH/PC/service/history_reader.py'
raw = original.read_bytes()
assert sha(raw) == '2273f86b869adc45ef2cb81b3cf9db4906497de40eb548af264eeacdecc08aa8'
items = []
for node in ast.parse(raw).body:
    keep = False
    if isinstance(node, ast.Import):
        keep = all((a.asname and a.asname.startswith('epoch_') for a in node.names))
    elif isinstance(node, ast.Assign):
        keep = all((isinstance(t, ast.Name) and t.id.startswith('epoch_') for t in node.targets))
    elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        keep = node.name.startswith('epoch_') or node.name == 'old_domain_from_snapshot'
    if keep:
        items.append(node)
history = types.ModuleType('r17_real_original_bridge')
exec(compile(ast.Module(body=items, type_ignores=[]), str(original), 'exec'), history.__dict__)
pub = P / 'R15-history-data-publish-prepared'
packet = json.loads((pub / 'packet.json').read_bytes())
native = json.loads((pub / 'native-original.json').read_bytes())
files = {}
for name, ref in native['data_refs'].items():
    b = (pub / 'index.json').read_bytes() if name == 'index.json' else base64.b64decode(packet['files'][name]['raw_b64'], validate=True)
    assert sha(b) == ref['sha256'] and len(b) == ref['F9'][2]
    files[ref['path']] = (b, ref['F9'])
bundle = json.loads(files[history.epoch_APPROVED_BINDING['source_bundle']['path']][0])
for name, ref in history.epoch_APPROVED_BINDING['old_metadata'].items():
    row = bundle['files'][name]
    b = zlib.decompress(base64.b64decode(row['zlib_base64'], validate=True))
    assert sha(b) == ref['sha256']
    files[ref['path']] = (b, ref['F9'])
calls = []

def read(path, limit=2097152):
    b, f = files[str(path)]
    assert len(b) <= limit
    calls.append(str(path))
    return (b, list(f))
config = {'review_sha256': '6be020877d73e6be6db7269c73941bdc9121df4e9dd62b52517de87b29b483a9'}
before = dict(sys.modules)
token = prep.prepare_bridge(read, history, config)
assert dict(sys.modules).keys() == before.keys() or all((not k.startswith('_owner_prepared_') for k in set(sys.modules) - set(before)))
value = token.recheck(read)
normal = R / 'R26_R16_FAILED_OWNER_RECOVERY_JOINT_SOURCE_R1/DATA/R16-normal-history.json'
expected = json.loads(normal.read_bytes())['old_domain']
assert value['domain'] == expected
assert value['historical_only'] and value['resource_authorized'] is value['source_activation_authorized'] is False
assert set(token.dependency_refs) == set(files) - {'/opt/dgx-v4/hx/mimo-registry-r15-history/normal-history.json'}
path = next(iter(files))
b, f = files[path]
new = list(f)
new[1] += 1
files[path] = (b, new)
try:
    token.recheck(read)
except prep.PreparationRefused as e:
    assert str(e) == 'prepared_history_fresh_fullSHA_F9_protection'
    inode_reason = str(e)
else:
    raise AssertionError('changed inode accepted')
files[path] = (b, f)
try:
    prep.denied()
except prep.PreparationRefused as e:
    assert str(e) == 'prepared_history_dynamic_capability_refused'
    dynamic_reason = str(e)
else:
    raise AssertionError('dynamic capability accepted')
result = {'real_original_bridge': True, 'all_two_original_terminal_consumers': True, 'domain_exact': True, 'dependency_leaves': len(token.dependency_refs), 'code_objects': len(token._codes), 'protected_read_calls': len(calls), 'samebytes_inode_refusal': inode_reason, 'dynamic_refusal': dynamic_reason, 'Root_FS_F9': 'explicit original metadata projection', 'Runtime': 0, 'BEGIN': 0, 'native': 0}
(H / 'BRIDGE_RESULT.json').write_bytes(prep.encode(result))
print(json.dumps(result, sort_keys=True))
