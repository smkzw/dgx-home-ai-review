# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Deterministic stdlib-only offline source operations, no ambient dependency loader."""
import ast, hashlib, json, pathlib, types
HERE = pathlib.Path(__file__).resolve().parent
FROZEN = HERE.parents[2] / 'runtime/R26_ASSET_PROTOCOL_JOINT_UPDATE_SOURCE_R12'
BASE = FROZEN / 'BASE'
LIVE = FROZEN / 'FINAL_GRAPH_D'

def need(v, r):
    if not v:
        raise ValueError(r)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def base(name):
    if name in ('INPUTS/actual-old-config.raw', 'INPUTS/actual-old-wire.raw'):
        return (HERE.parent / 'INPUTS' / ('R15-current-config.raw' if name.endswith('config.raw') else 'R15-current-wire.raw')).read_bytes()
    if name == 'INPUTS/actual-live-baseline.json':
        return (HERE.parent / 'R16_BASELINE_IMMUTABLE.json').read_bytes()
    if name.startswith(('A/', 'PC/')) and (LIVE / name).is_file():
        row = json.loads((LIVE / 'PHYSICAL_PINS.json').read_bytes())[name]
        raw = (LIVE / name).read_bytes()
        need(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'fixed_actual_R12_physical_input')
        return raw
    p = BASE / name
    pin = json.loads((HERE / 'BASE_PINS.json').read_bytes())[name]
    raw = p.read_bytes()
    need(sha(raw) == pin['sha256'] and len(raw) == pin['bytes'], 'fixed_base_changed:' + name)
    return raw

def literal(raw, name):
    n = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == name for t in n.targets))]
    need(len(n) == 1, 'literal_once:' + name)
    return ast.literal_eval(n[0].value)

def bind(raw, values):
    text = raw.decode()
    for key, value in values.items():
        nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == key for t in n.targets))]
        need(len(nodes) == 1, 'bind_once:' + key)
        n = nodes[0]
        ls = text.splitlines(True)
        ls[n.lineno - 1:n.end_lineno] = [key + '=' + repr(value) + '\n']
        text = ''.join(ls)
    compile(text, 'bound_r12_source', 'exec')
    return text.encode()

def expression(raw, name, expression):
    ast.parse(expression, mode='eval')
    s = raw.decode()
    n = next((x for x in ast.parse(s).body if isinstance(x, ast.Assign) and any((isinstance(t, ast.Name) and t.id == name for t in x.targets))))
    lines = s.splitlines(True)
    lines[n.lineno - 1:n.end_lineno] = [name + '=' + expression + '\n']
    b = ''.join(lines).encode()
    compile(b, 'r12_explicit_expression', 'exec')
    return b

def replace_definition(raw, source, name, *, class_name=None):
    tree = ast.parse(raw)
    replacement = ast.parse(source)
    select = lambda t: next((n for n in (next((c for c in t.body if isinstance(c, ast.ClassDef) and c.name == class_name)).body if class_name else t.body) if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name))
    old, new = (select(tree), select(replacement))
    text = ast.get_source_segment(source.decode(), new)
    prefix = ' ' * old.col_offset
    lines = raw.decode().splitlines(True)
    lines[old.lineno - 1:old.end_lineno] = ['\n'.join((prefix + x for x in text.splitlines())) + '\n']
    b = ''.join(lines).encode()
    compile(b, 'r12_definition_reuse', 'exec')
    return b

def load_source(raw, name, path):
    m = types.ModuleType(name)
    m.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    return m
