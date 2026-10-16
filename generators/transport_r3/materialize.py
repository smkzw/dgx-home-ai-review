# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure parent-only six-leaf derivation. None is not a source approval."""
import ast, hashlib, json, pathlib, types
H = pathlib.Path(__file__).resolve().parent
APPROVED_BASE = None
CONTRACT_SHA = '56886756e0b3ae99ec054f3454f1f2754bfc20971cb8d1b1dd1b15d253a233c8'

def sha(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def need(v, r):
    if not v:
        raise ValueError(r)

def replace_def(raw, name, new, last=False):
    t = ast.parse(raw)
    nodes = [n for n in t.body if isinstance(n, ast.FunctionDef) and n.name == name]
    need(len(nodes) == (2 if last else 1), 'one_exact_function_slot')
    n = nodes[-1]
    lines = raw.decode().splitlines(True)
    lines[n.lineno - 1:n.end_lineno] = [new.rstrip() + '\n']
    return ''.join(lines).encode()

def bind(raw, name, value):
    nodes = [n for n in ast.parse(raw).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == name for t in n.targets))]
    need(len(nodes) == 1, 'one_exact_literal')
    n = nodes[0]
    lines = raw.decode().splitlines(True)
    lines[n.lineno - 1:n.end_lineno] = [name + '=' + repr(value) + '\n']
    return ''.join(lines).encode()

def function_pins(files):
    result = {}
    for name, fn, last in [('parent_io.py', 'captured', False), ('parent_io.py', 'ssh', True), ('compact_transport.py', 'runner', False), ('compact_transport.py', 'decode', False), ('transport_evidence.py', 'Writer', False)]:
        t = ast.parse(files[name])
        nodes = [n for n in t.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == fn]
        need(len(nodes) == (2 if last else 1), 'exact_base_definition')
        result[name + ':' + fn] = sha(''.join(files[name].decode().splitlines(True)[nodes[-1].lineno - 1:nodes[-1].end_lineno]).encode())
    return result

def materialize(files, approved=None):
    need(approved is not None and approved == json.loads((H / 'BASE_FUNCTION_PINS.json').read_bytes()), 'transport_SOURCE_approval_None_or_wrong')
    need(sha((H / 'CONTRACT.json').read_bytes()) == CONTRACT_SHA, 'exact_transport_SOURCE_contract')
    need(function_pins(files) == approved, 'exact_accepted_parent_transport_definitions')
    out = dict(files)
    index = json.loads(out['parent-final-index.json'])
    need(all((sha(out[n]) == s for n, s in index['files'].items())), 'original_whole_parent_index')
    compact = out['compact_transport.py']
    s = compact.decode()
    old = " compile(script,'fixed_compact_transport','exec');return script.encode()"
    need(s.count(old) == 1 and "'original':c.pack(original)" in s, 'fixed_original_runner_output')
    extra = ' script=script.replace("\'original\':c.pack(original)","\'original\':w.pack(original)",1)\n script=script.replace(\'sys.stdout.buffer.write(\',"w=types.ModuleType(\'fixed_lossless_pulse_wire\');exec(compile("+repr(OUTPUT_CODEC_SOURCE)+",\'<fixed_lossless_pulse_wire>\',\'exec\'),w.__dict__)\\nsys.stdout.buffer.write(",1)\n'
    s = s.replace(old, extra + old, 1)
    old = " return C.unpack(v['original']),d"
    need(s.count(old) == 1, 'fixed_original_decode')
    s = s.replace(old, " import types\n w=types.ModuleType('fixed_lossless_pulse_wire');exec(compile(OUTPUT_CODEC_SOURCE,'<fixed_lossless_pulse_wire>','exec'),w.__dict__);return w.unpack(v['original']),d", 1)
    compact = (s + '\nOUTPUT_CODEC_SOURCE=' + repr((H / 'wire_codec.py').read_bytes()) + '\n').encode()
    out['compact_transport.py'] = compact
    io = out['parent_io.py']
    io = replace_def(io, 'captured', (H / 'captured_candidate.py').read_text())
    io = replace_def(io, 'ssh', (H / 'route_candidate.py').read_text(), last=True)
    io += b'\nLAST_ROUTE_TRACE=None\nLAST_TRANSPORT_DIAGNOSTIC=None\n'

    class SourceMap:

        def __truediv__(self, n):
            need(n in ('receipt_codec.py', 'safe_diagnostic.py'), 'two_fixed_runner_sources')
            return types.SimpleNamespace(read_bytes=lambda: out[n])
    module = types.ModuleType('pure_parent_compact')
    module.__file__ = str(H / 'BASE/compact_transport.py')
    exec(compile(compact, module.__file__, 'exec'), module.__dict__)
    module.HERE = SourceMap()
    tree = ast.parse(io)
    for name in ('PC_BOOTSTRAP_SOURCE', 'A_BOOTSTRAP_SOURCE'):
        value = ast.literal_eval(next((n.value for n in tree.body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == name for t in n.targets)))))
        io = bind(io, name.replace('_SOURCE', '_CODE'), module.code(value))
    out['parent_io.py'] = io
    out['transport_evidence.py'] += b'\n' + (H / 'evidence_candidate.py').read_bytes() + b'\nWriter.diagnostic=diagnostic\n'
    out['parent_metadata.py'] = bind(out['parent_metadata.py'], 'APPROVED_IO_SOURCE_SHA', sha(io))
    idx = dict(index, files={n: sha(out[n]) for n in index['files']})
    idxraw = encode(idx)
    out['parent-final-index.json'] = idxraw
    out['parent_entry.py'] = bind(out['parent_entry.py'], 'APPROVED_PARENT_INDEX_SHA', sha(idxraw))
    changed = {n for n in out if out[n] != files[n]}
    need(changed == {'compact_transport.py', 'parent_io.py', 'transport_evidence.py', 'parent_metadata.py', 'parent-final-index.json', 'parent_entry.py'}, 'only_six_parent_leaves')
    for n, b in out.items():
        need(type(b) is bytes and len(b) <= 2097152, 'original_parent_leaf_cap')
        compile(b, n, 'exec') if n.endswith('.py') else None
    need(sum(map(len, out.values())) <= 4194304, 'original_parent_bundle_cap')
    return {'files': out, 'pins': {n: {'sha256': sha(b), 'bytes': len(b)} for n, b in out.items()}, 'changed': sorted(changed), 'native_eligible': False, 'actual_slots': None}
if __name__ == '__main__':
    raise SystemExit('SOURCE_ONLY_actual_slots_None')
