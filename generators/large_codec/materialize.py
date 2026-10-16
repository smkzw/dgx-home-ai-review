# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Derive exact E3 parent25, replace only embedded output codec; SOURCE approval != grant."""
import ast, hashlib, json, pathlib, types
H = pathlib.Path(__file__).resolve().parent
E3 = H.parent / 'R26_R15_PARENT_TRANSPORT5_CAUSAL_SOURCE_R3'
E3_MANIFEST_SHA = 'd78e7a063dea2ed395dbf29128e08369e9cb23e1d85a8360e4f2ea0dc73f4c27'
ACTUAL_SLOTS = None
NATIVE_ELIGIBLE = False

def sha(b):
    return hashlib.sha256(b).hexdigest()

def need(v, r):
    if not v:
        raise ValueError(r)

def materialize(files, approved=None):
    need(approved is not None, 'SOURCE_approval_None')
    raw = (E3 / 'SOURCE_MANIFEST.json').read_bytes()
    need(sha(raw) == E3_MANIFEST_SHA, 'fixed_frozen_E3_manifest')
    manifest = json.loads(raw)
    for n, p in manifest['own'].items():
        b = (E3 / n).read_bytes()
        need(len(b) == p['bytes'] and sha(b) == p['sha256'], 'complete_frozen_E3_SOURCE')
    m = types.ModuleType('private_fixed_E3_materializer')
    m.__file__ = str(E3 / 'materialize.py')
    exec(compile((E3 / 'materialize.py').read_bytes(), m.__file__, 'exec'), m.__dict__)
    base = m.materialize(files, approved)
    out = dict(base['files'])
    codec = (H / 'wire_codec.py').read_bytes()
    compile(codec, 'fixed_large_opaque_wire_codec', 'exec')
    out['compact_transport.py'] = m.bind(out['compact_transport.py'], 'OUTPUT_CODEC_SOURCE', codec)

    class SourceMap:

        def __truediv__(self, n):
            need(n in ('receipt_codec.py', 'safe_diagnostic.py'), 'two_original_request_runner_sources')
            return types.SimpleNamespace(read_bytes=lambda: out[n])
    c = types.ModuleType('private_derived_compact')
    c.__file__ = str(E3 / 'BASE/compact_transport.py')
    exec(compile(out['compact_transport.py'], c.__file__, 'exec'), c.__dict__)
    c.HERE = SourceMap()
    io = out['parent_io.py']
    for name in ('PC_BOOTSTRAP_SOURCE', 'A_BOOTSTRAP_SOURCE'):
        values = [n.value for n in ast.parse(io).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == name for t in n.targets))]
        need(len(values) == 1, 'fixed_bootstrap_slot')
        io = m.bind(io, name.replace('_SOURCE', '_CODE'), c.code(ast.literal_eval(values[0])))
    out['parent_io.py'] = io
    out['parent_metadata.py'] = m.bind(out['parent_metadata.py'], 'APPROVED_IO_SOURCE_SHA', sha(io))
    idx = json.loads(out['parent-final-index.json'])
    idx['files'] = {n: sha(out[n]) for n in idx['files']}
    out['parent-final-index.json'] = m.encode(idx)
    out['parent_entry.py'] = m.bind(out['parent_entry.py'], 'APPROVED_PARENT_INDEX_SHA', sha(out['parent-final-index.json']))
    changed = {n for n in out if out[n] != base['files'][n]}
    need(changed == {'compact_transport.py', 'parent_io.py', 'parent_metadata.py', 'parent-final-index.json', 'parent_entry.py'}, 'only_five_parent_leaf_rebindings')
    need(set(out) == set(files) and len(out) == 25, 'no_new_runtime_leaf')
    for n, b in out.items():
        need(type(b) is bytes and len(b) <= 2097152, 'unchanged_parent_leaf_cap')
        compile(b, n, 'exec') if n.endswith('.py') else None
    need(sum(map(len, out.values())) <= 4194304, 'unchanged_parent_bundle_cap')
    return {'files': out, 'pins': {n: {'sha256': sha(b), 'bytes': len(b)} for n, b in out.items()}, 'changed_from_E3': sorted(changed), 'native_eligible': False, 'actual_slots': None}
if __name__ == '__main__':
    raise SystemExit('SOURCE_ONLY_actual_slots_None')
