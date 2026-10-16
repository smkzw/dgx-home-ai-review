# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Actual selected old bridge bodies under both loader future policies."""
import __future__, ast, json, pathlib, sys, types
H = pathlib.Path(__file__).resolve().parents[1]
seed = (H / 'tests/verify_bridge.py').read_text().split('before=dict(sys.modules)')[0]
ns = {'__file__': str(H / 'tests/verify_bridge.py'), '__name__': 'r17_flags_static_seed'}
exec(compile(seed, '<exact-bridge-seed>', 'exec'), ns)
raw = ns['raw']
items = ns['items']
prep = ns['prep']
read = ns['read']
config = ns['config']
results = []
tokens = []
for flags in (0, __future__.annotations.compiler_flag):
    m = types.ModuleType('r17_history_flags_' + str(flags))
    exec(compile(ast.Module(body=items, type_ignores=[]), str(ns['original']), 'exec', flags=flags, dont_inherit=True, optimize=sys.flags.optimize), m.__dict__)
    token = prep.prepare_bridge(read, m, config)
    assert token._flags == flags and token._optimize == sys.flags.optimize
    assert all((key[4] == flags and key[5] == sys.flags.optimize for key in token._codes))
    tokens.append(token)
    results.append({'flags': flags, 'code_objects': len(token._codes), 'full_original_semantics': True})
assert tokens[0]._raw == tokens[1]._raw
result = {'actual_original_selected_semantics_equal': True, 'policies': results, 'Python': sys.version.split()[0], 'optimize': sys.flags.optimize, 'native': 0}
(H / 'COMPILE_FLAGS_RESULT.json').write_bytes(prep.encode(result))
print(json.dumps(result, sort_keys=True))
