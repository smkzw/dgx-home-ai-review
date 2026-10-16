# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure late R12 stage-parent materializer over the accepted H4/H5 algorithms.
No transport, intent, budget clock, download, model or service is run here.
"""
import ast
import builtins
import hashlib
import json
import os
from pathlib import Path
import sys
import types
HERE = Path(__file__).resolve().parent
RUNTIME = Path('/REDACTED_HOME/AI-Staging/DGX_HOME_AI_20261011_V4/runtime')
H4 = RUNTIME / 'R26_R11_R3_FIRST_SUFFIX_PARENT_SOURCE_R1'
J3 = RUNTIME / 'R26_R11_C_HISTORICAL_PATH_STOPPED_CONTINUATION_JOINT_SOURCE_R3'
J12 = RUNTIME / 'R26_ASSET_PROTOCOL_JOINT_UPDATE_SOURCE_R12'
D3 = RUNTIME / None
PARENT = Path(None)
OLD_PC = '/opt/dgx-v4/hx/mimo-registry-native-r26-cpath-r11-r3'
NEW_PC = '/opt/dgx-v4/hx/mimo-registry-r16'
EPOCH = 'ed7021db9df4c839d02f3271361924de'
REF_SHA = '562dd7161e28e02567be07d64f70c6993107a43e99d08e8a14cdce635db09bdf'

def need(value, reason):
    if not value:
        raise ValueError(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def source(path):
    raw = (H4 / 'INPUT_REFERENCES.json').read_bytes()
    need(sha(raw) == REF_SHA, 'accepted_H4_complete_reference_table')
    row = json.loads(raw)['files'][str(path)]
    body = Path(path).read_bytes()
    need(sha(body) == row['sha256'] and len(body) == row['bytes'], 'accepted_complete_parent_source_body')
    return body

def function_root(raw, function, expected_count):
    """Only the chosen function's exact current-root literal changes.
    Historical strings, other definitions and all old raw hashes stay opaque.
    """
    tree = ast.parse(raw)
    target = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function))
    count = 0

    class Root(ast.NodeTransformer):

        def visit_Constant(self, node):
            nonlocal count
            if node.value == OLD_PC or node.value == OLD_PC + '/parent-root-rpc.py':
                count += 1
                return ast.copy_location(ast.Constant(node.value.replace(OLD_PC, NEW_PC, 1)), node)
            return node
    changed = Root().visit(target)
    need(count == expected_count, 'closed_current_root_literal_count_' + function)
    text = raw.decode().splitlines(True)
    text[target.lineno - 1:target.end_lineno] = [ast.unparse(changed) + '\n']
    result = ''.join(text).encode()
    compile(result, 'R12_same_parent_' + function, 'exec')
    return result

def modules(pc_pins):
    names = ('source_tools', 'receipt_codec', 'compact_transport', 'compact_parent', 'pc_stdin_envelope', 'bootstrap_policy', 'first_entry_parent', 'stage_materialize')
    loaded = {}

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if not level and name in names:
            return get(name)
        need(not level and name.split('.')[0] in sys.stdlib_module_names, 'private_parent_materializer_no_ambient_import')
        return builtins.__import__(name, globals, locals, fromlist, level)

    def get(name):
        if name in loaded:
            return loaded[name]
        path = J3 / (name + '.py')
        raw = source(path)
        if name == 'first_entry_parent':
            raw = function_root(raw, 'materialize', 1)
        elif name == 'bootstrap_policy':
            raw = function_root(raw, 'derive', 1)
            text = raw.decode()
            needle = "'operation': p['grant_operation']"
            need(text.count(needle) == 1, 'R15_one_source_index_bootstrap_policy_operation')
            raw = text.replace(needle, "'operation': p['operation']", 1).encode()
        m = types.ModuleType('private_R12_parent_' + name)
        m.__file__ = str(path)
        m.__dict__['__builtins__'] = dict(vars(builtins), __import__=imports)
        loaded[name] = m
        exec(compile(raw, str(path), 'exec'), m.__dict__)
        if name == 'first_entry_parent':
            m.APPROVED_FINAL_SOURCE = pc_pins
            bind = m.bind
            old = source(J3 / 'cold_bootstrap.py')
            fixed = (PARENT / 'cold_bootstrap_fixed.py').read_bytes()
            need(sha(fixed) == '7c4a9c0225c4b071cc9079f497b1051dadafc09c8a3c729665666214c38289e7', 'same_actual_fixed_cold_defs')

            def cold_bind(raw, values):
                return bind(fixed if raw == old else raw, values)
            m.bind = cold_bind
        return m
    return {name: get(name) for name in names}

def export_graph(graph, target):
    """Ordinary local exact source export; no deployment or permission evidence."""
    target = Path(target)
    need(not target.exists() and graph['packet']['operation'] == '2b9e9b631cebc13ae6b1550ee59c13ed' and (graph['packet']['grant_operation'] == EPOCH), 'new_local_graph_only')
    target.mkdir(mode=448)
    a = graph['A']
    pc = graph['PC']
    pins = {n: sha(b) for n, b in pc.items()}
    candidate = {'review_sha256': graph['packet']['review_sha256'], 'PC_config_sha256': sha(graph['config']), 'PC_files': pins, 'A_candidate': {'files': a['pins'], 'source_index_sha256': a['source_index_sha256'], 'agent_sha256': a['agent_sha256'], 'entry_worker_sha256': a['entry_worker_sha256'], 'worker_sha256': sha(a['files']['root_worker.py'])}}
    output = {'candidate.json': encode(candidate)}
    output.update({'PC/' + n: b for n, b in pc.items()})
    output.update({'A/A-candidate/' + n: b for n, b in a['files'].items()})
    output['A/parent-overlay/plan.py'] = a['files']['plan.py']
    for name in ('parent_io.py', 'parent_metadata.py'):
        output['A/parent-overlay/' + name] = source(D3 / 'A/parent-overlay' / name)
    for name, raw in output.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as file:
            file.write(raw)
        path.chmod(384)
    return candidate

def replace_definition(raw, reference, selector):
    """Replace one actual H5 definition, preserving every other definition."""

    def find(tree):
        nodes = tree.body
        for part in selector.split('.'):
            node = next((n for n in nodes if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == part))
            nodes = node.body
        return node
    before = find(ast.parse(raw))
    donor = find(ast.parse(reference))
    body = ast.get_source_segment(reference.decode(), donor)
    indent = ' ' * before.col_offset
    import textwrap
    replacement = textwrap.dedent(body)
    if before.col_offset:
        lines = body.splitlines()
        replacement = lines[0] + '\n' + '\n'.join((line[donor.col_offset:] for line in lines[1:]))
    replacement = '\n'.join((indent + line for line in replacement.splitlines())) + '\n'
    text = raw.decode().splitlines(True)
    text[before.lineno - 1:before.end_lineno] = [replacement]
    result = ''.join(text).encode()
    compile(result, 'same_H5_' + selector, 'exec')
    return result

def finish_sources(out, stage):
    """Apply the accepted H5 point-event changes to the newly bound original IO."""
    out = Path(out)
    h5 = J12 / 'BASE/H5/parent'
    pins = json.loads((J12 / 'BASE_PINS.json').read_bytes())

    def h5_source(name):
        raw = (h5 / name).read_bytes()
        need(sha(raw) == pins['H5/parent/' + name]['sha256'], 'accepted_H5_exact_final_parent_source')
        return raw
    raw = (out / 'parent_io.py').read_bytes()
    h5_io = h5_source('parent_io.py')
    for name in ('IO.rpc', 'bind_context'):
        raw = replace_definition(raw, h5_io, name)
    raw = b'import point_clock\n' + raw
    (out / 'parent_io.py').write_bytes(raw)
    (out / 'point_clock.py').write_bytes(h5_source('point_clock.py'))
    (out / 'terminal_wait.py').write_bytes(h5_source('terminal_wait.py'))
    ns = load_parent_modules()
    segment = ns['segment_hook'].derive(h5_source('segment_parent.py'))
    module = types.ModuleType('new_finite_stage_source')
    module.APPROVED_STAGE = None
    ns['segment_hook'].bind_stage(module, stage)
    segment = ns['sealing'].slots(segment, {'APPROVED_STAGE': repr(stage)})
    (out / 'segment_parent.py').write_bytes(segment)
    budget = (out / 'parent_budget.py').read_bytes()
    need(next((ast.literal_eval(n.value) for n in ast.parse(budget).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == 'OPERATION' for t in n.targets)))) == '3e38d054d32cc1015edfc26ae2ae5f78', 'exact_predecessor_parent_budget_domain')
    budget = ns['sealing'].slots(budget, {'OPERATION': repr(EPOCH)})
    (out / 'parent_budget.py').write_bytes(budget)
    metadata = ns['sealing'].slots((out / 'parent_metadata.py').read_bytes(), {'APPROVED_IO_SOURCE_SHA': repr(sha(raw))})
    (out / 'parent_metadata.py').write_bytes(metadata)
    index = json.loads((out / 'parent-final-index.json').read_bytes())
    names = set(index['files']) | {'segment_parent.py', 'point_clock.py', 'terminal_wait.py'}
    index['files'] = {n: sha((out / n).read_bytes()) for n in sorted(names)}
    encoded = encode(index)
    (out / 'parent-final-index.json').write_bytes(encoded)
    entry = ns['sealing'].slots((out / 'parent_entry.py').read_bytes(), {'APPROVED_PARENT_INDEX_SHA': repr(sha(encoded))})
    (out / 'parent_entry.py').write_bytes(entry)
    for path in out.iterdir():
        if path.is_file():
            path.chmod(384)
            if path.suffix == '.py':
                compile(path.read_bytes(), str(path), 'exec')
    return {'files': {p.name: sha(p.read_bytes()) for p in out.iterdir() if p.is_file()}, 'actual_intent': None, 'native_eligible': False, 'stage_operation_data': stage['stage_operation'], 'requires_prepared_runner_before_IO': True}

def source_parent(name):
    pins = {'emission.py': {'sha256': '4e9a41e4a0dad757f6613905ec913c90ff36e2455ef62bd6a85c9ae45d581dd1', 'bytes': 18883}, 'late_rpc.py': {'sha256': '1ef31dc617fb77f18027dc563edc5e8faba8c3168c05507e4c861f43b0e10f96', 'bytes': 6082}, 'prebind_failure.py': {'sha256': 'ec91c5c74e122be998836412f0b404a15302c0f512108556b90768ed3ec70db6', 'bytes': 5044}, 'segment_hook.py': {'sha256': '41e4ab6b61f2d8482f39f552e43751abfad6b0292cec6bef9349627d59479062', 'bytes': 8833}, 'sealing.py': {'sha256': '379b28865a8407dd23c65ef6a6c627eba8f9ea937a7ded59fc87c416a895b0b6', 'bytes': 3817}}
    need(name in pins, 'R15_closed_parent_source_table')
    raw = (PARENT / name).read_bytes()
    row = pins[name]
    need(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'R15_exact_parent_source_bytes')
    return raw

def load_parent_modules():
    names = ('emission', 'late_rpc', 'prebind_failure', 'segment_hook', 'sealing')
    loaded = {}

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if not level and name in names:
            return get(name)
        need(not level and name.split('.')[0] in sys.stdlib_module_names, 'parent_component_closed_import')
        return builtins.__import__(name, globals, locals, fromlist, level)

    def get(name):
        if name in loaded:
            return loaded[name]
        path = PARENT / (name + '.py')
        m = types.ModuleType('closed_R12_stage_' + name)
        m.__file__ = str(path)
        m.__dict__['__builtins__'] = dict(vars(builtins), __import__=imports)
        loaded[name] = m
        exec(compile(source_parent(name + '.py'), str(path), 'exec'), m.__dict__)
        return m
    return {n: get(n) for n in names}

def materialize(graph, current_original, destination, stage):
    need(stage['stage_operation'] != 'd8d0f06cc54a807f320d03813daf3b4b' and stage['maximum_seconds'] <= 1800, 'new_stage_no_spent_window')
    root = Path(destination)
    need(not root.exists(), 'new_parent_materialization_only')
    root.mkdir(mode=448)
    exported = root / 'final-source-graph'
    candidate = export_graph(graph, exported)
    ms = modules(candidate['PC_files'])
    result = ms['stage_materialize'].materialize(exported, root / 'parent', current_original, existing_VPS_alias='metadata-vps', stage_operation=stage['stage_operation'], ranges=stage['ranges'], maximum_seconds=stage['maximum_seconds'])
    return finish_sources(root / 'parent', stage)
