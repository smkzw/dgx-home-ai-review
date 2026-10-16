# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure exact-byte new source bundles; no upload, seal or restart at build time."""
import ast
import base64
import json
from pathlib import Path
from emission import need, sha, encode, checked_graph, PC_ROOT, EPOCH
HERE = Path(__file__).resolve().parent

def original(name):
    row = json.loads((HERE / 'sealer-original-references.json').read_bytes())[name]
    raw = (HERE / name).read_bytes()
    need(sha(raw) == row['sha256'] and len(raw) == row['bytes'], 'same_complete_existing_Root_sealer')
    return raw

def slots(raw, values):
    text = raw.decode()
    for key, expression in values.items():
        nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == key for t in n.targets))]
        need(len(nodes) == 1, 'one_sealer_source_slot_' + key)
        n = nodes[0]
        lines = text.splitlines(True)
        lines[n.lineno - 1:n.end_lineno] = [key + '=' + expression + '\n']
        text = ''.join(lines)
    compile(text, 'fixed_R12_source_sealer', 'exec')
    return text.encode()

def pc(graph):
    files = checked_graph(graph)
    index = json.loads(files['epoch-index.json'])
    bundle = encode({'role': 'epoch', 'review_sha256': graph['packet']['review_sha256'], 'files': {n: base64.b64encode(b).decode() for n, b in files.items()}, 'index': index})
    path = '/home/REDACTED_USER/dgx-r26-r16-source-bundle.json'
    raw = original('pc_sealer.original.py')
    marker = " if ROLE=='epoch':publish_packed_history_origin(source_root,files)\n"
    need(raw.decode().count(marker) == 1, 'one_old_in_code_history_publication_call')
    raw = raw.replace(marker.encode(), b'')
    raw = slots(raw, {'PC_ROOT': 'Path(' + repr(PC_ROOT) + ')', 'ROLE': repr('epoch'), 'APPROVED_BUNDLE_SHA': repr(sha(bundle)), 'APPROVED_REVIEW': repr(graph['packet']['review_sha256']), 'BUNDLE': 'Path(' + repr(path) + ')'})
    code = 'import types,json\nraw=' + repr(raw) + ";m=types.ModuleType('new_R12_Root_PC_sealer');m.__file__=" + repr(PC_ROOT + '/unpublished-sealer.py') + ";exec(compile(raw,m.__file__,'exec'),m.__dict__);print(json.dumps({'sealed_rc':m.main(),'bundle_sha256':" + repr(sha(bundle)) + '}))\n'
    compile(code, 'R12_PC_new_source_seal', 'exec')
    need(len(bundle) <= 8 * 1024 ** 2, 'existing_user_source_bundle_cap')
    return {'bundle': bundle, 'bundle_path': path, 'code': code, 'bundle_sha256': sha(bundle), 'actual_native_intent': None, 'native_eligible': False}

def A(graph):
    checked_graph(graph)
    files = graph['A']['files']
    pins = {n: sha(b) for n, b in files.items()}
    need(pins == graph['A']['pins'], 'same_complete_A_final54')
    root = '/opt/dgx-v4/mimo-registry-r16'
    path = '/home/REDACTED_USER/dgx-r26-r16-A-source-bundle.json'
    bundle = encode({'operation': EPOCH, 'files': {n: base64.b64encode(b).decode() for n, b in files.items()}, 'pins': pins})
    raw = slots(original('a_sealer.original.py'), {'APPROVED_BUNDLE_SHA': repr(sha(bundle)), 'OPERATION': repr(EPOCH), 'BUNDLE': 'Path(' + repr(path) + ')', 'STAGE': 'Path(' + repr(root) + ')'})
    code = 'import types,json\nraw=' + repr(raw) + ";m=types.ModuleType('new_R12_Root_A_sealer');m.__file__=" + repr(root + '/unpublished-sealer.py') + ";exec(compile(raw,m.__file__,'exec'),m.__dict__);print(json.dumps({'sealed_rc':m.main(),'bundle_sha256':" + repr(sha(bundle)) + '}))\n'
    compile(code, 'R12_A_new_source_seal', 'exec')
    need(sum(map(len, files.values())) <= 4194304 and len(bundle) <= 8 * 1024 ** 2, 'same_A_code_and_user_bundle_caps')
    return {'bundle': bundle, 'bundle_path': path, 'code': code, 'bundle_sha256': sha(bundle), 'actual_native_intent': None, 'native_eligible': False}
