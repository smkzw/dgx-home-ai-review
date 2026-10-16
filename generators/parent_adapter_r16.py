# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure fixed parent byte derivation, no runtime/transport or actual slots."""
import ast, hashlib, types
from pathlib import Path
P = Path(__file__).resolve().parent.parent / 'parent_checks/R25_RESUME/R26_R11_R3_FIRST_SUFFIX_PARENT'
UPSTREAM_SHA = 'ce9bb77ab4741b0fd9adf3aae7f8df7e98cdda03c5395b597b0da811213e8b99'
PC = '/opt/dgx-v4/hx/mimo-registry-r16'
A = '/opt/dgx-v4/mimo-registry-r16'
EPOCH = '2b9e9b631cebc13ae6b1550ee59c13ed'
FAMILY = 'ed7021db9df4c839d02f3271361924de'

def sha(b):
    return hashlib.sha256(b).hexdigest()

def materialize(destination, graph):
    path = P / 'r15_parent_stage_adapter.py'
    b = path.read_bytes()
    assert sha(b) == UPSTREAM_SHA
    m = types.ModuleType('R16_private_parent_adapter')
    m.__file__ = str(path)
    exec(compile(b, str(path), 'exec'), m.__dict__)
    m.PC_ROOT = PC
    m.A_ROOT = A
    m.SOURCE_EPOCH = EPOCH
    r = m.materialize(destination, graph)
    files = dict(r['files'])
    s = files['emission.py'].decode()
    assert s.count('LIVE_IDLE_SAME_FAMILY_FAILED_ASSETS_RELEASED') == 1
    s = s.replace('LIVE_IDLE_SAME_FAMILY_FAILED_ASSETS_RELEASED', 'LIVE_IDLE_FAILED_TERMINAL_HELD')
    s = s.replace('C29', 'C30').replace('/c-arm-r29', '/c-arm-r30').replace("'c-arm-r29/", "'c-arm-r30/")
    old = '/opt/dgx-v4/runtime/g8-clock-probe-c29-mimo-registry-r15'
    assert s.count(old) == 1
    s = s.replace(old, '/opt/dgx-v4/runtime/g8-clock-probe-c30-mimo-registry-r16', 1)
    files['emission.py'] = s.encode()
    s = files['sealing.py'].decode()
    for a, b in (('/home/REDACTED_USER/dgx-r26-r15-source-bundle.json', '/home/REDACTED_USER/dgx-r26-r16-source-bundle.json'), ('/home/REDACTED_USER/dgx-r26-r15-A-source-bundle.json', '/home/REDACTED_USER/dgx-r26-r16-A-source-bundle.json')):
        assert s.count(a) == 1
        s = s.replace(a, b, 1)
    files['sealing.py'] = s.encode()
    binding = files['binding.py'].decode()
    node = next((n for n in ast.parse(binding).body if isinstance(n, ast.FunctionDef) and n.name == 'source_parent'))
    pins = {n: {'sha256': sha(files[n]), 'bytes': len(files[n])} for n in ('emission.py', 'late_rpc.py', 'prebind_failure.py', 'segment_hook.py', 'sealing.py')}
    replacement = 'def source_parent(name):\n    pins=' + repr(pins) + "\n    need(name in pins,'R15_closed_parent_source_table')\n    raw=(PARENT/name).read_bytes();row=pins[name]\n    need(sha(raw)==row['sha256'] and len(raw)==row['bytes'],'R15_exact_parent_source_bytes')\n    return raw\n"
    lines = binding.splitlines(True)
    lines[node.lineno - 1:node.end_lineno] = [replacement]
    files['binding.py'] = ''.join(lines).encode()
    for n, b in files.items():
        compile(b, n, 'exec')
    return dict(r, files=files, pins={n: {'sha256': sha(b), 'bytes': len(b)} for n, b in files.items()})

def normal_sources():
    """Three original finite parent algorithms, only unused R16/C30/domain slots."""
    path = P / 'r15_parent_stage_adapter.py'
    raw = path.read_bytes()
    assert sha(raw) == UPSTREAM_SHA
    m = types.ModuleType('R16_private_normal_adapter')
    m.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), m.__dict__)
    m.PC_ROOT = PC
    m.SOURCE_EPOCH = EPOCH
    files = m.normal_sources()
    out = {}
    for name, raw in files.items():
        s = raw.decode().replace('C29', 'C30').replace('c29', 'c30').replace('c-arm-r29', 'c-arm-r30')
        s = s.replace('LIVE_IDLE_SAME_FAMILY_FAILED_ASSETS_RELEASED', 'LIVE_IDLE_FAILED_TERMINAL_HELD')
        s = s.replace("native_tag = 'r15-epoch-'", "native_tag = 'r16-epoch-'")
        compile(s, 'R16_' + name, 'exec')
        out[name] = s.encode()
    assert set(out) == {'normal_flow.py', 'observations.py', 'epoch_once.py'}
    return out
