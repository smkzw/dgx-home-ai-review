# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""One fixed short-c/stdin transport, preserving complete original RPC bytes/rc."""
import ast, base64, hashlib, json, zlib
from pathlib import Path
HERE = Path(__file__).parent
REQUEST_SCHEMA = 'reserved-parent-compact-input/v1'
CAP = 4194304
BOOT_CAP = 16384

def sha(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + chr(10)).encode()

def body(request, bootstrap):
    import receipt_codec as C
    if type(request) is not bytes or type(bootstrap) is not bytes or (not 0 < len(bootstrap) <= BOOT_CAP):
        raise ValueError('compact_exact_bounded_input')
    payload = {'schema': REQUEST_SCHEMA, 'bootstrap': C.pack(bootstrap), 'request': C.pack(request)}
    r = runner(bootstrap)
    if len(r) > 32768:
        raise ValueError('fixed_runner_bound')
    return encode({'schema': 'reserved-parent-short-runner/v1', 'runner': C.pack(r), 'payload': payload})

def runner(bootstrap):
    if type(bootstrap) is not bytes or not 0 < len(bootstrap) <= BOOT_CAP:
        raise ValueError('fixed_bootstrap_cap')
    codec = (HERE / 'receipt_codec.py').read_bytes()
    diagnostic = (HERE / 'safe_diagnostic.py').read_bytes()
    script = None.replace('CODEC', repr(codec)).replace('DIAG', repr(diagnostic)).replace('BOOT_SHA', repr(sha(bootstrap)))
    paths = []
    domain = 'PC'
    for n in ast.parse(bootstrap).body:
        if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == 'POLICY' for t in n.targets)):
            p = ast.literal_eval(n.value)
            if type(p) is dict and 'PC_ROOT' in p:
                paths = [p['PC_ROOT'] + '/parent-root-rpc.py', p['PC_ROOT'] + '/service/plan.py']
            if type(p) is dict and 'stage' in p:
                domain = 'A'
                paths = [p['stage'] + '/' + x for x in p['files'] if x.endswith('.py')]
    script = script.replace('SOURCE_PATHS', repr(paths)).replace('DOMAIN', repr(domain))
    script = script.replace("'original':c.pack(original)", "'original':w.pack(original)", 1)
    script = script.replace('sys.stdout.buffer.write(', "w=types.ModuleType('fixed_lossless_pulse_wire');exec(compile(" + repr(OUTPUT_CODEC_SOURCE) + ",'<fixed_lossless_pulse_wire>','exec'),w.__dict__)\nsys.stdout.buffer.write(", 1)
    compile(script, 'fixed_compact_transport', 'exec')
    return script.encode()

def code(bootstrap):
    raw = runner(bootstrap)
    if len(raw) > 32768:
        raise ValueError('fixed_runner_bound')
    script = None.replace('PIN', repr(sha(raw)))
    compile(script, 'fixed_short_envelope', 'exec')
    comp = base64.b64encode(zlib.compress(script.encode(), 9)).decode()
    result = 'import base64,zlib;exec(compile(zlib.decompress(base64.b64decode(' + repr(comp) + ")),'<fixed_short_envelope>','exec'))"
    return result

def decode(raw):
    import receipt_codec as C

    def pairs(xs):
        v = {}
        for k, x in xs:
            if k in v:
                raise ValueError('duplicate_compact_key')
            v[k] = x
        return v
    if type(raw) is not bytes or len(raw) > CAP:
        raise ValueError('bounded_compact_output')
    v = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
    if type(v) is not dict or set(v) != {'schema', 'original', 'diagnostic'} or v['schema'] != 'reserved-parent-RPC-output/v1':
        raise ValueError('exact_compact_output')
    d = v['diagnostic']
    if d is not None:
        import safe_diagnostic as D
        if type(d) is not dict or set(d) != {'stage', 'source_reason_code', 'error_type'} or d['stage'] not in set(D.ACTIONS.values()) | {'A_fixed_rpc', 'PC_fixed_rpc'} or (d['source_reason_code'] not in D.VOCAB | D.PC_VOCAB | D.BOOTSTRAP_VOCAB | {'owned_A_RPC_failed_no_retry', 'owned_PC_RPC_failed_no_retry'}) or (d['error_type'] not in ('Refused', 'FixedFailure', 'ProtectedSource')):
            raise ValueError('fixed_safe_diagnostic_only')
    import types
    w = types.ModuleType('fixed_lossless_pulse_wire')
    exec(compile(OUTPUT_CODEC_SOURCE, '<fixed_lossless_pulse_wire>', 'exec'), w.__dict__)
    return (w.unpack(v['original']), d)
OUTPUT_CODEC_SOURCE = None
