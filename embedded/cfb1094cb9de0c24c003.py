# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure late-data final8 builder over the original reviewed C readonly bundle."""
import ast, base64, json, hashlib
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = '/opt/dgx-v4/c-unarmed-renewal-r26-2d8bb6adefd99ead39104bf44bf247d9'
UNIT = 'dgx-v4-c-unarmed-renewal-r26-2d8bb6adefd99ead39104bf44bf247d9.service'
DATA = ('readonly_once.py', 'validate.py', 'ANCHORS.json', 'Root_C_pins.json', 'old_three.json')
SOURCE = DATA + ('worker.py', 'seal.py', 'build.py', 'consumer.py')

def need(v, k):
    if not v:
        raise ValueError(k)

def sha(v):
    return hashlib.sha256(v).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):

    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, 'duplicate_JSON')
            out[k] = v
        return out
    out = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_JSON'))
    encode(out)
    return out

def source_bodies():
    return {n: (HERE / n).read_bytes() for n in SOURCE}

def source_pins(bodies=None):
    return {n: sha(b) for n, b in (source_bodies() if bodies is None else bodies).items()}

def bind(raw, key, value):
    text = raw.decode()
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id == key for t in n.targets))]
    need(len(nodes) == 1, 'single_literal_' + key)
    n = nodes[0]
    lines = text.splitlines(True)
    lines[n.lineno - 1:n.end_lineno] = [key + '=' + repr(value) + '\n']
    out = ''.join(lines).encode()
    compile(out, key, 'exec')
    return out

def materialize(review_raw, request_raw, bodies=None):
    bodies = source_bodies() if bodies is None else bodies
    review = strict(review_raw)
    need(set(bodies) == set(SOURCE) and all((type(v) is bytes for v in bodies.values())), 'complete_static_C_SOURCE')
    need(review == {'schema': 'c-unarmed-renewal-R26-readonly-source-review/v1', 'source_pins': source_pins(bodies), 'native_pending': True}, 'exact_complete_C_source_review')
    request = strict(request_raw)
    r = sha(review_raw)
    need(set(request) == {'schema', 'action', 'nonce', 'source_review_sha256', 'PC_config_sha256', 'PC_boot_id', 'PC_manager_identity'} and request['schema'] == 'c-unarmed-renewal-r26-readonly-request/v1' and (request['action'] == 'collect-current-C') and (request['source_review_sha256'] == r) and (encode(request) == request_raw), 'exact_actual_request_original')
    import re
    need(type(request['nonce']) is str and re.fullmatch('[0-9a-f]{32}', request['nonce']) and re.fullmatch('[0-9a-f]{64}', request['PC_config_sha256']) and (type(request['PC_boot_id']) is str) and (re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', request['PC_boot_id']) is not None), 'fixed_PC_original_request_identity')
    identity = request['PC_manager_identity']
    need(type(identity) is dict and set(identity) == {'pid', 'start_ticks', 'boot_id', 'invocation_id'} and (type(identity['pid']) is int) and (identity['pid'] > 1) and (type(identity['start_ticks']) is str) and (re.fullmatch('[1-9][0-9]*', identity['start_ticks']) is not None) and (identity['boot_id'] == request['PC_boot_id']) and (re.fullmatch('[0-9a-f]{32}', identity['invocation_id']) is not None), 'actual_current_PC_identity')
    need(request['nonce'] != '0' * 32, 'unused_real_renewal_nonce_not_template')
    ROOT = '/opt/dgx-v4/c-unarmed-renewal-r26-' + request['nonce']
    UNIT = 'dgx-v4-c-unarmed-renewal-r26-' + request['nonce'] + '.service'
    bodies = {n: v.replace(b'c-unarmed-renewal-r26-' + b'0' * 32, ('c-unarmed-renewal-r26-' + request['nonce']).encode()) for n, v in bodies.items()}
    data = {n: bodies[n] for n in DATA}
    data['readonly_once.py'] = bind(data['readonly_once.py'], 'APPROVED_READONLY_SOURCE_REVIEW_SHA256', r)
    for k, v in (('REQUEST_SHA', sha(request_raw)), ('REQUEST_NONCE', request['nonce'])):
        data['readonly_once.py'] = bind(data['readonly_once.py'], k, v)
    data['parent-review.raw'] = review_raw
    worker = bodies['worker.py']
    for k, v in (('ROLE', 'c'), ('ROOT', ROOT), ('DATA_PINS', {n: sha(b) for n, b in data.items()}), ('REVIEW_SHA', r), ('REQUEST_SHA', sha(request_raw)), ('REQUEST_NONCE', request['nonce'])):
        worker = bind(worker, k, v)
    data['worker.py'] = worker
    data['launch-and-capture.py'] = bind(worker, 'WORKER_SHA', sha(worker))
    need(len(data) == 8 and sum(map(len, data.values())) <= 2097152, 'fixed_stage8_bounded')
    sealer = bodies['seal.py']
    for k, v in (('APPROVED_BUNDLE', {n: base64.b64encode(b).decode() for n, b in data.items()}), ('APPROVED_ROLE', 'c'), ('APPROVED_REVIEW_SHA', r)):
        sealer = bind(sealer, k, v)
    return {'files': data, 'file_pins': {n: sha(b) for n, b in data.items()}, 'sealer': sealer, 'role': 'c', 'root': ROOT, 'unit': UNIT, 'request_raw': request_raw, 'request_sha256': sha(request_raw), 'source_review_sha256': r, 'native_called': False, 'nativeeligible': False}

def expected_pins(review_raw, request_raw, source_bodies):
    return materialize(review_raw, request_raw, source_bodies)['file_pins']

def request_command(plan):
    """Emit only the new Root request leaf O_EXCL; actual launch remains separate."""
    need(plan['root'] == '/opt/dgx-v4/c-unarmed-renewal-r26-' + strict(plan['request_raw'])['nonce'] and sha(plan['request_raw']) == plan['request_sha256'] and (plan['native_called'] is False), 'fixed_C_request_plan')
    return 'import pathlib,os,base64,importlib.util; p=pathlib.Path(' + repr(plan['root']) + "); s=importlib.util.spec_from_file_location('fixed_C_launcher',p/'launch-and-capture.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.context(); raw=base64.b64decode(" + repr(base64.b64encode(plan['request_raw']).decode()) + "); m.need(m.sha(raw)==m.REQUEST_SHA,'exact_request'); m.fresh(p/'request.json',raw)"

def fixed_entry(plan, mode):
    need(plan['root'] == '/opt/dgx-v4/c-unarmed-renewal-r26-' + strict(plan['request_raw'])['nonce'] and mode in ('launch', 'observe', 'capture-owned-stop') and (plan['native_called'] is False), 'fixed_C_parent_mode')
    return 'import pathlib,importlib.util,json; p=pathlib.Path(' + repr(plan['root']) + "); s=importlib.util.spec_from_file_location('fixed_C_launcher',p/'launch-and-capture.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.context(); result=m." + {'launch': 'launch', 'observe': 'observe', 'capture-owned-stop': 'capture_then_stop'}[mode] + '(); print(json.dumps(result,allow_nan=False))'
if __name__ == '__main__':
    print(json.dumps({'status': 'SOURCE_inert', 'nativeeligible': False, 'native_actions': 0}))
