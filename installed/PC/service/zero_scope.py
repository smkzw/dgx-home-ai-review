# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Fresh independent readonly scope; aggregate never-launched is not EXIT0.
All slots are final SOURCE data, not arguments from a public request.
"""
import base64, re
from plan import need, strict, encode
from root_io import sha
from ready_history import positive
from old_failed_kernel import validate_failed_kernel
import zero_negative
APPROVED_SCOPE = None

def original(r):
    need(type(r) is dict and set(r) == {'raw_b64', 'sha256', 'F9'}, 'zero_scope_full_original')
    b = base64.b64decode(r['raw_b64'], validate=True)
    f = r['F9']
    need(len(f) == 9 and f[2] == len(b) and (f[3:7] == [0, 0, 33152, 1]) and (sha(b) == r['sha256']), 'zero_scope_Root_raw_SHA_F9')
    return b

def validate(v, history_raw, current):
    p = APPROVED_SCOPE
    need(type(p) is dict and set(p) == {'unit', 'worker_sha256', 'worker_path', 'operation', 'nonce'}, 'zero_scope_reviewed_SOURCE_None')
    need(type(v) is dict and set(v) == {'schema', 'request_nonce', 'body_original', 'scope', 'owned_stop_originals', 'kernel_original'} and (v['schema'] == 'fixed-zero-launch-readonly-scope/v1') and (v['request_nonce'] == p['nonce']), 'zero_scope_exact_fresh_type_nonce')
    scope = v['scope']
    b = positive(scope, p['unit'], p['worker_sha256'], True, operation=p['operation'])
    need(scope['worker_source']['path'] == p['worker_path'], 'zero_scope_exact_pinned_readonly_worker')
    bodyraw = original(v['body_original'])
    body = strict(bodyraw)
    r = zero_negative.checked_request(zero_negative.original(body['request_original']), current)
    need(r['nonce'] == p['nonce'], 'zero_scope_inner_request_nonce')
    zero_negative.validate(body, history_raw, current)
    stops = v['owned_stop_originals']
    need(type(stops) is dict and set(stops) == {'stop-intent.json', 'stop-result.json'}, 'zero_scope_archive_owned_stop_once')
    i, s = (strict(original(stops[n])) for n in ('stop-intent.json', 'stop-result.json'))
    need(i['unit'] == p['unit'] and i['invocation_id'] == scope['unit']['InvocationID'] and (i['body_sha256'] == sha(bodyraw)) and (type(s['rc']) is int) and (s['rc'] == 0) and (base64.b64decode(s['stderr_b64'], validate=True) == b'') and (i['observed_at'] <= s['observed_at']), 'zero_scope_real_saved_ownedstop_not_count')
    validate_failed_kernel(v['kernel_original'], p['unit'], b['worker_pid'], scope['boot_id'], body['started_at'])
    need(v['kernel_original']['finished_at'] >= s['observed_at'], 'zero_scope_fresh_poststop_kernel')
    return body

def produce(body_raw, body_F9, scope, owned_stop_originals, kernel_original, history_raw, current):
    p = APPROVED_SCOPE
    need(type(p) is dict, 'zero_scope_SOURCE_None')
    v = {'schema': 'fixed-zero-launch-readonly-scope/v1', 'request_nonce': p['nonce'], 'body_original': {'raw_b64': base64.b64encode(body_raw).decode(), 'sha256': sha(body_raw), 'F9': body_F9}, 'scope': scope, 'owned_stop_originals': owned_stop_originals, 'kernel_original': kernel_original}
    validate(v, history_raw, current)
    return v
