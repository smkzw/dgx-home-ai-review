# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Pure original C scope/data consumer; clock comes from genuine protected PC IO."""
import ast, base64, json, hashlib, math, stat, types
from pathlib import Path
APPROVED_C_REVIEW_RAW = None
APPROVED_C_SOURCE_BODIES = None
APPROVED_R26_REVIEW = None
PC_ROOT = Path('/opt/dgx-v4/hx/mimo-registry-native-r26-r6/c-arm-r26/renewals')
ROOT = '/opt/dgx-v4/c-unarmed-renewal-r26-2d8bb6adefd99ead39104bf44bf247d9'
UNIT = 'dgx-v4-c-unarmed-renewal-r26-2d8bb6adefd99ead39104bf44bf247d9.service'
FIELDS = ('st_dev', 'st_ino', 'st_size', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')

def need(v, k):
    if not v:
        raise ValueError(k)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):

    def pairs(xs):
        out = {}
        for k, v in xs:
            need(k not in out, 'duplicate_JSON')
            out[k] = v
        return out
    out = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_JSON'))
    encode(out)
    return out

def f9(v, raw, *, gid, mode):
    need(type(v) is list and len(v) == 9 and all((type(x) is int for x in v)) and (v[2] == len(raw)) and (v[3:7] == [0, gid, stat.S_IFREG | mode, 1]) and (0 <= v[2] <= 4194304), 'exact_original_Root_fullF9')
    return v

class BoundFiles:

    def __init__(self, bodies, name=None):
        self.bodies = bodies
        self.name = name

    def __truediv__(self, name):
        need(name in ('ANCHORS.json', 'Root_C_pins.json', 'old_three.json'), 'fixed_pure_C_resource')
        return BoundFiles(self.bodies, name)

    def read_bytes(self):
        return self.bodies[self.name]

def definitions(raw, name):
    tree = ast.parse(raw)
    code = '\n'.join((ast.get_source_segment(raw.decode(), n) for n in tree.body if not (isinstance(n, ast.Assign) and any((isinstance(t, ast.Name) and t.id in ('HERE', 'A') for t in n.targets)))))
    m = types.ModuleType(name)
    m.__file__ = ROOT + '/' + name + '.py'
    exec(compile(code, m.__file__, 'exec'), m.__dict__)
    return m

def consume_current_C(receipt_raw, receipt_stat, clock, config, now):
    need(APPROVED_C_REVIEW_RAW is not None and APPROVED_C_SOURCE_BODIES is not None and (APPROVED_R26_REVIEW is not None), 'current_C_consumer_SOURCE_pending')
    bodies = APPROVED_C_SOURCE_BODIES
    build = types.ModuleType('fixed_pure_C_build')
    build.__file__ = str(PC_ROOT / 'held-renewal-build.py')
    exec(compile(bodies['build.py'], build.__file__, 'exec'), build.__dict__)
    f9(receipt_stat, receipt_raw, gid=0, mode=384)
    r = strict(receipt_raw)
    import re
    need(type(r['nonce']) is str and re.fullmatch('[0-9a-f]{32}', r['nonce']) is not None and (r['nonce'] != '0' * 32), 'new_renewal_namespace_nonce')
    ROOT = '/opt/dgx-v4/c-unarmed-renewal-r26-' + r['nonce']
    UNIT = 'dgx-v4-c-unarmed-renewal-r26-' + r['nonce'] + '.service'
    need(r['schema'] == 'c-unarmed-renewal-R26-owned-readonly-completed/v1' and r['role'] == 'c' and (r['root'] == ROOT) and (r['unit'] == UNIT) and (r['ARM_or_trial_accepted'] is False), 'actual_new_C_readonly_scope_not_ARM')
    request = r['request_original']
    request_raw = base64.b64decode(request['raw_b64'], validate=True)
    need(sha(request_raw) == request['sha256'], 'actual_received_request_raw')
    f9(request['stat'], request_raw, gid=0, mode=384)
    req = strict(request_raw)
    expected = build.expected_pins(APPROVED_C_REVIEW_RAW, request_raw, bodies)
    review = sha(APPROVED_C_REVIEW_RAW)
    need(r['source_review_sha256'] == review and r['nonce'] == req['nonce'] and (req['PC_config_sha256'] == config['_config_sha256']) and (req['PC_boot_id'] == config['_manager_identity']['boot_id']) and (req['PC_manager_identity'] == config['_manager_identity']) and (encode(req['PC_manager_identity']) == encode(config['_manager_identity'])), 'actual_C_request_nonce_PC_config_boot_review')
    sources = r['source_originals']
    need(set(sources) == set(expected) and len(sources) == 8, 'actual_materialized_C_source8')
    for name, pin in expected.items():
        original = sources[name]
        raw = base64.b64decode(original['raw_b64'], validate=True)
        need(sha(raw) == original['sha256'] == pin, 'actual_source8_not_self_reported')
        f9(original['stat'], raw, gid=0, mode=384)
    need(base64.b64decode(sources['parent-review.raw']['raw_b64'], validate=True) == APPROVED_C_REVIEW_RAW, 'exact_complete_C_source_review_original')
    originals = {}
    for name in ('intent.json', 'returned.json', 'worker-completed.json', 'stdout.raw', 'stderr.raw', 'candidate-before-validation.raw.json'):
        item = r['originals'][name]
        raw = base64.b64decode(item['raw_b64'], validate=True)
        need(sha(raw) == item['sha256'], 'actual_scope_original_SHA')
        f9(item['stat'], raw, gid=0, mode=384)
        originals[name] = raw
    intent = strict(originals['intent.json'])
    returned = strict(originals['returned.json'])
    done = strict(originals['worker-completed.json'])
    payload = strict(originals['stdout.raw'])
    need(intent == r['intent'] and returned == r['returned'] and (done == r['worker_completed']) and (payload == r['actual_result']) and (strict(originals['candidate-before-validation.raw.json']) == payload) and (not originals['stderr.raw']), 'actual_scope_payload_candidate_raw')
    need(intent['unit'] == UNIT and intent['role'] == 'c' and (intent['nonce'] == r['nonce']) and (intent['request_original'] == request) and (intent['source_review_sha256'] == review) and (intent['automatic_retry'] is False), 'actual_new_once_request_intent')
    need(intent['worker_sha256'] == expected['worker.py'] and intent['worker_stat'] == sources['worker.py']['stat'], 'exact_scope_worker_fullF9')
    data = {n: {'sha256': expected[n], 'stat': sources[n]['stat']} for n in ('readonly_once.py', 'validate.py', 'ANCHORS.json', 'Root_C_pins.json', 'old_three.json', 'parent-review.raw')}
    need(intent['five_source'] == data, 'actual_complete_collector_data6')
    for value in (returned, done):
        need(all((value[k] == intent[k] for k in ('role', 'unit', 'worker_pid', 'boot_id', 'invocation_id', 'worker_sha256', 'worker_stat', 'five_source', 'source_review_sha256', 'request_original', 'nonce'))), 'same_worker_source_request_identity')
    need(returned['child_rc'] == 0 and done['actual_Root_collector_rc'] == 0 and (done['ARM_or_model_POST'] == 0) and (r['stdout_sha256'] == returned['stdout_sha256'] == done['stdout_sha256'] == sha(originals['stdout.raw'])) and (r['stdout_stat'] == r['originals']['stdout.raw']['stat']) and (r['stderr_sha256'] == returned['stderr_sha256'] == sha(originals['stderr.raw'])) and (r['stderr_stat'] == r['originals']['stderr.raw']['stat']), 'actual_positive_child_output')
    terminal = r['actual_retained_EXIT0']
    u = terminal['unit']
    unitraw = base64.b64decode(terminal['unit_raw_b64'], validate=True)
    need(sha(unitraw) == terminal['unit_raw_sha256'] and dict((line.split('=', 1) for line in unitraw.decode().splitlines())) == u, 'original_retained_unit_raw')
    need(u['LoadState'] == 'loaded' and u['ActiveState'] == 'active' and (u['SubState'] == 'exited') and (u['MainPID'] == '0') and (u['ExecMainCode'] == '1') and (u['ExecMainStatus'] == '0') and (u['NRestarts'] == '0') and (u['Result'] == 'success') and (u['Type'] == 'exec') and (u['User'] == u['Group'] == 'root') and (u['KillMode'] == 'control-group') and ('argv[]=/usr/bin/python3 -I -B ' + ROOT + '/worker.py --worker ;' in u['ExecStart']) and (u['InvocationID'] == intent['invocation_id']) and (int(u['ExecMainPID']) == intent['worker_pid']) and (terminal['boot_id'] == intent['boot_id'] == payload['boot_id']) and (terminal['cgroup_procs'] == []) and (u['ControlGroup'] in ('', '/system.slice/' + UNIT)), 'retained_true_new_C_EXIT0_invocation_worker_boot')
    need(u['CPUQuotaPerSecUSec'] == '1s' and u['MemoryMax'] == '201326592' and (u['MemorySwapMax'] == '0') and (u['TasksMax'] == '32') and (u['Nice'] == '10') and (u['IOSchedulingClass'] == '3') and (u['RuntimeMaxUSec'] == '2min') and (u['SendSIGKILL'] == 'no') and (u['Restart'] == 'no') and (u['RemainAfterExit'] == 'yes'), 'actual_C_CPU1_192M_swap0_tasks32_scope')
    need(payload['schema'] == 'g8-C-R25-C-current-readonly/v1' and payload['native_model_POST'] == 0 and (intent['observed_at'] <= payload['observed_at'] <= returned['observed_at'] <= done['observed_at'] <= terminal['observed_at'] <= r['observed_at']), 'original_current_C_scope_time_order')
    validate = definitions(bodies['validate.py'], 'pure_C_validate')
    validate.HERE = BoundFiles(bodies)
    validate.A = strict(bodies['ANCHORS.json'])
    validate.c(payload, payload['observed_at'])
    keys = {'schema', 'nonce', 'PC_sent_at', 'PC_received_at', 'PC_monotonic_elapsed', 'PC_boot_id', 'PC_config_sha256', 'source_review_sha256', 'original_send_sha256', 'original_send_stat', 'PC_manager_identity'}
    need(type(clock) is dict and set(clock) == keys and (clock['schema'] == 'PC-C-R26-renewal-readonly-clock/v1') and (clock['nonce'] == req['nonce']) and (clock['PC_manager_identity'] == req['PC_manager_identity']) and (encode(clock['PC_manager_identity']) == encode(req['PC_manager_identity'])) and (clock['PC_boot_id'] == req['PC_boot_id']) and (clock['PC_config_sha256'] == req['PC_config_sha256']) and (clock['source_review_sha256'] == APPROVED_R26_REVIEW) and (clock['original_send_sha256'] == sha(request_raw)), 'actual_protected_PC_clock_request_binding')
    f9(clock['original_send_stat'], request_raw, gid=989, mode=288)
    for value in (now, clock['PC_sent_at'], clock['PC_received_at'], clock['PC_monotonic_elapsed'], config['max_clock_skew_seconds']):
        need(type(value) in (int, float) and math.isfinite(value), 'finite_actual_PC_clock')
    wall = clock['PC_received_at'] - clock['PC_sent_at']
    mono = clock['PC_monotonic_elapsed']
    lag = now - clock['PC_received_at']
    skew = config['max_clock_skew_seconds']
    need(0 <= skew <= 30 and 0 <= wall <= 120 and (0 <= mono <= 120) and (lag >= 0) and (abs(wall - mono) <= skew), 'conservative_nonnegative_PC_wall_mono_elapsed')
    need(clock['PC_sent_at'] - skew <= intent['observed_at'] <= r['observed_at'] <= clock['PC_received_at'] + skew, 'actual_C_scope_within_PC_request_interval')
    for frame in payload['preflights']:
        need(intent['observed_at'] <= frame['sent_at'] <= frame['reply']['observed_at'] <= frame['received_at'] <= payload['observed_at'], 'new_scope_original_three_frame_causality')
        need(clock['PC_sent_at'] - skew <= frame['sent_at'] <= frame['received_at'] <= clock['PC_received_at'] + skew, 'whole_original_frame_inside_PC_interval')
    need(0 <= mono + lag <= 10, 'whole_transport_conservative_C_age10')
    return {'schema': 'C-unarmed-R26-renewal-current-consumed/v1', 'nonce': req['nonce'], 'payload': payload, 'source_review_sha256': review, 'receipt_sha256': sha(receipt_raw), 'receipt_stat': receipt_stat, 'clock_original': clock, 'fresh_current_C_only': True, 'ARM_or_model_POST': 0, 'originals_retained': r}

def consume(read, clock, config, now):
    import re
    need(type(clock['nonce']) is str and re.fullmatch('[0-9a-f]{32}', clock['nonce']) is not None, 'fixed_renewal_receipt_namespace')
    parent = PC_ROOT / clock['nonce']
    raw, mirrorstat = read(parent / 'C-receipt.json', limit=4194304)
    f9(mirrorstat, raw, gid=989, mode=288)
    origin, originstat = read(parent / 'C-origin.json', limit=4194304)
    f9(originstat, origin, gid=989, mode=288)
    value = strict(origin)
    need(set(value) == {'origin_stat', 'origin_sha256'} and value['origin_sha256'] == sha(raw), 'Spark_original_bound_to_PC_mirror')
    return consume_current_C(raw, value['origin_stat'], clock, config, now)
if __name__ == '__main__':
    print(json.dumps({'status': 'SOURCE_inert', 'nativeeligible': False, 'native_actions': 0}))
