# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Minimal new nonce-bound two-host entry clock, SOURCE-only default inert.
PC wall+monotonic age owns freshness; remoteA stamps are audit/order under the
actual configured30 policy. Does not install an epoch or reissue old entry.
"""
import base64, hashlib, json, math, re, time
APPROVED_POLICY = None
from stage_naming import PREFIX, unit as readiness_unit

class Refused(ValueError):
    pass

def need(v, r):
    if not v:
        raise Refused(r)

def sha(v):
    return hashlib.sha256(v).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(raw):
    need(type(raw) is bytes and len(raw) <= 2 * 1024 ** 2, 'bounded_clock_original_bytes')

    def pairs(xs):
        out = {}
        for k, v in xs:
            need(k not in out, 'duplicate_entry_clock_key')
            out[k] = v
        return out
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite_clock'))

def number(v):
    return type(v) in (int, float) and math.isfinite(v)

def f9(s, raw, *, gid, mode):
    need(type(s) is list and len(s) == 9 and all((type(x) is int for x in s)) and (s[0] > 0) and (s[1] > 0) and (s[7] >= 0) and (s[8] >= 0) and (s[2] == len(raw)) and (s[3:7] == [0, gid, 32768 | mode, 1]), 'entry_origin_exact_F9')
REQUEST_KEYS = {'schema', 'operation', 'nonce', 'source_review_sha256', 'manager_identity', 'current_PC_source118', 'PC_config_sha256', 'clock_policy_sha256', 'unit'}
MOMENT_KEYS = {'schema', 'nonce', 'PC_sent_at', 'PC_monotonic_sent', 'request_sha256', 'request_stat', 'manager_identity', 'PC_config_sha256'}
RESPONSE_KEYS = {'schema', 'nonce', 'request_raw_b64', 'request_sha256', 'request_stat', 'entry_raw_b64', 'entry_sha256', 'entry_stat', 'A_started_at', 'A_finished_at', 'A_monotonic_elapsed', 'owned_stop_calls', 'owned_stop_originals'}
CERT_KEYS = {'schema', 'nonce', 'request_sha256', 'request_stat', 'response_raw_sha256', 'entry_sha256', 'entry_origin_stat', 'PC_sent_at', 'PC_received_at', 'PC_monotonic_elapsed', 'source_review_sha256', 'clock_policy_sha256', 'manager_identity', 'PC_config_sha256', 'current_PC_source118'}
ENTRY_KEYS = {'schema', 'operation', 'producer_sha256', 'readonly_worker_sha256', 'actual_readonly_scope', 'manager_identity', 'current_PC_source118', 'PC_config_sha256', 'models_started', 'observed_at', 'result', 'source_index_sha256'}

def shape(v, keys, code):
    need(type(v) is dict and set(v) == keys, code)

def decode(v):
    need(type(v) is str and len(v) <= 2796204, 'bounded_clock_base64_type')
    raw = base64.b64decode(v, validate=True)
    need(base64.b64encode(raw).decode() == v, 'canonical_clock_base64')
    return raw

def identity_check(v):
    shape(v, {'pid', 'start_ticks', 'boot_id', 'invocation_id'}, 'exact_actual_manager_identity')
    need(type(v['pid']) is int and v['pid'] > 0 and (type(v['start_ticks']) is str) and re.fullmatch('[1-9][0-9]*', v['start_ticks']) and (type(v['boot_id']) is str) and re.fullmatch('[0-9a-f-]{36}', v['boot_id']) and (type(v['invocation_id']) is str) and re.fullmatch('[0-9a-f]{32}', v['invocation_id']), 'strict_actual_manager_identity')

def request_check(r, config, identity):
    p = policy()
    shape(r, REQUEST_KEYS, 'exact_request_original_keys')
    identity_check(identity)
    need(type(r['nonce']) is str and re.fullmatch('[0-9a-f]{32}', r['nonce']) and (r['schema'] == 'A-entry-clock-readonly-request/v1') and (r['operation'] == p['operation']) and (r['unit'] == readiness_unit(r['nonce'])), 'exact_new_request_scope')
    need(type(config['PC_source_pins']) is dict and len(config['PC_source_pins']) == 118 and all((type(k) is str and type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for k, v in config['PC_source_pins'].items())), 'exact_current118_source')
    need(r['source_review_sha256'] == config['review_sha256'] == p['source_review_sha256'] and r['manager_identity'] == identity and (r['current_PC_source118'] == config['PC_source_pins']) and (r['PC_config_sha256'] == config['_config_sha256']) and (r['clock_policy_sha256'] == p['clock_policy_sha256']), 'request_exact_current_epoch')

def entry_check(body, r):
    p = policy()
    shape(body, ENTRY_KEYS, 'exact_entry_original_keys')
    need(body['schema'] == 'registry-R26-A-entry-qualified/v1' and body['operation'] == r['operation'] == p['operation'] and (body['producer_sha256'] == p['producer_sha256']) and (body['readonly_worker_sha256'] == p['worker_sha256']) and (body['source_index_sha256'] == p['source_index_sha256']) and (body['result']['index_sha256'] == p['source_index_sha256']) and (body['actual_readonly_scope']['unit']['Id'] == r['unit'] == readiness_unit(r['nonce'])), 'entry_exact_new_scope_schema_source')
    need(body['manager_identity'] == r['manager_identity'] and body['current_PC_source118'] == r['current_PC_source118'] and (body['PC_config_sha256'] == r['PC_config_sha256']) and (type(body['models_started']) is int) and (body['models_started'] == 0) and number(body['observed_at']), 'entry_exact_current_epoch_and_source')
    result = body['result']
    need(type(result) is dict and result['payload_namespace_absent'] is True and (result['daemon_started'] is False) and (type(result['models_started']) is int) and (result['models_started'] == 0) and (type(result['MemAvailable_bytes']) is int) and (result['MemAvailable_bytes'] >= 8 * 1024 ** 3) and (type(result['NVMe_free_bytes']) is int) and (result['NVMe_free_bytes'] > 0), 'entry_actual_idle_resource_fields')

def originals(read, root, config, identity):
    req, rs = read(root / 'send.json')
    sr, ss = read(root / 'send-moment.json')
    r = strict(req)
    m = strict(sr)
    f9(rs, req, gid=989, mode=288)
    f9(ss, sr, gid=989, mode=288)
    request_check(r, config, identity)
    shape(m, MOMENT_KEYS, 'exact_send_moment_keys')
    need(m['schema'] == 'PC-A-entry-clock-send/v1' and m['nonce'] == r['nonce'] and (m['request_sha256'] == sha(req)) and (m['request_stat'] == rs) and (m['manager_identity'] == identity) and (m['PC_config_sha256'] == config['_config_sha256']) and all((number(m[k]) for k in ('PC_sent_at', 'PC_monotonic_sent'))), 'actual_send_moment_full_original_binding')
    return (req, rs, r, m)

def policy():
    need(type(APPROVED_POLICY) is dict and set(APPROVED_POLICY) == {'operation', 'source_review_sha256', 'producer_sha256', 'worker_sha256', 'clock_policy_sha256', 'source_index_sha256', 'max_clock_skew_seconds'}, 'entry_clock_source_literal_pending')
    for k in ('source_review_sha256', 'producer_sha256', 'worker_sha256', 'clock_policy_sha256', 'source_index_sha256'):
        need(type(APPROVED_POLICY[k]) is str and re.fullmatch('[0-9a-f]{64}', APPROVED_POLICY[k]), 'entry_policy_exact_SHA')
    need(type(APPROVED_POLICY['operation']) is str and re.fullmatch('[0-9a-f]{32}', APPROVED_POLICY['operation']), 'new_operation_literal')
    need(number(APPROVED_POLICY['max_clock_skew_seconds']) and APPROVED_POLICY['max_clock_skew_seconds'] == 30, 'actual_configured_clock_policy30_not_loosened')
    return APPROVED_POLICY

def request(config, identity, nonce):
    p = policy()
    need(re.fullmatch('[0-9a-f]{32}', nonce), 'new_actual_entry_nonce')
    need(len(config['PC_source_pins']) == 118 and config['review_sha256'] == p['source_review_sha256'], 'new_current118_source_review')
    raw = encode({'schema': 'A-entry-clock-readonly-request/v1', 'operation': p['operation'], 'nonce': nonce, 'source_review_sha256': p['source_review_sha256'], 'manager_identity': identity, 'current_PC_source118': config['PC_source_pins'], 'PC_config_sha256': config['_config_sha256'], 'clock_policy_sha256': p['clock_policy_sha256'], 'unit': readiness_unit(nonce)})
    request_check(strict(raw), config, identity)
    return raw

def begin(write, read, root, config, identity, nonce):
    raw = request(config, identity, nonce)
    path = root / 'send.json'
    write(path, raw, mode=288, gid=989)
    actual, stat = read(path)
    need(actual == raw, 'actual_entry_send_original')
    f9(stat, raw, gid=989, mode=288)
    sent = {'schema': 'PC-A-entry-clock-send/v1', 'nonce': nonce, 'PC_sent_at': time.time(), 'PC_monotonic_sent': time.monotonic(), 'request_sha256': sha(raw), 'request_stat': stat, 'manager_identity': identity, 'PC_config_sha256': config['_config_sha256']}
    write(root / 'send-moment.json', encode(sent), mode=288, gid=989)
    return {'request_raw_b64': base64.b64encode(raw).decode(), 'request_sha256': sha(raw), 'request_stat': stat, 'sent': sent}

def A_response(request_raw, request_stat, entry_raw, entry_stat, *, started_at, finished_at, elapsed, positive, stop_originals):
    """Called only after a NEW fixed readonly request/scope actualEXIT0+ownedstop.
 Full producer/Rootscope launcher still required; no success flag substitutes.
 """
    p = policy()
    r = strict(request_raw)
    shape(r, REQUEST_KEYS, 'exact_request_original_keys')
    f9(request_stat, request_raw, gid=0, mode=384)
    f9(entry_stat, entry_raw, gid=0, mode=384)
    v = strict(entry_raw)
    entry_check(v, r)
    need(r['schema'] == 'A-entry-clock-readonly-request/v1' and r['operation'] == v['operation'] == p['operation'] and (r['source_review_sha256'] == p['source_review_sha256']) and (r['clock_policy_sha256'] == p['clock_policy_sha256']), 'new_scope_request_policy')
    need(v['producer_sha256'] == p['producer_sha256'] and v['readonly_worker_sha256'] == p['worker_sha256'] and (v['actual_readonly_scope']['unit']['Id'] == r['unit'] == readiness_unit(r['nonce'])), 'fresh_independent_entry_scope_not_old_entry')
    positive(v['actual_readonly_scope'], r['unit'], p['worker_sha256'], True)
    need(all((number(x) for x in (started_at, finished_at, elapsed, v['observed_at']))) and 0 <= elapsed <= 90 and (started_at <= v['observed_at'] <= finished_at) and (0 <= finished_at - started_at <= 90), 'A_local_scope_clock_order_and90')
    need(v['manager_identity'] == r['manager_identity'] and v['current_PC_source118'] == r['current_PC_source118'] and (v['PC_config_sha256'] == r['PC_config_sha256']), 'A_entry_current_exact_request_epoch')
    return encode({'schema': 'A-entry-clock-returned-original/v1', 'nonce': r['nonce'], 'request_raw_b64': base64.b64encode(request_raw).decode(), 'request_sha256': sha(request_raw), 'request_stat': request_stat, 'entry_raw_b64': base64.b64encode(entry_raw).decode(), 'entry_sha256': sha(entry_raw), 'entry_stat': entry_stat, 'A_started_at': started_at, 'A_finished_at': finished_at, 'A_monotonic_elapsed': elapsed, 'owned_stop_calls': 1, 'owned_stop_originals': stop_originals})

def stop_check(v, body):
    stops = v['owned_stop_originals']
    shape(stops, {'entry-stop-intent.json', 'entry-stop-result.json'}, 'complete_actual_owned_stop_originals')
    rows = {}
    for name, item in stops.items():
        shape(item, {'raw_b64', 'sha256', 'stat'}, 'exact_stop_origin')
        raw = decode(item['raw_b64'])
        need(sha(raw) == item['sha256'], 'stop_original_full_SHA')
        f9(item['stat'], raw, gid=0, mode=384)
        rows[name] = strict(raw)
    intent = rows['entry-stop-intent.json']
    result = rows['entry-stop-result.json']
    shape(intent, {'unit', 'InvocationID', 'receipt_sha256', 'observed_at'}, 'actual_stop_intent_schema')
    shape(result, {'rc', 'stdout_b64', 'stderr_b64', 'observed_at'}, 'actual_stop_result_schema')
    need(intent['unit'] == body['actual_readonly_scope']['unit']['Id'] and intent['InvocationID'] == body['actual_readonly_scope']['unit']['InvocationID'] and (intent['receipt_sha256'] == v['entry_sha256']) and (type(result['rc']) is int) and (result['rc'] == 0) and (decode(result['stderr_b64']) == b'') and (len(decode(result['stdout_b64'])) <= 65536), 'same_owned_scope_actual_stop0_not_bool')
    need(all((number(x) for x in (intent['observed_at'], result['observed_at']))) and v['A_started_at'] <= body['observed_at'] <= intent['observed_at'] <= result['observed_at'] <= v['A_finished_at'], 'actual_stop_time_chain')

def finish(read, write, root, response_raw, config, identity, *, positive):
    p = policy()
    req, rs, r, m = originals(read, root, config, identity)
    v = strict(response_raw)
    shape(v, RESPONSE_KEYS, 'exact_response_original_keys')
    now = time.time()
    mono = time.monotonic()
    duration = mono - m['PC_monotonic_sent']
    wall = now - m['PC_sent_at']
    need(v['schema'] == 'A-entry-clock-returned-original/v1' and v['nonce'] == r['nonce'] == m['nonce'] and (v['request_sha256'] == sha(req) == m['request_sha256']) and (rs == m['request_stat']) and (decode(v['request_raw_b64']) == req) and (type(v['owned_stop_calls']) is int) and (v['owned_stop_calls'] == 1), 'same_complete_new_request_no_replay_or_retime')
    f9(v['request_stat'], req, gid=0, mode=384)
    need(all((number(x) for x in (duration, wall, now, mono, v['A_started_at'], v['A_finished_at'], v['A_monotonic_elapsed']))) and 0 <= duration <= 90 and (0 <= wall <= 90) and (abs(wall - duration) <= p['max_clock_skew_seconds']), 'PC_actual_whole_readonly90')
    need(0 <= v['A_monotonic_elapsed'] <= 90 and 0 <= v['A_finished_at'] - v['A_started_at'] <= 90 and (abs(v['A_finished_at'] - v['A_started_at'] - v['A_monotonic_elapsed']) <= 30) and (m['PC_sent_at'] - 30 <= v['A_started_at'] <= v['A_finished_at'] <= now + 30), 'remote_stamps_within_actual_configured30')
    entry = decode(v['entry_raw_b64'])
    need(sha(entry) == v['entry_sha256'], 'entry_full_original_SHA')
    f9(v['entry_stat'], entry, gid=0, mode=384)
    body = strict(entry)
    entry_check(body, r)
    need(body['producer_sha256'] == p['producer_sha256'] and body['readonly_worker_sha256'] == p['worker_sha256'] and (body['source_index_sha256'] == p['source_index_sha256']) and (body['result']['index_sha256'] == p['source_index_sha256']) and (body['actual_readonly_scope']['unit']['Id'] == r['unit']) and (v['A_started_at'] <= body['observed_at'] <= v['A_finished_at']), 'same_actual_localA_entry_source_and_order')
    need(body['manager_identity'] == r['manager_identity'] and body['current_PC_source118'] == r['current_PC_source118'] and (body['PC_config_sha256'] == r['PC_config_sha256']) and (body['operation'] == r['operation']), 'entry_finish_exact_current_epoch')
    positive(body['actual_readonly_scope'], r['unit'], p['worker_sha256'], True)
    stop_check(v, body)
    out = {'schema': 'PC-A-entry-clock-received/v1', 'nonce': r['nonce'], 'request_sha256': sha(req), 'request_stat': rs, 'response_raw_sha256': sha(response_raw), 'entry_sha256': sha(entry), 'entry_origin_stat': v['entry_stat'], 'PC_sent_at': m['PC_sent_at'], 'PC_received_at': now, 'PC_monotonic_elapsed': duration, 'source_review_sha256': p['source_review_sha256'], 'clock_policy_sha256': p['clock_policy_sha256'], 'manager_identity': r['manager_identity'], 'PC_config_sha256': r['PC_config_sha256'], 'current_PC_source118': r['current_PC_source118']}
    write(root / 'response.json', response_raw, mode=288, gid=989)
    write(root / 'received.json', encode(out), mode=288, gid=989)
    return out

def consume(read, root, config, identity, now, *, positive, validate_resources):
    p = policy()
    req, rs, r, m = originals(read, root, config, identity)
    cr, cs = read(root / 'received.json')
    c = strict(cr)
    rr, st = read(root / 'response.json')
    v = strict(rr)
    shape(c, CERT_KEYS, 'exact_received_certificate_keys')
    shape(v, RESPONSE_KEYS, 'exact_response_original_keys')
    entry = decode(v['entry_raw_b64'])
    f9(cs, cr, gid=989, mode=288)
    f9(st, rr, gid=989, mode=288)
    f9(v['request_stat'], req, gid=0, mode=384)
    f9(v['entry_stat'], entry, gid=0, mode=384)
    need(v['schema'] == 'A-entry-clock-returned-original/v1' and decode(v['request_raw_b64']) == req and (type(v['owned_stop_calls']) is int) and (v['owned_stop_calls'] == 1) and all((number(v[k]) for k in ('A_started_at', 'A_finished_at', 'A_monotonic_elapsed'))) and (0 <= v['A_monotonic_elapsed'] <= 90) and (0 <= v['A_finished_at'] - v['A_started_at'] <= 90) and (abs(v['A_finished_at'] - v['A_started_at'] - v['A_monotonic_elapsed']) <= 30), 'complete_response_clock_original')
    need(number(c['PC_sent_at']) and c['PC_sent_at'] == m['PC_sent_at'] and number(c['PC_received_at']) and (0 <= c['PC_received_at'] - c['PC_sent_at'] <= 90) and number(c['PC_monotonic_elapsed']) and (abs(c['PC_received_at'] - c['PC_sent_at'] - c['PC_monotonic_elapsed']) <= 30) and (c['PC_sent_at'] - 30 <= v['A_started_at'] <= v['A_finished_at'] <= c['PC_received_at'] + 30), 'certificate_original_local_and_remote_order')
    need(c['schema'] == 'PC-A-entry-clock-received/v1' and c['source_review_sha256'] == config['review_sha256'] == p['source_review_sha256'] and (c['manager_identity'] == identity) and (c['current_PC_source118'] == config['PC_source_pins']) and (c['PC_config_sha256'] == config['_config_sha256']) and (c['clock_policy_sha256'] == p['clock_policy_sha256']), 'current_entry_clock_certificate_not_historical')
    need(c['nonce'] == v['nonce'] == r['nonce'] and c['request_sha256'] == sha(req) == v['request_sha256'] and (rs == c['request_stat']) and (c['response_raw_sha256'] == sha(rr)) and (c['entry_sha256'] == sha(entry) == v['entry_sha256']) and (c['entry_origin_stat'] == v['entry_stat']), 'full_immutable_clock_and_origin_chain')
    need(number(now) and number(c['PC_received_at']) and number(c['PC_monotonic_elapsed']) and (0 <= now - c['PC_received_at']) and (0 <= c['PC_monotonic_elapsed'] <= 90) and (c['PC_monotonic_elapsed'] + now - c['PC_received_at'] <= 300), 'PC_local_conservative_age300_not_remote_wall')
    body = strict(entry)
    entry_check(body, r)
    need(v['A_started_at'] <= body['observed_at'] <= v['A_finished_at'], 'consume_original_A_order')
    need(body['operation'] == p['operation'] and body['producer_sha256'] == p['producer_sha256'] and (body['readonly_worker_sha256'] == p['worker_sha256']) and (body['manager_identity'] == identity) and (body['current_PC_source118'] == config['PC_source_pins']) and (body['PC_config_sha256'] == config['_config_sha256']), 'entry_consumer_exact_current_epoch_and_producer')
    positive(body['actual_readonly_scope'], r['unit'], p['worker_sha256'], True)
    stop_check(v, body)
    validate_resources(body)
    return {'entry_original': body, 'entry_sha256': sha(entry), 'clock_raw_sha256': sha(cr), 'historical_only': False, 'nonce': c['nonce']}
if __name__ == '__main__':
    raise SystemExit('SOURCE_ONLY_epoch_and_new_producer_pending_no_native')
