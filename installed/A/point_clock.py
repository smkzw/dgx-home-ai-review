# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Explicit PC sole-event interval; original RPC endpoints never restamped."""
import base64, hashlib, json, math, re
SCHEMA = 'registry-R26-sole-pulse-point-clock/v1'

class Refused(ValueError):
    pass

def need(v, r):
    if not v:
        raise Refused(r)

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def sha(b):
    return hashlib.sha256(b).hexdigest()

def strict(raw):
    need(type(raw) is bytes and len(raw) <= 4194304, 'point_clock_bounded_raw')

    def pairs(xs):
        d = {}
        for k, v in xs:
            need(k not in d, 'point_clock_duplicate_key')
            d[k] = v
        return d
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'point_clock_nonfinite'))

def number(v):
    return type(v) in (int, float) and math.isfinite(v)

def raw(v):
    need(type(v) is dict and set(v) == {'raw_b64', 'sha256'}, 'point_clock_full_socket_original_not_file_F9')
    b = base64.b64decode(v['raw_b64'], validate=True)
    need(sha(b) == v['sha256'], 'point_clock_original_SHA')
    return b

def event(frame):
    need(type(frame) is dict and set(frame) in ({'operation', 'original_raw_b64', 'original_sha256', 'PC_sent_at', 'PC_received_at', 'PC_monotonic_elapsed', 'original_reply_raw_b64', 'original_reply_sha256'}, {'operation', 'original_raw_b64', 'original_sha256', 'PC_sent_at', 'PC_received_at', 'PC_monotonic_elapsed', 'original_reply_raw_b64', 'original_reply_sha256', 'A_received_at'}), 'point_clock_actual_frame_shape')
    p = base64.b64decode(frame['original_raw_b64'], validate=True)
    reply = base64.b64decode(frame['original_reply_raw_b64'], validate=True)
    v = strict(p)
    r = strict(reply)
    need(sha(p) == frame['original_sha256'] and sha(reply) == frame['original_reply_sha256'] and (r == {'ok': True, 'pulse': v}) and (encode(v) == p), 'point_clock_exact_private_pulse_reply')
    need(v['operation'] == frame['operation'] and type(v['ordinal']) is int and (v['ordinal'] > 0) and re.fullmatch('[0-9a-f]{32}', v['request_nonce']) and all((number(x) for x in (frame['PC_sent_at'], frame['PC_received_at'], frame['PC_monotonic_elapsed'], v['observed_at']))) and (frame['PC_sent_at'] <= v['observed_at'] <= frame['PC_received_at']) and (0 <= frame['PC_monotonic_elapsed'] <= 5), 'point_clock_actual_sole_event_inside_original_PC_phase')
    return v

def make(before_raw, frame, after_raw):
    p = event(frame)
    a, b = (strict(before_raw), strict(after_raw))
    need(type(a) is dict and type(b) is dict, 'point_clock_original_A_dicts')
    return {'schema': SCHEMA, 'A_before_original': {'raw_b64': base64.b64encode(before_raw).decode(), 'sha256': sha(before_raw)}, 'A_after_original': {'raw_b64': base64.b64encode(after_raw).decode(), 'sha256': sha(after_raw)}, 'PC_frame_sha256': sha(encode({k: v for k, v in frame.items() if k != 'A_received_at'})), 'PC_event_at': p['observed_at'], 'pulse_sha256': frame['original_sha256'], 'ordinal': p['ordinal'], 'request_nonce': p['request_nonce'], 'reservation_sha256': p['clear_reservation_sha256']}

def consume(clock, c):
    need(type(clock) is dict and set(clock) == {'schema', 'A_before_original', 'A_after_original', 'PC_frame_sha256', 'PC_event_at', 'pulse_sha256', 'ordinal', 'request_nonce', 'reservation_sha256'} and (clock['schema'] == SCHEMA), 'point_clock_exact_new_type')
    frame = c['initial_pulse_original']
    p = event(frame)
    a, b = (strict(raw(clock[k])) for k in ('A_before_original', 'A_after_original'))
    keys = {'nonce', 'A_observed_at', 'A_monotonic', 'source_sha256', 'boot_id'}
    need(set(a) == set(b) == keys, 'point_clock_actual_A_clock_schema')
    need(a['boot_id'] == b['boot_id'] == c['A_boot_id'] and a['source_sha256'] == b['source_sha256'] == c['context_producer_sha256'] and re.fullmatch('[0-9a-f]{64}', a['source_sha256']) and all((type(x) is str and re.fullmatch('[0-9a-f]{32}', x) for x in (a['nonce'], b['nonce']))) and (a['nonce'] != b['nonce']), 'point_clock_same_source_boot_distinct_requests')
    need(all((number(v) for v in (a['A_observed_at'], b['A_observed_at'], a['A_monotonic'], b['A_monotonic']))) and 0 <= b['A_monotonic'] - a['A_monotonic'] <= 5 and (0 <= b['A_observed_at'] - a['A_observed_at'] <= 5), 'point_clock_original_A_bracket5')
    need(clock['PC_frame_sha256'] == sha(encode({k: v for k, v in frame.items() if k != 'A_received_at'})) and clock['PC_event_at'] == p['observed_at'] and (clock['pulse_sha256'] == frame['original_sha256']) and (type(clock['ordinal']) is int) and (clock['ordinal'] == p['ordinal']) and (clock['request_nonce'] == p['request_nonce']) and (clock['reservation_sha256'] == p['clear_reservation_sha256']), 'point_clock_complete_original_sole_event_binding')
    need(frame['A_received_at'] >= b['A_observed_at'], 'point_clock_A_local_receipt_order')
    lower = a['A_observed_at'] - p['observed_at']
    upper = b['A_observed_at'] - p['observed_at']
    need(lower <= upper and upper - lower <= 5, 'point_clock_width5_unchanged')
    return (lower, upper)
