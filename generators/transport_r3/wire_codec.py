# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
"""Transport-only reversible canonical pulse transform; carries no authority."""
import base64, binascii, hashlib, json, math, re, zlib
RAW_CAP = 4194304
COMPRESSED_CAP = 1048576
SCHEMA = 'parent-transport-lossless/v2'
PULSE_KEYS = {'PC_monotonic_elapsed', 'PC_received_at', 'PC_sent_at', 'operation', 'original_raw_b64', 'original_reply_raw_b64', 'original_reply_sha256', 'original_sha256'}
SKELETON_KEYS = {'PC_monotonic_elapsed', 'PC_received_at', 'PC_sent_at', 'operation', 'original_reply_raw_b64'}
KEYS = {'schema', 'encoding', 'transform', 'raw_bytes', 'raw_sha256', 'transport_bytes', 'transport_sha256', 'compressed_bytes', 'compressed_sha256', 'payload_b64'}

class Refused(ValueError):
    pass

def need(v, r):
    if not v:
        raise Refused(r)

def sha(b):
    return hashlib.sha256(b).hexdigest()

def encode(v):
    return (json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def strict(b):

    def pairs(xs):
        v = {}
        for k, x in xs:
            need(k not in v, 'wire_duplicate_key')
            v[k] = x
        return v
    return json.loads(b, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'wire_nonfinite'))

def decoded(text, cap):
    need(type(text) is str and len(text) <= 4 * ((cap + 2) // 3), 'wire_base64_cap')
    try:
        b = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise Refused('wire_strict_base64') from None
    need(len(b) <= cap and base64.b64encode(b).decode() == text, 'wire_canonical_base64')
    return b

def pulse(s):
    need(type(s) is dict and set(s) == SKELETON_KEYS, 'wire_exact_pulse_skeleton')
    need(type(s['operation']) is str and re.fullmatch('[0-9a-f]{32}', s['operation']), 'wire_original_operation')
    for k in ('PC_sent_at', 'PC_received_at', 'PC_monotonic_elapsed'):
        need(type(s[k]) in (int, float) and math.isfinite(s[k]), 'wire_original_clock_type')
    reply = decoded(s['original_reply_raw_b64'], 1048576)
    v = strict(reply)
    need(type(v) is dict and set(v) == {'ok', 'pulse'} and (v['ok'] is True) and (type(v['pulse']) is dict), 'wire_original_private_pulse')
    raw = encode(v['pulse'])
    need(0 < len(raw) <= 1048576, 'wire_original_private_pulse_cap')
    return dict(s, original_raw_b64=base64.b64encode(raw).decode(), original_sha256=sha(raw), original_reply_sha256=sha(reply))

def pack(raw):
    need(type(raw) is bytes and 0 < len(raw) <= RAW_CAP, 'wire_raw_fixed4MiB')
    transform = 'opaque/v1'
    data = raw
    try:
        v = strict(raw)
    except Refused:
        raise
    except (json.JSONDecodeError, UnicodeError):
        v = None
    if type(v) is dict and set(v) == PULSE_KEYS:
        s = {k: v[k] for k in SKELETON_KEYS}
        rebuilt = encode(pulse(s))
        need(rebuilt == raw, 'wire_exact_eight_fields_and_original_bytes')
        data = encode(s)
        transform = 'canonical-pulse8/v1'
    need(0 < len(data) <= RAW_CAP, 'wire_transport_fixed4MiB')
    compressed = zlib.compress(data, 9)
    need(0 < len(compressed) <= COMPRESSED_CAP, 'wire_compressed_fixed1MiB')
    return {'schema': SCHEMA, 'encoding': 'zlib+base64', 'transform': transform, 'raw_bytes': len(raw), 'raw_sha256': sha(raw), 'transport_bytes': len(data), 'transport_sha256': sha(data), 'compressed_bytes': len(compressed), 'compressed_sha256': sha(compressed), 'payload_b64': base64.b64encode(compressed).decode()}

def unpack(v):
    need(type(v) is dict and set(v) == KEYS and (v['schema'] == SCHEMA) and (v['encoding'] == 'zlib+base64') and (v['transform'] in ('opaque/v1', 'canonical-pulse8/v1')), 'wire_exact_envelope')
    for k, cap in (('raw_bytes', RAW_CAP), ('transport_bytes', RAW_CAP), ('compressed_bytes', COMPRESSED_CAP)):
        need(type(v[k]) is int and 0 < v[k] <= cap, 'wire_original_caps')
    for k in ('raw_sha256', 'transport_sha256', 'compressed_sha256'):
        need(type(v[k]) is str and re.fullmatch('[0-9a-f]{64}', v[k]), 'wire_exact_SHA')
    compressed = decoded(v['payload_b64'], COMPRESSED_CAP)
    need(len(compressed) == v['compressed_bytes'] and sha(compressed) == v['compressed_sha256'], 'wire_compressed_full_SHA')
    try:
        d = zlib.decompressobj()
        data = d.decompress(compressed, v['transport_bytes'] + 1)
    except zlib.error:
        raise Refused('wire_zlib_CRC_or_stream') from None
    need(len(data) == v['transport_bytes'] and d.eof and (not d.unused_data) and (not d.unconsumed_tail), 'wire_EOF_no_trailing_no_bomb')
    need(sha(data) == v['transport_sha256'], 'wire_transport_full_SHA')
    raw = encode(pulse(strict(data))) if v['transform'] == 'canonical-pulse8/v1' else data
    need(len(raw) == v['raw_bytes'] and len(raw) <= RAW_CAP and (sha(raw) == v['raw_sha256']), 'wire_exact_full_original_SHA')
    return raw
