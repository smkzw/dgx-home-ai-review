# REVIEW-ONLY SANITIZED SOURCE: data/constants redacted; not deployable; original licenses apply.
import sys, json, base64, zlib, hashlib, io
b = sys.stdin.buffer.read(4194305)
assert 0 < len(b) <= 4194304

def pairs(xs):
    v = {}
    for k, x in xs:
        assert k not in v
        v[k] = x
    return v
v = json.loads(b, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
assert type(v) is dict and set(v) == {'schema', 'runner', 'payload'} and (v['schema'] == 'reserved-parent-short-runner/v1')
e = v['runner']
assert type(e) is dict and set(e) == {'schema', 'encoding', 'raw_bytes', 'raw_sha256', 'compressed_bytes', 'compressed_sha256', 'payload_b64'} and (e['schema'] == 'reserved-parent-RPC-lossless/v1') and (e['encoding'] == 'zlib+base64') and (type(e['raw_bytes']) is int) and (0 < e['raw_bytes'] <= 32768) and (type(e['compressed_bytes']) is int) and (0 < e['compressed_bytes'] <= 32768) and (type(e['payload_b64']) is str) and (len(e['payload_b64']) <= 43692)
c = base64.b64decode(e['payload_b64'], validate=True)
assert len(c) == e['compressed_bytes'] and base64.b64encode(c).decode() == e['payload_b64'] and (hashlib.sha256(c).hexdigest() == e['compressed_sha256'])
d = zlib.decompressobj()
s = d.decompress(c, e['raw_bytes'] + 1)
assert len(s) == e['raw_bytes'] and d.eof and (not d.unused_data) and (not d.unconsumed_tail) and (hashlib.sha256(s).hexdigest() == e['raw_sha256'] == PIN)
sys.stdin = io.TextIOWrapper(io.BytesIO((json.dumps(v['payload'], separators=(',', ':'), allow_nan=False) + chr(10)).encode()))
exec(compile(s, '<fixed_reviewed_compact_runner>', 'exec'))
